import base64
import io
import json
import datetime
from textwrap import indent
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field, is_dataclass, asdict
from libtrust.keys.protocol import PrivateKey, PublicKey
from libtrust.utils import (
    jose_base64_url_decode,
    jose_base64_url_encode,
    detect_json_indent,
    not_space,
    last_index,
    json_dumps,
)
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from libtrust.keys.ec_key import ECPublicKey
from libtrust.keys.rs_key import RSAPublicKey
from libtrust.exceptions import InvalidJSONContent, MissingSignatureKey


__all__ = ["JSONSignature"]


class JsonEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if is_dataclass(o):
            return asdict(o)
        return super().default(o)


@dataclass
class JSHeader:
    jwk: Dict
    alg: str
    chain: List[str] = field(default_factory=list)


@dataclass
class JsSignature:
    header: JSHeader
    signature: str
    protected: str


@dataclass
class JSONSignature:
    """Usage for JSONSignature.
    call ``new`` to make new JSONSignature for content.
    call ``sign`` to signature by private key.
    call ``verify`` to verify the JSONSignature objects.
    call ``to_jws/from_jws`` to serialize/deserialize a jose-json-web-signature object.
    call ``to_pretty_signature/from_pretty_signature`` to serialize/deserialize a
            self-signed JSON signature, which is used in Docker Manifest verify.
    """

    payload: str
    indent: int
    format_length: int
    format_tail: str
    signatures: List[JsSignature] = field(default_factory=list)

    @classmethod
    def new(cls, content: Union[str, Dict], *signatures: dict) -> "JSONSignature":
        if isinstance(content, Dict):
            # indent = 3, is the magic number from
            # https://github.com/distribution/distribution/blob/main/vendor/github.com/docker/libtrust/jsonsign.go#L450
            content = json_dumps(content, indent=3)

        assert isinstance(content, str)

        indent = detect_json_indent(content)
        payload = jose_base64_url_encode(content)

        # Find trailing } and whitespace, put in protected header
        close_index = last_index(content, not_space)
        if content[close_index] != "}":
            raise InvalidJSONContent("content not close by '}'")
        last_rune_index = last_index(content[:close_index], not_space)
        if content[last_rune_index] == ",":
            raise InvalidJSONContent("invalid json")
        format_length = last_rune_index + 1
        format_tail = content[format_length:]

        instance = cls(
            payload=payload,
            indent=indent,
            format_length=format_length,
            format_tail=format_tail,
        )
        for signature_content in signatures:
            signature = JsSignature(
                header=JSHeader(**signature_content.pop("header")), **signature_content
            )
            instance.signatures.append(signature)
        return instance

    def _protected_header(self, dt: Optional[datetime.datetime] = None):
        protected = {
            "formatLength": self.format_length,
            "formatTail": jose_base64_url_encode(self.format_tail),
            "time": (dt or datetime.datetime.utcnow()).isoformat("T"),
        }
        return jose_base64_url_encode(json_dumps(protected))

    def sign(self, key: PrivateKey, dt: Optional[datetime.datetime] = None):
        """add a signature using the given private key."""
        protected = self._protected_header(dt)
        buffer = io.BytesIO((".".join([protected, self.payload])).encode())
        sig_bytes, algorithm = key.sign(buffer, hash_id=hashes.SHA256())

        self.signatures.append(
            JsSignature(
                header=JSHeader(
                    jwk=key.public_key().to_jwk(),
                    alg=algorithm,
                ),
                signature=jose_base64_url_encode(sig_bytes),
                protected=protected,
            )
        )

    def verify(self) -> List[PublicKey]:
        keys = []
        for sign in self.signatures:
            key: PublicKey
            if sign.header.chain:
                cert_bytes = base64.b64decode(sign.header.chain[0].encode())
                cert = x509.load_der_x509_certificate(cert_bytes)
                crypto_public_key = cert.public_key()

                if isinstance(crypto_public_key, rsa.RSAPublicKey):
                    key = RSAPublicKey(crypto_public_key)
                elif isinstance(crypto_public_key, ec.EllipticCurvePublicKey):
                    key = ECPublicKey(crypto_public_key)
                else:
                    raise Exception("UnSupport cert type")
            elif sign.header.jwk is None:
                raise Exception("missing public key")
            else:
                jwk = sign.header.jwk
                if jwk["kty"] == ECPublicKey.key_type():
                    key = ECPublicKey.from_jwk(jwk)
                elif jwk["kty"] == RSAPublicKey.key_type():
                    key = RSAPublicKey.from_jwk(jwk)
                else:
                    raise Exception(f"UnSupport jwk type {jwk['kty']}")

            buffer = io.BytesIO((".".join([sign.protected, self.payload])).encode())
            key.verify(buffer, sign.header.alg, jose_base64_url_decode(sign.signature))
            keys.append(key)
        return keys

    def to_jws(self) -> str:
        """
        JSON serialized JWS according to
        http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-7.2
        :return:
        """
        if len(self.signatures) == 0:
            raise Exception("missing signature")

        self.signatures.sort()

        return json_dumps(
            {
                "payload": self.payload,
                "signatures": self.signatures,
            },
            indent=self.indent,
            cls=JsonEncoder,
        )

    @classmethod
    def from_jws(cls, jws_content: str):
        jws = json.loads(jws_content)
        if "payload" not in jws:
            raise Exception("missing payload")
        if not jws.get("signatures"):
            raise Exception("missing signature")

        payload = jose_base64_url_decode(jws["payload"]).decode()
        return cls.new(payload, *jws.get("signatures", []))

    def to_pretty_signature(self, signature_key: str = "signatures") -> str:
        """formats a json signature into an easy to read single json serialized object.
        :param signature_key: The Key of signatures in json object.
        :return:
        """
        if len(self.signatures) == 0:
            raise Exception("missing signature")

        self.signatures.sort()
        if self.indent:
            signatures = indent(
                json_dumps(self.signatures, indent=self.indent, cls=JsonEncoder),
                " " * self.indent,
            )
        else:
            signatures = json_dumps(self.signatures, indent=None, cls=JsonEncoder)
        payload = jose_base64_url_decode(self.payload).decode()[: self.format_length]

        buf = io.StringIO()
        buf.write(payload)
        buf.write(",")
        if self.indent:
            buf.write("\n")
            buf.write(" " * self.indent)
            buf.write('"')
            buf.write(signature_key)
            buf.write('": ')
            buf.write(signatures[self.indent :])
            buf.write("\n")
        else:
            buf.write('"')
            buf.write(signature_key)
            buf.write('": ')
            buf.write(signatures)

        buf.write("}")
        buf.seek(0)
        return buf.read()

    @classmethod
    def from_pretty_signature(
        cls, content: str, signature_key: Optional[str] = "signatures"
    ) -> "JSONSignature":
        """
        parses a formatted signature into a JSON signature.
        If the signatures are missing the format information an error is thrown.
        The formatted signature must be created by the same method as format signature.
        """
        loaded = json.loads(content)
        if signature_key not in loaded:
            raise MissingSignatureKey

        signatures = [
            JsSignature(JSHeader(**signature.pop("header")), **signature)
            for signature in loaded[signature_key]
        ]

        format_length = 0
        format_tail = ""
        for signature in signatures:
            protected_header = json.loads(jose_base64_url_decode(signature.protected))

            _format_length = protected_header["formatLength"]
            _format_tail = jose_base64_url_decode(
                protected_header["formatTail"]
            ).decode()

            if format_length and format_length != _format_length:
                raise
            if format_tail and format_tail != _format_tail:
                raise

            format_length = _format_length
            format_tail = _format_tail

        if format_length > len(content):
            raise Exception("invalid format length")

        payload = content[:format_length] + format_tail
        indent = detect_json_indent(payload)

        instance = JSONSignature(
            payload=jose_base64_url_encode(payload),
            indent=indent,
            format_length=format_length,
            format_tail=format_tail,
            signatures=signatures,
        )
        return instance
