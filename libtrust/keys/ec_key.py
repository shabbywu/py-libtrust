from typing import Dict, Type, BinaryIO, Union, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.utils import int_to_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature,
)
from libtrust.keys.utils import (
    encode_key_id_from_crypto_key,
    encode_ec_coordinate,
    decode_ec_coordinate,
)


__all__ = ["ECPublicKey", "ECPrivateKey", "generate_private_key"]


class ECPublicKey:
    """Usage for ECPublicKey:
    call ``verify`` to verify the signature for data in buffer.
    call ``to_pem/from_pem`` to serialize/deserialize the PEM format encoding.
    call ``to_jwk/from_jwk`` to serialize/deserialize the JWK format encoding.
    """

    def __init__(self, key: ec.EllipticCurvePublicKey):
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("`key` is not a EllipticCurvePublicKey")
        self._public_key = key

    def __eq__(self, other):
        if not isinstance(other, ECPublicKey):
            return False
        return (
            self.crypto_public_key().public_numbers()
            == other.crypto_public_key().public_numbers()
        )

    @classmethod
    def key_type(cls) -> str:
        return "EC"

    def key_id(self) -> str:
        return encode_key_id_from_crypto_key(self.crypto_public_key())

    def to_pem(self) -> str:
        return (
            self.crypto_public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    @classmethod
    def from_pem(cls, pem: Union[str, bytes]) -> "ECPublicKey":
        if isinstance(pem, str):
            pem = pem.encode()
        return cls(serialization.load_pem_public_key(pem, default_backend()))

    def crypto_public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key

    def to_jwk(self) -> Dict:
        crypto_public_key = self.crypto_public_key()
        public_numbers = crypto_public_key.public_numbers()
        return {
            "kty": self.key_type(),
            "kid": self.key_id(),
            "crv": self.curve_name(),
            "x": encode_ec_coordinate(public_numbers.x, crypto_public_key.curve),
            "y": encode_ec_coordinate(public_numbers.y, crypto_public_key.curve),
        }

    @classmethod
    def from_jwk(cls, jwk: Dict) -> "ECPublicKey":
        assert jwk["kty"] == cls.key_type()

        crv = jwk["crv"]
        if crv not in _curve_names_map_to_curves:
            raise Exception(f"JWK EC Public Key curve identifier not supported: {crv}")

        curve = _curve_names_map_to_curves[crv]()
        x = decode_ec_coordinate(jwk["x"], curve)
        y = decode_ec_coordinate(jwk["y"], curve)

        return cls(
            ec.EllipticCurvePublicNumbers(x, y, curve).public_key(default_backend())
        )

    def verify(
        self,
        buffer: BinaryIO,
        alg: str,
        signature: bytes,
        *,
        raise_exception: bool = True,
    ) -> bool:
        crypto_public_key = self.crypto_public_key()
        curve_name = self.curve_name()
        if _curve_names_map_to_alg[curve_name] != alg:
            raise Exception(
                f"unable to verify signature: "
                f"EC Public Key with curve {curve_name} does not support signature algorithm {alg}"
            )

        expected_octet_length = 2 * ((crypto_public_key.curve.key_size + 7) >> 3)
        if expected_octet_length != len(signature):
            raise Exception(
                f"signature length is {len(signature)} octets long, should be {expected_octet_length}"
            )

        sig_length = len(signature)
        r_bytes, s_bytes = signature[: sig_length // 2], signature[sig_length // 2 :]

        r = int.from_bytes(r_bytes, "big")
        s = int.from_bytes(s_bytes, "big")

        signature = encode_dss_signature(r, s)
        hash_algorithm = _hash_algorithm_maps[_curve_names_map_to_alg[curve_name]]
        verifier = crypto_public_key.verifier(signature, ec.ECDSA(hash_algorithm))
        while True:
            d = buffer.read(1024)
            if not d:
                break
            verifier.update(d)

        try:
            verifier.verify()
            return True
        except Exception:
            if raise_exception:
                raise
            return False

    def curve_name(self) -> str:
        return _curves_map_to_curve_names[type(self.crypto_public_key().curve)]


class ECPrivateKey(ECPublicKey):
    """Usage for ECPrivateKey:
    call ``sign`` to sign data in buffer.
    call ``verify`` to verify the signature for data in buffer.
    call ``to_pem/from_pem`` to serialize/deserialize the PEM format encoding.
    call ``to_jwk/from_jwk`` to serialize/deserialize the JWK format encoding.
    """

    def __init__(self, key: ec.EllipticCurvePrivateKeyWithSerialization):
        if not isinstance(key, ec.EllipticCurvePrivateKeyWithSerialization):
            raise ValueError("`key` is not a EllipticCurvePrivateKeyWithSerialization")
        super(ECPrivateKey, self).__init__(key.public_key())
        self._private_key = key

    def __eq__(self, other):
        if not isinstance(other, ECPrivateKey):
            return False
        return (
            self.crypto_private_key().private_numbers()
            == other.crypto_private_key().private_numbers()
        )

    def public_key(self) -> ECPublicKey:
        return ECPublicKey(self.crypto_public_key())

    def crypto_private_key(self) -> ec.EllipticCurvePrivateKeyWithSerialization:
        return self._private_key

    def to_pem(self) -> str:
        return (
            self.crypto_private_key()
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )

    @classmethod
    def from_pem(
        cls, pem: Union[str, bytes], password: Optional[bytes] = None
    ) -> "ECPrivateKey":
        if isinstance(pem, str):
            pem = pem.encode()
        return cls(serialization.load_pem_private_key(pem, password, default_backend()))

    def to_jwk(self) -> Dict:
        jwk = super().to_jwk()
        jwk["d"] = encode_ec_coordinate(
            self.crypto_private_key().private_numbers().private_value,
            self.crypto_public_key().curve,
        )
        return jwk

    @classmethod
    def from_jwk(cls, jwk: Dict) -> "ECPrivateKey":
        assert jwk["kty"] == cls.key_type()

        crv = jwk["crv"]
        if crv not in _curve_names_map_to_curves:
            raise Exception(f"JWK EC Public Key curve identifier not supported: {crv}")

        curve = _curve_names_map_to_curves[crv]()
        x = decode_ec_coordinate(jwk["x"], curve)
        y = decode_ec_coordinate(jwk["y"], curve)
        d = decode_ec_coordinate(jwk["d"], curve)

        return cls(
            ec.EllipticCurvePrivateNumbers(
                d, ec.EllipticCurvePublicNumbers(x, y, curve)
            ).private_key(default_backend())
        )

    def sign(self, buffer: BinaryIO, hash_id: hashes.HashAlgorithm):
        crypto_private_key = self.crypto_private_key()
        crypto_algorithm = _curve_names_map_to_alg[self.curve_name()]
        hash_algorithm = _hash_algorithm_maps[crypto_algorithm]
        signer = crypto_private_key.signer(ec.ECDSA(hash_algorithm))

        while True:
            d = buffer.read(1024)
            if not d:
                break
            signer.update(d)

        r, s = decode_dss_signature(signer.finalize())
        r_bytes = int_to_bytes(r)
        s_bytes = int_to_bytes(s)
        octet_length = (crypto_private_key.curve.key_size + 7) >> 3

        r_bytes = b"\x00" * (octet_length - len(r_bytes)) + r_bytes
        s_bytes = b"\x00" * (octet_length - len(s_bytes)) + s_bytes
        signature = r_bytes + s_bytes
        return signature, crypto_algorithm


_curves_map_to_curve_names: Dict[Type[ec.EllipticCurve], str] = {
    ec.SECP256R1: "P-256",
    ec.SECP384R1: "P-384",
    ec.SECP521R1: "P-521",
}
_curve_names_map_to_curves: Dict[str, Type[ec.EllipticCurve]] = {
    v: k for k, v in _curves_map_to_curve_names.items()
}

_curve_names_map_to_alg: Dict[str, str] = {
    "P-256": "ES256",
    "P-384": "ES384",
    "P-521": "ES521",
}
_alg_map_to_curve_names = {v: k for k, v in _curve_names_map_to_alg.items()}

_hash_algorithm_maps: Dict[str, hashes.HashAlgorithm] = {
    "ES256": hashes.SHA256(),
    "ES384": hashes.SHA384(),
    "ES521": hashes.SHA512(),
}


def generate_private_key(curve_name: str = "P-256") -> ECPrivateKey:
    if curve_name not in _curve_names_map_to_curves:
        raise Exception(f"Does not support curve {curve_name} does not support")

    curve = _curve_names_map_to_curves[curve_name]()
    return ECPrivateKey(ec.generate_private_key(curve, default_backend()))
