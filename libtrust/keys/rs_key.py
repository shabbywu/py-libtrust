from typing import Dict, Type, BinaryIO, Union, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.utils import int_to_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from libtrust.keys.utils import (
    encode_key_id_from_crypto_key,
)
from libtrust.utils import jose_base64_url_encode, jose_base64_url_decode


__all__ = ["RSAPublicKey", "RSAPrivateKey", "generate_private_key"]


class RSAPublicKey:
    """Usage for RSAPublicKey:
    call ``verify`` to verify the signature for data in buffer.
    call ``to_pem/from_pem`` to serialize/deserialize the PEM format encoding.
    call ``to_jwk/from_jwk`` to serialize/deserialize the JWK format encoding.
    """

    def __init__(self, key: rsa.RSAPublicKey):
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("`key` is not a RSAPublicKey")
        self._public_key = key

    def __eq__(self, other):
        if not isinstance(other, RSAPublicKey):
            return False
        return (
            self.crypto_public_key().public_numbers()
            == other.crypto_public_key().public_numbers()
        )

    @classmethod
    def key_type(cls) -> str:
        return "RSA"

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
    def from_pem(cls, pem: Union[str, bytes]) -> "RSAPublicKey":
        if isinstance(pem, str):
            pem = pem.encode()
        return cls(serialization.load_pem_public_key(pem, default_backend()))

    def crypto_public_key(self) -> rsa.RSAPublicKey:
        return self._public_key

    def to_jwk(self) -> Dict:
        public_numbers = self.crypto_public_key().public_numbers()
        return {
            "kty": self.key_type(),
            "kid": self.key_id(),
            "n": jose_base64_url_encode(int_to_bytes(public_numbers.n)),
            "e": jose_base64_url_encode(int_to_bytes(public_numbers.e)),
        }

    @classmethod
    def from_jwk(cls, jwk: Dict) -> "RSAPublicKey":
        assert jwk["kty"] == cls.key_type()

        n = int.from_bytes(jose_base64_url_decode(jwk["n"]), "big")
        e = int.from_bytes(jose_base64_url_decode(jwk["e"]), "big")
        return cls(rsa.RSAPublicNumbers(e, n).public_key(default_backend()))

    def verify(
        self,
        buffer: BinaryIO,
        alg: str,
        signature: bytes,
        *,
        raise_exception: bool = True,
    ) -> bool:
        hash_algorithm = _hash_algorithm_maps.get(alg, None)
        if hash_algorithm is None:
            raise Exception(f"RSA Digital Signature Algorithm {alg} not supported")

        verifier = self.crypto_public_key().verifier(
            signature,
            padding.PKCS1v15(),
            hash_algorithm,
        )
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


class RSAPrivateKey(RSAPublicKey):
    """Usage for RSAPrivateKey:
    call ``sign`` to sign data in buffer.
    call ``verify`` to verify the signature for data in buffer.
    call ``to_pem/from_pem`` to serialize/deserialize the PEM format encoding.
    call ``to_jwk/from_jwk`` to serialize/deserialize the JWK format encoding.
    """

    def __init__(self, key: rsa.RSAPrivateKeyWithSerialization):
        if not isinstance(key, rsa.RSAPrivateKeyWithSerialization):
            raise ValueError("`key` is not a RSAPrivateKey")
        super().__init__(key.public_key())
        self._private_key = key

    def __eq__(self, other):
        if not isinstance(other, RSAPrivateKey):
            return False
        return (
            self.crypto_private_key().private_numbers()
            == other.crypto_private_key().private_numbers()
        )

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.crypto_public_key())

    def crypto_private_key(self) -> rsa.RSAPrivateKeyWithSerialization:
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
    ) -> "RSAPrivateKey":
        if isinstance(pem, str):
            pem = pem.encode()
        return cls(serialization.load_pem_private_key(pem, password, default_backend()))

    def to_jwk(self) -> Dict:
        jwk = super().to_jwk()
        private_numbers = self.crypto_private_key().private_numbers()
        jwk["d"] = jose_base64_url_encode(int_to_bytes(private_numbers.d))
        jwk["p"] = jose_base64_url_encode(int_to_bytes(private_numbers.p))
        jwk["q"] = jose_base64_url_encode(int_to_bytes(private_numbers.q))
        jwk["dp"] = jose_base64_url_encode(int_to_bytes(private_numbers.dmp1))
        jwk["dq"] = jose_base64_url_encode(int_to_bytes(private_numbers.dmq1))
        jwk["qi"] = jose_base64_url_encode(int_to_bytes(private_numbers.iqmp))
        return jwk

    @classmethod
    def from_jwk(cls, jwk: Dict) -> "RSAPrivateKey":
        assert jwk["kty"] == cls.key_type()

        n = int.from_bytes(jose_base64_url_decode(jwk["n"]), "big")
        e = int.from_bytes(jose_base64_url_decode(jwk["e"]), "big")
        d = int.from_bytes(jose_base64_url_decode(jwk["d"]), "big")
        p = int.from_bytes(jose_base64_url_decode(jwk["p"]), "big")
        q = int.from_bytes(jose_base64_url_decode(jwk["q"]), "big")
        dmp1 = int.from_bytes(jose_base64_url_decode(jwk["dp"]), "big")
        dmq1 = int.from_bytes(jose_base64_url_decode(jwk["dq"]), "big")
        iqmp = int.from_bytes(jose_base64_url_decode(jwk["qi"]), "big")

        return cls(
            rsa.RSAPrivateNumbers(
                p, q, d, dmp1, dmq1, iqmp, rsa.RSAPublicNumbers(e, n)
            ).private_key(default_backend())
        )

    def sign(self, buffer, hash_id):
        crypto_algorithm = _alg_maps.get(hash_id, "RS256")
        hash_algorithm = _hash_algorithm_maps[crypto_algorithm]
        signer = self.crypto_private_key().signer(padding.PKCS1v15(), hash_algorithm)
        while True:
            d = buffer.read(1024)
            if not d:
                break
            signer.update(d)

        return signer.finalize(), crypto_algorithm


_alg_maps: Dict[Type[hashes.HashAlgorithm], str] = {
    hashes.SHA256: "RS256",
    hashes.SHA384: "RS384",
    hashes.SHA512: "RS512",
}


_hash_algorithm_maps: Dict[str, hashes.HashAlgorithm] = {
    "RS256": hashes.SHA256(),
    "RS384": hashes.SHA384(),
    "RS512": hashes.SHA512(),
}


def generate_private_key(
    key_size: int = 2048, public_exponent: int = 65537
) -> RSAPrivateKey:
    return RSAPrivateKey(
        rsa.generate_private_key(public_exponent, key_size, default_backend())
    )
