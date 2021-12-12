from typing import Dict, Union, TYPE_CHECKING, BinaryIO, Tuple
from typing_extensions import Protocol


if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives import hashes


class PublicKey(Protocol):
    def key_type(self) -> str:
        """
        KeyType returns the key type for this key. For elliptic curve keys,
        this value should be "EC". For RSA keys, this value should be "RSA".
        :return:
        """

    def key_id(self) -> str:
        """
        returns a distinct identifier which is unique to this Public Key.
        The format generated by this library is a base32 encoding of a 240 bit
        hash of the public key data divided into 12 groups like so:
            ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP
        :return:
        """

    def to_jwk(self) -> Dict:
        """
        Serialize to the public keys to the standard JSON encoding for
        JSON Web Keys.
        See section 6 of the IETF draft RFC for JOSE JSON Web Algorithms.
        ref: https://www.rfc-editor.org/rfc/rfc7518.txt
        :return:
        """

    @classmethod
    def from_jwk(cls, jwk: Dict) -> "PublicKey":
        """
        Deserialize the public keys from the standard JSON encoding for
        JSON Web Keys.
        :param jwk: JSON Web Key
        :return: PublicKey
        """

    def to_pem(self) -> str:
        """
        Serialize to the public keys to the standard PEM encoding.
        :return:
        """

    @classmethod
    def from_pem(cls, pem: str) -> "PublicKey":
        """
        Deserialize the public keys from the standard PEM encoding.
        :param pem: pem content string.
        :return: PublicKey
        """

    def crypto_public_key(
        self,
    ) -> Union["ec.EllipticCurvePublicKey", "rsa.RSAPublicKey"]:
        """
        returns the internal object which can be used as a
        crypto.PublicKey for use with other standard library operations. The type
        is either rsa.RSAPublicKey or ec.EllipticCurvePublicKey
        :return:
        """

    def verify(
        self,
        buffer: BinaryIO,
        alg: str,
        signature: bytes,
        *,
        raise_exception: bool = True
    ) -> bool:
        """
        verify the signature of the data in the buffer using this Public Key.
        The alg parameter should identify the digital signature algorithm
        which was used to produce the signature and should be supported by this public key.

        Returns true if the signature is valid.
        :param buffer:
        :param alg:
        :param signature:
        :param raise_exception:
        :return:
        """


class PrivateKey(PublicKey, Protocol):
    def public_key(self) -> "PublicKey":
        ...

    def crypto_private_key(
        self,
    ) -> Union["ec.EllipticCurvePrivateKey", "rsa.RSAPrivateKey"]:
        """
        CryptoPrivateKey returns the internal object which can be used as a
        crypto.PublicKey for use with other standard library operations. The
        type is either rsa.RSAPrivateKey or ec.EllipticCurvePrivateKey
        :return:
        """

    def sign(
        self, buffer: BinaryIO, hash_id: "hashes.HashAlgorithm"
    ) -> Tuple[bytes, str]:
        """
        signs the data read from the buffer using a signature algorithm
        supported by the private key. If the specified hashing algorithm is
        supported by this key, that hash function is used to generate the
        signature otherwise the the default hashing algorithm for this key is
        used.
        :param buffer:
        :param hash_id:
        :return: the signature and identifier of the algorithm used.
        """
