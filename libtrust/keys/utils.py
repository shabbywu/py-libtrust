import base64
from typing import TYPE_CHECKING, Union
from cryptography.utils import int_to_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from libtrust.utils import jose_base64_url_decode, jose_base64_url_encode


if TYPE_CHECKING:
    try:
        from cryptography.hazmat.primitives.asymmetric.types import PUBLIC_KEY_TYPES
    except ModuleNotFoundError:
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        PUBLIC_KEY_TYPES = Union[EllipticCurvePublicKey, RSAPublicKey]


def encode_key_id_from_crypto_key(pub_key: "PUBLIC_KEY_TYPES") -> str:
    """Encode distinct identifier which is unique to this Public Key.
    :param pub_key:
    :return:
    """
    der_bytes = pub_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hasher = hashes.Hash(hashes.SHA256(), default_backend())
    hasher.update(der_bytes)
    hash_bytes = hasher.finalize()
    return _encode_key_id_from_hashed(hash_bytes[:30])


def _encode_key_id_from_hashed(hashed: bytes) -> str:
    """Encode the 30 bytes hash of the public key data.

    First encode the hash with base32, then divide into 12 groups like so:
        ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP
    :param hashed:
    :return:
    """
    s = base64.b32encode(hashed).decode().rstrip("=")
    block_size = 4
    key_id = ":".join((s[i : i + block_size] for i in range(0, len(s), block_size)))
    remain = len(s) % block_size
    if remain:
        key_id += s[-remain:]
    return key_id


def encode_ec_coordinate(coordinate: int, curve: EllipticCurve) -> str:
    """Encode ec.coordinate x/y/d to base64 encoded str"""
    octet_length = (curve.key_size + 7) >> 3
    coordinate_bytes = int_to_bytes(coordinate)
    coordinate_bytes = (
        b"\x00" * (octet_length - len(coordinate_bytes)) + coordinate_bytes
    )
    return jose_base64_url_encode(coordinate_bytes)


def decode_ec_coordinate(coordinate_str: str, curve: EllipticCurve) -> int:
    """Decode ec.coordinate x/y/d from base64 encoded str"""
    octet_length = (curve.key_size + 7) >> 3
    coordinate_bytes = jose_base64_url_decode(coordinate_str)

    if octet_length != len(coordinate_bytes):
        raise Exception(
            f"invalid number of octets: got {len(coordinate_bytes)}, should be {octet_length}"
        )

    return int.from_bytes(coordinate_bytes, "big")
