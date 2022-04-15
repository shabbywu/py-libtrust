import pytest

from libtrust.keys.ec_key import ECPublicKey
from libtrust.keys.utils import encode_key_id_from_crypto_key


@pytest.mark.parametrize(
    "docker_jwk",
    # test case copy from https://github.com/distribution/distribution/blob/main/docs/spec/manifest-v2-1.md
    [
        {
            "crv": "P-256",
            "kid": "OD6I:6DRK:JXEJ:KBM4:255X:NSAA:MUSF:E4VM:ZI6W:CUN2:L4Z6:LSF4",
            "kty": "EC",
            "x": "3gAwX48IQ5oaYQAYSxor6rYYc_6yjuLCjtQ9LUakg4A",
            "y": "t72ge6kIA1XOjqjVoEOiPPAURltJFBMGDSQvEGVB010",
        }
    ],
)
def test_encode_key_id_from_crypto_key(docker_jwk):
    assert encode_key_id_from_crypto_key(ECPublicKey.from_jwk(docker_jwk).crypto_public_key()) == docker_jwk["kid"]
