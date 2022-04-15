import datetime

import pytest

from libtrust.jsonsign import JSONSignature
from libtrust.keys.ec_key import ECPrivateKey
from libtrust.keys.rs_key import RSAPrivateKey


@pytest.fixture
def dt():
    return datetime.datetime(1970, 1, 1, 0, 0)


@pytest.fixture
def ec_key():
    return ECPrivateKey.from_jwk(
        {
            "kty": "EC",
            "d": "0j0jt94e1A8vXp3LQG0QkVIdRVF04-5tVINCJDq3X_8",
            "crv": "P-256",
            "x": "IyjT-5avK4dAeJekAZ5U9pQSd0wcaatcWxObmOVZG-4",
            "y": "MyNFBLjQLq-6Bj_GqEdhhBYddTO95J9HcZzbhOtld-M",
        }
    )


@pytest.fixture
def rsa_key():
    return RSAPrivateKey.from_jwk(
        {
            "p": "_VWrpJm0EE1XViHq6bFSRivBtAoSGOg8B2sBYk1RLY0",
            "kty": "RSA",
            "q": "lyo11qCTTSs0aIk_QBCBbq2m7rKp3wvkbGgHg1A7MpE",
            "d": "SWnWzYRDDmTfszn2eqewdZW233_md82U09vee4_duko3ItQqs4wINNkZMV55kaz9J2dCJyIXtR3fdI4i0Y3cQQ",
            "e": "AQAB",
            "qi": "785yZM_gCIQ2-pMq2bKGNYq89_ge7cfhu0TL_JCvWus",
            "dp": "zquKaLD_5eDCpEDtXRLNFPPzhYZFt04WUtLoASMkW60",
            "dq": "Kb3lKgQjSM7iZO9pQNaN9zMKgqVhVQ8in3DGilMwVZE",
            "n": "lZdNk2C4TGkEj8LSPvn_3etC5JoMDFp89YHMLe3IeeGDywEqCfZ2lwh0MhlFzKwVObiwOUMMF7vpw1XgNV9W3Q",
        }
    )


@pytest.fixture
def key(request):
    return request.getfixturevalue(request.param)


class TestCase:
    @pytest.mark.parametrize(
        "content, key",
        [
            (
                {"test": "case"},
                "ec_key",
            ),
            (
                {"test": "case"},
                "rsa_key",
            ),
            pytest.param("test", "ec_key", marks=[pytest.mark.xfail]),
            pytest.param('{"test": "a",}', "ec_key", marks=[pytest.mark.xfail]),
        ],
        indirect=["key"],
    )
    def test_jws(self, content, key, dt):
        js1 = JSONSignature.new(content)
        js1.sign(key=key, dt=dt)

        jws = js1.to_jws()
        js2 = JSONSignature.from_jws(jws)

        assert js1 == js2
        assert js1.verify()

    def test_pretty_signature(self, django_example_manifest, django_example_manifest_no_indent):
        js = JSONSignature.from_pretty_signature(django_example_manifest)
        assert js.verify()

        pretty_signature = js.to_pretty_signature(signature_key="signatures")
        assert pretty_signature == django_example_manifest

        js.indent = 0
        assert js.to_pretty_signature(signature_key="signatures") == django_example_manifest_no_indent
