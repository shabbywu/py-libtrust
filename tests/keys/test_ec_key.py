import pytest

from libtrust.keys.ec_key import ECPrivateKey, ECPublicKey, generate_private_key
from libtrust.keys.rs_key import generate_private_key as generate_rsa_private_key


class TestCase:
    @pytest.mark.parametrize(
        # JWK generate by https://mkjwk.org/
        "case",
        [
            {
                "kty": "EC",
                "d": "1MK1ru9lInB8XsLLr6Mh4VIH-RdnICG1F2BA6QdvbhQ",
                "use": "sig",
                "crv": "P-256",
                "x": "930a_yEwpi5_CHscX9RuPPgk_4T37GKb3N5J7DwEg6M",
                "y": "oNYIM7J9euRFprEoqT-mS9JKsk7p9zt9xbzjdsf9sT4",
            },
            {
                "kty": "EC",
                "d": "pp79jkCLMzUc8sN1aGRQFj8svSAUq0VvgrP1CkcM5UqhGOSuNIR-EOYQ8BZQfHWX",
                "use": "sig",
                "crv": "P-384",
                "x": "3nrV6yG4cfcILrJVG5NCuju3yewQHH0GQLa-qzA7o9Sn2ujgADLIRtNfnUXMlrCW",
                "y": "6hYpOZiM3-tidG9JtFT2g3_9t6ogT1s2zfSmrpHbqHPDkikxqcyfRS3K3AAvYDtN",
            },
            {
                "kty": "EC",
                "d": "AC9LfYCmQ7k4A4dMmRWC7Z3rm1uQ7EO5aO6INKtwf68v2k8jCKCRf-tdOr7LUme26ACIVLNemPLEbKumW-3GveUc",
                "use": "sig",
                "crv": "P-521",
                "x": "AHLIMApz2Yxudo451gHqNzDXJp2ebY4yQwKIB4h2YHHRSvAmWVOYgwYg-xdnKL4tK6d-k2ebtYjuFnm_A5Cvs3g9",
                "y": "AadfrgRh90Dx3CycW5_7zdoNIG50xvJWKq28judxoslTUeCziijcIFBWGMbi26cyEFhJ7r_9VtS9T5AWGrpJOn0k",
            },
        ],
    )
    @pytest.mark.parametrize(
        "subject, expected_field",
        [(ECPublicKey, ["x", "y", "crv"]), (ECPrivateKey, ["x", "y", "crv", "d"])],
    )
    def test_jwk_serialization(self, case, subject, expected_field):
        jwk = subject.from_jwk(case).to_jwk()
        for field in expected_field:
            assert jwk[field] == case[field]

    @pytest.mark.parametrize("curve_name", ["P-256", "P-384", "P-521"])
    def test_generate_private_key(self, curve_name):
        one = generate_private_key()
        other = ECPrivateKey.from_pem(one.to_pem())

        assert one.to_jwk() == other.to_jwk()

        one_pub = one.public_key()
        other_pub = ECPublicKey.from_pem(one_pub.to_pem())

        assert one_pub.to_jwk() == other_pub.to_jwk()

    def test_value_error(self):
        with pytest.raises(ValueError):
            ECPrivateKey.from_pem(generate_rsa_private_key().to_pem())

        with pytest.raises(ValueError):
            ECPublicKey.from_pem(generate_rsa_private_key().public_key().to_pem())
