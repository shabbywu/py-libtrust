import pytest
from libtrust.keys.rs_key import RSAPrivateKey, RSAPublicKey, generate_private_key
from libtrust.keys.ec_key import generate_private_key as generate_ec_private_key


class TestCase:
    @pytest.mark.parametrize(
        # JWK generate by https://mkjwk.org/
        "case",
        [
            {
                "p": "9_rBP5CtwLVBWEdU8W9yC1WtTWzGXUchqwiEYvrZaDft88GntZJf9znArZONfaqwzlb6ZEPGaK8YmddoaY7OiIspWFWBLKoXa9MIcifMRA9VOgPIkb9BwzWCsYCVndEwLWn95FrO642JrPHJxCxAbimwhda8zXIqtFQj9k7sOl0",
                "kty": "RSA",
                "q": "27b-uF8YOUfGLYdC_lUp7xnzU5imdR8KZ3bz_ASR1H0Zf7wx_GBomJc46tWjV0JHIzrleNNE0S-hCxhrtsklnDkoycwMBL3ZryaBU44XvRtXi-3UD5Vv6cgttMUapSuv5_MH_p-nlvyJ7t6SKtbupDB_v4HwPpPOVGvB-JvJVyU",
                "d": "iHQK3DX4JH675wvH7UFuCRiahIG-0kRLc_BGNSVwWNsP_50do7sH-PmhQWpzqK2b6vyy6OcJC45qov1YCGeKdpFjRU0VOC2eaUqv5Aln9o2oGbRTI3WpcWiVf0IcPWMAdO3Qd688IV6Vnmge4nX57GzCjWmCrYv5dG5K17P8U0jja7n4yp0TM52JIMmFCsV-EeTSg6d9XyRhNug3dJZuBFMXTT2YGhf7Pjgv37c5ICfcM_WA7GUYaURP1PUsp-PeSEytvOPJeDaADN2p30FBxNZlole5sCDUTlMLrAy6JD1O3tCXxW34poUNXtifrjQqxX4kw8XszFe05-Y2-VrP4Q",
                "e": "AQAB",
                "qi": "ruoY2Kb8h5ZjjdhE8uYhbKNBlq70YcHjuGaawiFAtMAJUCRP-sGri15WKu-c-G5KO2OmWStmjV8sXzMyVnMfICQ4uduX24-VllF7jgkmYQMLZ6ecjNLXPThlkjpRAbkzkZfytI57umhtiLGSM1suulxPwwnIEET_uxV2wvvAWAY",
                "dp": "fX5q-c4wAEw6K4C93gk2P8I2F-6qXF45DaMbzDOCfpl_VFJ2mw7effC-L5lyi1wsad_ei4s5B5VE7-XxMypQHw29-LQc0QurGqgLqCm31-Gikd-ESy3tC-synr2h-eH5baIsGLpT6SURvXIHV73FRXrXmIPZvGbAcc36_RVnuwk",
                "dq": "Tz2MWEpTnjT4kGr8CmYEnasqSrf_MLZlNjN8gyPSxGPp0lu5W2AZ2Q6RBIDQTCQnK9mN8Smg5CDdX_cKwf2BhvpGb6EbpIoj_DtS4SOaBCXcSScZGBW5KwN7GHsNxQwggPLxqy9Bbf7ecDvtU23421ZyfEsMrkT4YRIL_vGQh9E",
                "n": "1NTGVCgK-1OCCikbVnys2d0yUdZ386OGPxG33zgx_3XTDX7xAU7TGO25OOQjjSAJ5ecnVOHUONQonB4K-jWbtC60gR36mPE17_7J5uHEtNCN-ospJfZB3ilmGWqCHG-OF4HLLILLnojVkJaw0uIcpmTQhv0WmRAdcSm0qJaJa76OcwQ4pNVN79M3RmciNF0PCZ4xxdFt-NtSn-RGElRn2PhdD4GUXFUmtSDR_FJ6-GeAdxbo6LpSJS9JlFwsHvqHnVu2DrKzjoUoZifhZqglB0o4xRt9tmLptHbDYuxih3RyGAn8BOqTL_odzjoGeV4jF795Ow7M8SB8Ro1T0f8KcQ",
            },
            {
                "p": "9N-pgkWLCEqfaHKp3W2TUog7O0z-SgawCy4rz9mFeHVYsJWb3M-u7MfYRF_Fiu7J1VFwlzjEUUj7MZ_EEHlMy-NzschwJk2kUWB5wBqA79_kWscYKPLmmuwUl8RBIjL8Q4I9q6dZM-FvujC46tykN6gzv3Y9d3WiUngb5rlBS7s",
                "kty": "RSA",
                "q": "rwk0tA9P0uzlCM4BAzIg4wQBDmHxfiz26lltWFzgnQrtGvQsVeB-ZNvoioTDW6QZhJjFNtUGnk-15yMF14zvWzsnBDNoCS8lC8SOG4CPpGgqPOQEiZdCNgQN0NYj5_C5G78RljVOX-fTSMdZn4uFp4QCqfutKdg38WnJVqoZUfU",
                "d": "XmWVOltWD6mRFk0yP44dK7uoQVf6nnpb2pPVEHk1RbLkXOZA5xlwT_O0QyybyMub-76mMvj1rvXMa2jWia1SZQ5ONExVZypgYzmvgPoFkR1216VuIRklDqEnVx6fKbKBERE9n1h6EB7yztvaUzUdmVgm6FEKu7lUapuKrPV7n1wktXmFg0LgmpgLbWzt6KCKBfaExDe220F5x6atYZzgOMisSoHlGuYA1rjWl9P-DP44JnnifmHjvjTA0BHQsA2E5YCsBIl5S06WdqZ1_KTNVrt10QvPq3ToBKxCcf8NY74n4l_2hlKDkpGyLMSpG1DP0VYzw6DIBmXe1Al2CNHyMQ",
                "e": "AQAB",
                "qi": "c7QhOd2WUIRW339nhVs0RI9YVTdkBY0-7g8-bJmAUYGwTufevBRYKfEco8PdIBF_tBnuerDY8VY3uaIF_kfbGIlRbf9VHKuRP5-obN-b0jVsc9Mrl7wvqfeDHaeYLkZmTlTYIYBd5pFfSdC1amuOpfm4IFXAp6SRYWWkafTc7As",
                "dp": "hiMu-8mUi4o1IEYPfthTZ1Zw-98FPQ_Ex5sXLNh_IKlHWBPcOW0a6WHfujSsRZrgvRXLk0rpX42W7GwUPuHzi4yhB7ZAmPrXFCzBBNZ_4ubGdGOzfFryr9K6xRgghddgEKr7lVgqqRzI0zl1UlJjMonVLwBaU2IA9SQORKked5k",
                "dq": "jaKOYhFtz0jgACLqENL0Z55q2F-K0UXDO1jHsVPecVVRDZl9crQosqZ74fKSPkpoV7JjCv6Pz3TCxdjCNmyVlqYj6TNLwPrEKGSRdVGvaiLb4s_DmC6sZhcbstxEy78vmnMe4QQbemGVx3OAYyi8KxQYL8I2mgCbLB8ky5ryyC0",
                "n": "p22zJq11l_10oTkbUQWW12t8OyQ0-g_zggOSkB--XiSDMUc4qzpYjZYjKQHyUcb4xriqgJxcrBE0nypKNJk582U3kan2aGTRN60Z6pacWfpRiipp04PxegzRLjmou8uyX2B5YzaznOelh3dh6vY8mRJcl8G41ocaOuPdwALxDfxuQR8_d-aenlLdH02o48GyNHU6wEZIOrGRCSyVjoAlpEAfD1U2q6dS-ZQWmuQlMstxVljXTE1ldgaukeSrKli7S3uV8SE8cuDZYJe1DPGGy7pD5SeX-LmV_UIs886_QBHZJCBqGnZJ7KHrnC519FYDRSQBD_RTyOl5bGvph7ak9w",
            },
        ],
    )
    @pytest.mark.parametrize(
        "subject, expected_field",
        [
            (RSAPublicKey, ["e", "n"]),
            (RSAPrivateKey, ["e", "n", "d", "p", "q", "dp", "dq", "qi"]),
        ],
    )
    def test_jwk_serialization(self, case, subject, expected_field):
        jwk = subject.from_jwk(case).to_jwk()
        for field in expected_field:
            assert jwk[field] == case[field]

    def test_generate_private_key(self):
        one = generate_private_key()
        other = RSAPrivateKey.from_pem(one.to_pem())

        assert one.to_jwk() == other.to_jwk()

        one_pub = one.public_key()
        other_pub = RSAPublicKey.from_pem(one_pub.to_pem())

        assert one_pub.to_jwk() == other_pub.to_jwk()

    def test_value_error(self):
        with pytest.raises(ValueError):
            RSAPrivateKey.from_pem(generate_ec_private_key().to_pem())

        with pytest.raises(ValueError):
            RSAPublicKey.from_pem(generate_ec_private_key().public_key().to_pem())
