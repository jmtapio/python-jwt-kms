import unittest
import unittest.mock
import base64
from jwt_kms import jwk, jws


pubkey = base64.b64decode(
    b'''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkckJYKGNE0KndLDp9Yk
LCLOPZNGMqhAncH/vUpib7SGUnf2qWUJvhud5t+W5vpF9v60LC/DWkBiWY3yliyQ
BFTJWKniziHn3TOeZChhSuZGa8jYWh11CHfnK76lziW+E/Ejt/GbEUOcpUjdkv8a
ZK3w12U1nI9n6LV/s/201wJorBlvisgOndPDi+14zX6Im20wqbBQn69HuJdZ8Dff
1xb8Wywua75ApTWMEuKSvuvysHAfcpLhQx4AOO3lefQV9C21/whRh1BSyuSLDRIS
XF+nIJCssPCDRaOzpIYq3LB0xenWyOO0mx+Jj/djYT7V5FnEW8+OxbnZ2ZbycXlr
uwIDAQAB''')


class JWSTests(unittest.TestCase):
    mock_info1 = dict(
        PublicKey = pubkey,
        KeyUsage = 'SIGN_VERIFY',
        SigningAlgorithms = [
            'RSASSA_PSS_SHA_256',
            'RSASSA_PSS_SHA_384',
            'RSASSA_PSS_SHA_512',
            'RSASSA_PKCS1_V1_5_SHA_256',
            'RSASSA_PKCS1_V1_5_SHA_384',
            'RSASSA_PKCS1_V1_5_SHA_512',
            ],
        CustomerMasterKeySpec = 'RSA_2048',
        )

    def test_jws_sign(self):
        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info1
        client.sign.return_value = dict(Signature=b'foosignature')
        key = jwk.Key(client, 'foo')
        token = jws.JWS(dict(foo='baz'))
        compact = token.add_signature(key).serialize(compact=True)

        self.assertEqual(
            compact,
            'eyJ0eXAiOiAiSldTIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiLTBFMVBsQTB3eHZyYlo3ejhKY1B6SkVPWldvSGJPajhyQllLUFBBOHJnTSJ9.eyJmb28iOiAiYmF6In0.Zm9vc2lnbmF0dXJl'
        )

        client.get_public_key.assert_called()
        client.sign.assert_called_once()
