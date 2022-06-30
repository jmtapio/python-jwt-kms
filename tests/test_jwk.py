import unittest
import unittest.mock
import base64
from jwt_kms import jwa, jwk, jws


pubkey = base64.b64decode(
    b'''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkckJYKGNE0KndLDp9Yk
LCLOPZNGMqhAncH/vUpib7SGUnf2qWUJvhud5t+W5vpF9v60LC/DWkBiWY3yliyQ
BFTJWKniziHn3TOeZChhSuZGa8jYWh11CHfnK76lziW+E/Ejt/GbEUOcpUjdkv8a
ZK3w12U1nI9n6LV/s/201wJorBlvisgOndPDi+14zX6Im20wqbBQn69HuJdZ8Dff
1xb8Wywua75ApTWMEuKSvuvysHAfcpLhQx4AOO3lefQV9C21/whRh1BSyuSLDRIS
XF+nIJCssPCDRaOzpIYq3LB0xenWyOO0mx+Jj/djYT7V5FnEW8+OxbnZ2ZbycXlr
uwIDAQAB''')


class KeyTests(unittest.TestCase):
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
            ]
        )
    mock_info2 = dict(
        PublicKey = pubkey,
        KeyUsage = 'ENCRYPT_DECRYPT'
    )

    def test_public_key_pem(self):
        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info1

        key = jwk.Key(client, 'foo')
        self.assertIn(b'-BEGIN PUBLIC KEY-', key.public_key_pem)
        self.assertIn(b'BFTJWKniziHn3TOeZChhSuZGa8jYWh11CHfnK76lziW', key.public_key_pem)

        client.get_public_key.assert_called()

    def test_supported_algs(self):
        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info1

        key = jwk.Key(client, 'foo')
        self.assertIn('RSASSA_PKCS1_V1_5_SHA_384', key.supported_algs)

        client.get_public_key.assert_called()

    def test_use(self):
        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info1

        key = jwk.Key(client, 'bar1')
        self.assertEqual(key.use, 'sig')
        client.get_public_key.assert_called()

        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info2

        key = jwk.Key(client, 'bar2')
        self.assertEqual(key.use, 'enc')
        client.get_public_key.assert_called()

    def test_sign_digest(self):
        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info1
        client.sign.return_value = dict(Signature=b'foosignature')

        key = jwk.Key(client, 'foosign')
        sig = key.sign_digest(b'foodigest', 'RSASSA_PKCS1_V1_5_SHA_256')

        self.assertEqual(sig, b'foosignature')
        client.get_public_key.assert_called()
        client.sign.assert_called_with(
            KeyId='foosign',
            Message=b'foodigest',
            MessageType='DIGEST',
            SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
        )
