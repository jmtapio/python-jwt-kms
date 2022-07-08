import unittest
import unittest.mock
import base64
from jwt_kms import jwk


pubkey = base64.b64decode(
    b'''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkckJYKGNE0KndLDp9Yk
LCLOPZNGMqhAncH/vUpib7SGUnf2qWUJvhud5t+W5vpF9v60LC/DWkBiWY3yliyQ
BFTJWKniziHn3TOeZChhSuZGa8jYWh11CHfnK76lziW+E/Ejt/GbEUOcpUjdkv8a
ZK3w12U1nI9n6LV/s/201wJorBlvisgOndPDi+14zX6Im20wqbBQn69HuJdZ8Dff
1xb8Wywua75ApTWMEuKSvuvysHAfcpLhQx4AOO3lefQV9C21/whRh1BSyuSLDRIS
XF+nIJCssPCDRaOzpIYq3LB0xenWyOO0mx+Jj/djYT7V5FnEW8+OxbnZ2ZbycXlr
uwIDAQAB''')

pubkey_ec = base64.b64decode(
    b'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBi/pFKSljzZr91kzgw2iA/RAUdi1\nfnjzxm3xvTjz4MXiIylU64csUM7oRHxhboroE4cpI0QCWTOuDZNTRzM5aw=='
)


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
            ],
        CustomerMasterKeySpec = 'RSA_2048'
        )
    mock_info2 = dict(
        PublicKey = pubkey,
        KeyUsage = 'ENCRYPT_DECRYPT',
        CustomerMasterKeySpec = 'RSA_2048'
    )
    mock_info3 = dict(
        PublicKey = pubkey_ec,
        KeyUsage = 'SIGN_VERIFY',
        SigningAlgorithms = ['ECDSA_SHA_256'],
        CustomerMasterKeySpec = 'ECC_NIST_P256'
        )

    def setUp(self):
        self.maxDiff = None

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

    def test_jwk_rsa(self):
        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info1

        key = jwk.Key(client, 'foosign')
        j = key.public_key_jwk

        self.assertEqual(j['kid'], '-0E1PlA0wxvrbZ7z8JcPzJEOZWoHbOj8rBYKPPA8rgM')
        self.assertEqual(
            j,
            dict(
                e="AQAB",
                kid="-0E1PlA0wxvrbZ7z8JcPzJEOZWoHbOj8rBYKPPA8rgM",
                kty="RSA",
                n="vkckJYKGNE0KndLDp9YkLCLOPZNGMqhAncH_vUpib7SGUnf2qWUJvhud5t-W5vpF9v60LC_DWkBiWY3yliyQBFTJWKniziHn3TOeZChhSuZGa8jYWh11CHfnK76lziW-E_Ejt_GbEUOcpUjdkv8aZK3w12U1nI9n6LV_s_201wJorBlvisgOndPDi-14zX6Im20wqbBQn69HuJdZ8Dff1xb8Wywua75ApTWMEuKSvuvysHAfcpLhQx4AOO3lefQV9C21_whRh1BSyuSLDRISXF-nIJCssPCDRaOzpIYq3LB0xenWyOO0mx-Jj_djYT7V5FnEW8-OxbnZ2ZbycXlruw",
                use='sig'
                )
            )

    def test_jwk_ec(self):
        client = unittest.mock.Mock()
        client.get_public_key.return_value = self.mock_info3

        key = jwk.Key(client, 'foosign_ec')
        j = key.public_key_jwk

        self.assertEqual(
            j,
            dict(
                crv="P-256",
                kid="D1mAwDrTE2-kl1T1z32Gv9SlfBTkd5oETasReCsC8xo",
                kty="EC",
                x="Bi_pFKSljzZr91kzgw2iA_RAUdi1fnjzxm3xvTjz4MU",
                y="4iMpVOuHLFDO6ER8YW6K6BOHKSNEAlkzrg2TU0czOWs",
                use='sig'
                )
            )
