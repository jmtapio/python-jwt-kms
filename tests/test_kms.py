import unittest

"""
Tests with actual KMS

These tests are skipped if the environment does not have AWS access or
if test keys have not been created.

The tests needs two KMS keys:

  - alias/test-sign-key (a RSA signing key)
  - alias/test-encrypt-key (a RSA encryption key)
"""

import boto3
import json
import jwcrypto.jwk
import jwcrypto.jws

from jwt_kms import jwk, jws


# Check if we have the environment set up
have_key1, have_key2, have_key3 = False, False, False

try:
    client = boto3.client('kms')

    try:
        key1 = jwk.Key(client, 'alias/test-sign-key')
        if key1.key_info:
            have_key1 = True
    except: pass

    try:
        key2 = jwk.Key(client, 'alias/test-encrypt-key')
        if key2.key_info:
            have_key2 = True
    except: pass

    try:
        key3 = jwk.Key(client, 'alias/test-sign-key-p256')
        if key3.key_info:
            have_key3 = True
    except: pass

except:
    pass


@unittest.skipIf(not have_key1, 'KMS signature key not available for test')
class TestSigKey(unittest.TestCase):
    def setUp(self):
        self.key = jwk.Key(client, 'alias/test-sign-key')

    def test_public_key(self):
        pem = self.key.public_key_pem
        self.assertIn(b'BEGIN PUBLIC KEY', pem)

    def test_use(self):
        self.assertEqual(self.key.use, 'sig')

    def test_sign_compact(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key).serialize(compact=True)
        self.assertEqual(token.count('.'), 2)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'RS256')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_long_form(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key).serialize(compact=False)

        dict_token = json.loads(token)
        self.assertIn('payload', dict_token)
        self.assertIn('signatures', dict_token)
        self.assertIn('protected', dict_token['signatures'][0])
        self.assertIn('signature', dict_token['signatures'][0])

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'RS256')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_rs384(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key, 'RS384').serialize(compact=True)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'RS384')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_rs512(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key, 'RS512').serialize(compact=True)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'RS512')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_keyspec(self):
        self.assertEqual(self.key.keyspec, 'RSA_2048')

    def test_sign_ps256(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key, 'PS256').serialize(compact=True)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'PS256')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_ps384(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key, 'PS384').serialize(compact=True)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'PS384')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_ps512(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key, 'PS512').serialize(compact=True)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'PS512')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_es256(self):
        with self.assertRaises(jwk.JWKError):
            jws.JWS({'foo': 'bar'}).add_signature(self.key, 'ES256').serialize(compact=True)


@unittest.skipIf(not have_key2, 'KMS encryption key not available for test')
class TestEncKey(unittest.TestCase):
    def test_use(self):
        key = jwk.Key(client, 'alias/test-encrypt-key')
        self.assertEqual(key.use, 'enc')


@unittest.skipIf(not have_key3, 'KMS P-256 signature key not available for test')
class TestSigKeyP256(unittest.TestCase):
    def setUp(self):
        self.key = jwk.Key(client, 'alias/test-sign-key-p256')

    def test_public_key(self):
        pem = self.key.public_key_pem
        self.assertIn(b'BEGIN PUBLIC KEY', pem)

    def test_use(self):
        self.assertEqual(self.key.use, 'sig')

    def test_sign_compact(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key, 'ES256').serialize(compact=True)
        self.assertEqual(token.count('.'), 2)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'ES256')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_long_form(self):
        token = jws.JWS({'foo': 'bar'}).add_signature(self.key, 'ES256').serialize(compact=False)

        dict_token = json.loads(token)
        self.assertIn('payload', dict_token)
        self.assertIn('signatures', dict_token)
        self.assertIn('protected', dict_token['signatures'][0])
        self.assertIn('signature', dict_token['signatures'][0])

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey, 'ES256')

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_es512(self):
        with self.assertRaises(jwk.JWKError):
            jws.JWS({'foo': 'bar'}).add_signature(self.key, 'ES512').serialize(compact=True)

    def test_keyspec(self):
        self.assertEqual(self.key.keyspec, 'ECC_NIST_P256')
