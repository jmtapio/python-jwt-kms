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
import jwcrypto.jwk, jwcrypto.jws

from jwt_kms import jwk, jws


# Check if we have the environment set up
have_key1, have_key2 = False, False

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
        public_key = self.key.public_key_pem

        token = jws.JWS({'foo': 'bar'}).add_signature(self.key).serialize(compact=True)
        self.assertEqual(token.count('.'), 2)

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey)

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')

    def test_sign_long_form(self):
        public_key = self.key.public_key_pem

        token = jws.JWS({'foo': 'bar'}).add_signature(self.key).serialize(compact=False)

        dict_token = json.loads(token)
        self.assertIn('payload', dict_token)
        self.assertIn('signatures', dict_token)
        self.assertIn('protected', dict_token['signatures'][0])
        self.assertIn('signature', dict_token['signatures'][0])

        jwkey = jwcrypto.jwk.JWK.from_pem(self.key.public_key_pem)
        jwtoken = jwcrypto.jws.JWS()
        jwtoken.deserialize(token)
        jwtoken.verify(jwkey)

        self.assertEqual(jwtoken.payload, b'{"foo": "bar"}')


@unittest.skipIf(not have_key2, 'KMS encryption key not available for test')
class TestEncKey(unittest.TestCase):
    def test_use(self):
        key = jwk.Key(client, 'alias/test-encrypt-key')
        self.assertEqual(key.use, 'enc')
