import base64
import cryptography.hazmat.primitives.serialization
import functools
import hashlib
import json
import math


class JWKError(Exception):
    pass


class Key:
    def __init__(self, client, keyId):
        self.client = client
        self.keyId = keyId

    @functools.cached_property
    def key_info(self):
        return self.client.get_public_key(KeyId=self.keyId)

    @property
    def public_key(self):
        return cryptography.hazmat.primitives.serialization.load_der_public_key(
            self.key_info['PublicKey'])

    @property
    def public_key_pem(self):
        return self.public_key.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM,
            cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @property
    def public_key_jwk(self):
        if self.keyspec.startswith('RSA_'):
            num = self.public_key.public_numbers()
            core = dict(
                kty='RSA',
                n=self._encode_b64u(num.n),
                e=self._encode_b64u(num.e)
                )
            core.update(dict(
                use=self.use,
                kid=self._thumbprint(core),
                ))
            return core

        elif self.keyspec.startswith('ECC_NIST_'):
            num = self.public_key.public_numbers()
            core = dict(
                kty='EC',
                crv={
                    'ECC_NIST_P256': 'P-256',
                    'ECC_NIST_P384': 'P-384',
                    'ECC_NIST_P512': 'P-512',
                }[self.keyspec],
                x=self._encode_b64u(num.x),
                y=self._encode_b64u(num.y),
            )
            core.update(dict(
                use=self.use,
                kid=self._thumbprint(core),
                ))
            return core

        raise JWKError('Unknown keyspec {}'.format(self.keyspec))

    @property
    def use(self):
        return {
            'ENCRYPT_DECRYPT': 'enc',
            'SIGN_VERIFY': 'sig',
        }.get(self.key_info.get('KeyUsage'))

    @property
    def supported_algs(self):
        return self.key_info.get('SigningAlgorithms', [])

    @property
    def keyspec(self):
        return self.key_info.get('CustomerMasterKeySpec', '')

    def sign_digest(self, digest, alg):
        if alg not in self.supported_algs:
            raise JWKError('Alg {} not supported by this key. Supported: {}'.format(
                alg, self.supported_algs))

        return self.client.sign(
            KeyId=self.keyId,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm=alg
        )['Signature']

    def _encode_b64u(self, number):
        return base64.urlsafe_b64encode(
            number.to_bytes(
                math.ceil(math.log2(number)/8), 'big'
                )
        ).decode('utf-8').rstrip('=')

    def _thumbprint(self, d):
        return base64.urlsafe_b64encode(
            hashlib.sha256(
                json.dumps(d, sort_keys=True, separators=(',', ':')).encode('utf-8')
            ).digest()
        ).decode('utf-8').rstrip('=')
