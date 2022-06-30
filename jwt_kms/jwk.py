import cryptography.hazmat.primitives.serialization
import functools

from . import jwa


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
    def use(self):
        return {
            'ENCRYPT_DECRYPT': 'enc',
            'SIGN_VERIFY': 'sig',
        }.get(self.key_info.get('KeyUsage'))

    @property
    def supported_algs(self):
        return self.key_info.get('SigningAlgorithms', [])

    def sign_digest(self, digest, alg):
        if alg not in self.supported_algs:
            raise ValueError('Alg {} not supported by this key. Supported: {}'.format(
                alg, self.supported_algs))

        return self.client.sign(
            KeyId=self.keyId,
            Message=digest,
            MessageType='DIGEST',
            SigningAlgorithm=alg
        )['Signature']
