import base64
import json
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from . import jwa, jwk


class JWS:
    def __init__(self, payload=None):
        self.payload = json.dumps(payload).encode('utf-8')
        self.signatures = list()

    def add_signature(self, key, alg='RS256', protected=None, header=None):
        if key.use != 'sig':
            raise jwk.JWKError('The key is not for signing')

        if header is not None:
            raise NotImplementedError('Unprotected header not implemented')

        try:
            aws_alg = jwa.jwa2aws[alg]
        except KeyError:
            raise jwk.JWKError('Algorithm {} not possible'.format(alg))

        if protected is None:
            protected = dict()

        if header is None:
            header = dict()

        protected_header = dict(
            typ='JWS',
            alg=alg,
            kid=key.public_key_jwk['kid'],
            )
        protected_header.update(protected)
        protected_header = json.dumps(protected_header).encode('utf-8')

        signing_input = jwa.jwa2halg[alg](
            base64.urlsafe_b64encode(protected_header).rstrip(b'=')
            + b'.'
            + base64.urlsafe_b64encode(self.payload).rstrip(b'=')
        ).digest()

        signature = key.sign_digest(signing_input, aws_alg)

        if alg in ('ES256', 'ES384', 'ES512'):
            # Convert DER format signature to R|S
            octets = {
                'ES256': 32,
                'ES384': 48,
                'ES512': 66
                }[alg]
            r, s = decode_dss_signature(signature)
            signature = r.to_bytes(octets, 'big') + s.to_bytes(octets, 'big')

        self.signatures.append(
            dict(
                protected=base64.urlsafe_b64encode(protected_header).decode('utf-8').rstrip('='),
                signature=base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
                ))

        return self

    def serialize(self, compact=False):
        payload = base64.urlsafe_b64encode(self.payload).decode('utf-8').rstrip('=')

        if compact:
            if len(self.signatures) > 1:
                raise jwk.JWKError('Too many signatures for compact JWT')
            if not self.signatures:
                raise jwk.JWKError('Not signed, can\'t serialize JWT')
            return '{}.{}.{}'.format(
                self.signatures[0]['protected'],
                payload,
                self.signatures[0]['signature']
                )

        token = dict(
            payload=payload,
            signatures=self.signatures
            )

        return json.dumps(token)

    @classmethod
    def from_jose_token(self):
        raise NotImplementedError()
