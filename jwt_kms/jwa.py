import functools
import hashlib

signing_algs = (
    ('RSASSA_PSS_SHA_256',        'PS256', 'sha256'),
    ('RSASSA_PSS_SHA_384',        'PS384', 'sha384'),
    ('RSASSA_PSS_SHA_512',        'PS512', 'sha512'),
    ('RSASSA_PKCS1_V1_5_SHA_256', 'RS256', 'sha256'),
    ('RSASSA_PKCS1_V1_5_SHA_384', 'RS384', 'sha384'),
    ('RSASSA_PKCS1_V1_5_SHA_512', 'RS512', 'sha512'),
    ('ECDSA_SHA_256',             'ES256', 'sha256'),
    ('ECDSA_SHA_384',             'ES384', 'sha384'),
    ('ECDSA_SHA_512',             'ES512', 'sha512'),
    )

jwa2aws = { jwa: aws for aws, jwa, _ in signing_algs }
aws2jwa = { aws: jwa for aws, jwa, _ in signing_algs }
jwa2halg = { jwa: functools.partial(hashlib.new, halg) for _, jwa, halg in signing_algs }
