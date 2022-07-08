# Python `jwt_kms` library

This library is work in progress.

Isolating private asymmetric keys to AWS KMS helps improve security by 
making it next to impossible to make copies of them. This library aims to 
provide a simple interface to use KMS keys to sign payloads into JWS tokens 
and/or to encrypt payloads into JWE tokens.

Signing with RSA and EC keys is currently supported.

## Keys

```
import boto3
from jwt_kms import jwk

client = boto3.client('kms')
key = jwk.JWK(client, 'some-key-id')

public_key_pem = key.public_key_pem
```

## Signing

```
from jwt_kms import jws

payload = {
   'something': 'yes',
   'more_something': 'abc'
}

token = jws.JWS(payload).add_signature(key, 'RS256').serialize(compact=True)  # or compact=False
```

## Encrypting

TODO.
