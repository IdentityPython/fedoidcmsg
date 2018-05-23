#!/usr/bin/env python3

import json

from oidcmsg.key_jar import build_keyjar

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

_jwks, _keyjar, _ = build_keyjar(KEYDEFS)

print(json.dumps(_keyjar.export_jwks(private=True)))

