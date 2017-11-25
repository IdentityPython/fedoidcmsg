#!/usr/bin/env python3
import json
import sys

from fedoidc import unfurl

def unf(jws):
    msg = unfurl(jws)
    if 'metadata_statements' in msg:
        _sm = {}
        for iss, sms in msg['metadata_statements'].items():
            _sm[iss] = unf(sms)

        msg['metadata_statements'] = _sm

    return msg

for sms in sys.argv[1:]:
    print(json.dumps(unf(sms), sort_keys=True, indent=4,
                     separators=(',', ': ')))
