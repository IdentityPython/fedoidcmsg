#!/usr/bin/env python3
import json
import sys

from fedoidc import unfurl

sms_file = sys.argv[1]

def unf(jws):
    msg = unfurl(jws)
    if 'metadata_statements' in msg:
        _sm = {}
        for iss, sms in msg['metadata_statements'].items():
            _sm[iss] = unf(sms)

        msg['metadata_statements'] = _sm

    return msg

for sms_file in sys.argv[1:]:
    print(sms_file)
    print(json.dumps(unf(open(sms_file).read()), sort_keys=True, indent=4,
                     separators=(',', ': ')))
