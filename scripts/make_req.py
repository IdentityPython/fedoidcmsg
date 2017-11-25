#!/usr/bin/env python3
import argparse
import json

from fedoidc import read_jwks_file
from fedoidc.operator import Operator

parser = argparse.ArgumentParser()
parser.add_argument('-j', dest='jwks',
                    help="A JWKS containing the signing keys for this entity")
parser.add_argument(
    '-r', dest='req',
    help="The basic message to which should be added the signing keys and metadata statements")
parser.add_argument('-m', dest='ms', action='append',
                    help="Metadata statements to add the basic message")
args = parser.parse_args()

kj = read_jwks_file(args.jwks)
op = Operator(keyjar=kj)

_req = json.loads(open(args.req).read())
_req['signing_keys'] = op.keyjar.export_jwks()
if args.ms:
    _req["metadata_statements"] = dict(
        [open(m).read().strip().rsplit(':', 1) for m in args.ms])
print(json.dumps(_req))
