#!/usr/bin/env python3
import argparse
import json

from fedoidc import MetadataStatement, read_jwks_file
from fedoidc.operator import Operator


parser = argparse.ArgumentParser()
parser.add_argument('-j', dest='jwks',
                    help="A JWKS containing the signers private keys")
parser.add_argument('-i', dest='iss',
                    help='The identifier of the signer')
parser.add_argument('-r', dest='req', help='The message to sign')
parser.add_argument('-l', dest='lifetime', default=86400, type=int,
                    help="The lifetime of the signature")
parser.add_argument('-f', dest='fo',
                    help="The identifier of the federation")
args = parser.parse_args()

kj = read_jwks_file(args.jwks)
op = Operator(keyjar=kj, iss=args.iss, lifetime=args.lifetime)

_req = json.loads(open(args.req).read())
req = MetadataStatement(**_req)

print(op.pack_metadata_statement(req))
