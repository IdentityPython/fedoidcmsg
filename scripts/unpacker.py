#!/usr/bin/env python3
import argparse

from fedoidc import read_jwks_file
from fedoidc.bundle import JWKSBundle
from fedoidc.operator import Operator


parser = argparse.ArgumentParser()
parser.add_argument('-j', dest='jwks',
                    help="A JWKS file that contains the federation operators public keys")
parser.add_argument('-r', dest='req', help="The message")
parser.add_argument('-f', dest='fo', help='The identifier of the Federation')
parser.add_argument('-l', dest='flatten', action='store_true',
                    help="Flatten the compounded metadata statement")
args = parser.parse_args()

kj = read_jwks_file(args.jwks)

_bundle = JWKSBundle('')
_bundle[args.fo] = kj

op = Operator(jwks_bundle=_bundle)

_fo, _req = open(args.req).read().rsplit(':', 1)

res = op.unpack_metadata_statement(jwt_ms=_req.strip())

print(res.result)