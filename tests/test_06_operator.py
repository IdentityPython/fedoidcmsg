import json
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlparse

from cryptojwt import as_unicode
from cryptojwt.jws import factory
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import KeyJar
from oidcmsg.key_jar import public_keys_keyjar

from fedoidcmsg import MetadataStatement
from fedoidcmsg.bundle import FSJWKSBundle
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.operator import Operator
from fedoidcmsg.signing_service import InternalSigningService
from fedoidcmsg.test_utils import create_federation_entities
from fedoidcmsg.test_utils import make_signing_sequence

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

ALL = ['https://swamid.sunet.se', 'https://sunet.se', 'https://op.sunet.se',
       'https://www.feide.no', 'https://edugain.com']

ENTITY = create_federation_entities(ALL, KEYDEFS)

sign_seq = make_signing_sequence(['https://op.sunet.se', 'https://sunet.se',
                                  'https://swamid.sunet.se'], ENTITY)


def public_jwks_bundle(eids):
    jb_copy = JWKSBundle('')
    for eid in eids:
        jwks = ENTITY[eid].signing_keys_as_jwks()
        kj_copy = KeyJar()
        kj_copy.import_jwks(jwks, eid)
        jb_copy.bundle[eid] = kj_copy
    return jb_copy


class Response(object):
    pass


class MockHTTPClient():
    def __init__(self, mds):
        self.mds = mds

    def http_request(self, url):
        p = urlparse(url)
        rsp = Response()
        rsp.status_code = 200
        rsp.text = self.mds[p.path.split('/')[-1]]
        return rsp


def test_pack_metadata_statement():
    jb = FSJWKSBundle('', None, 'fo_jwks',
                      key_conv={'to': quote_plus, 'from': unquote_plus})
    _keyjar = build_keyjar(KEYDEFS)[1]
    self_signer = InternalSigningService('https://example.com/op',
                                         keyjar=_keyjar)
    op = Operator(self_signer=self_signer, jwks_bundle=jb,
                  iss='https://example.com/op')
    req = MetadataStatement(issuer='https://example.org/op')
    sms = op.pack_metadata_statement(req)
    assert sms  # Should be a signed JWT
    _jwt = factory(sms)
    assert _jwt
    assert _jwt.jwt.headers['alg'] == 'RS256'
    _body = json.loads(as_unicode(_jwt.jwt.part[1]))
    assert _body['iss'] == op.iss
    assert _body['issuer'] == 'https://example.org/op'

    # verify signature
    _kj = public_keys_keyjar(_keyjar, '', None, op.iss)
    r = _jwt.verify_compact(sms, _kj.get_signing_key(owner=op.iss))
    assert r


def test_pack_metadata_statement_other_alg():
    _keyjar = build_keyjar(KEYDEFS)[1]
    self_signer = InternalSigningService('https://example.com/op',
                                         keyjar=_keyjar)
    op = Operator(self_signer=self_signer, iss=self_signer.iss)
    req = MetadataStatement(issuer='https://example.org/op')
    sms = op.pack_metadata_statement(req, sign_alg='ES256')
    assert sms  # Should be a signed JWT
    _jwt = factory(sms)
    _body = json.loads(as_unicode(_jwt.jwt.part[1]))
    assert _body['iss'] == self_signer.iss

    # verify signature
    _kj = public_keys_keyjar(_keyjar, '', None, op.iss)
    r = _jwt.verify_compact(sms, _kj.get_signing_key(owner=op.iss))
    assert r
