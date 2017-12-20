from fedoicmsg import MetadataStatement
from fedoicmsg.bundle import JWKSBundle
from fedoicmsg.entity import FederationEntity
from fedoicmsg.operator import Operator
from fedoicmsg.signing_service import InternalSigningService
from fedoicmsg.signing_service import Signer

from oicmsg.oauth2 import Message
from oicmsg.key_jar import build_keyjar
from oicmsg.key_jar import KeyJar
from oicmsg.key_jar import public_keys_keyjar

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

def public_jwks_bundle(jwks_bundle):
    jb_copy = JWKSBundle('')
    for fo, kj in jwks_bundle.bundle.items():
        kj_copy = KeyJar()
        for owner in kj.owners():
            public_keys_keyjar(kj, owner, kj_copy, owner)
        jb_copy.bundle[fo] = kj_copy
    return jb_copy


def test_get_metadata_statement():
    jb = JWKSBundle('')
    for iss in ['https://example.org/', 'https://example.com/']:
        jb[iss] = build_keyjar(KEYDEFS)[1]

    op = Operator(keyjar=jb['https://example.com/'], iss='https://example.com/')
    req = MetadataStatement(foo='bar')
    sms = op.pack_metadata_statement(req, alg='RS256')
    sms_dir = {'https://example.com': sms}
    req['metadata_statements'] = Message(**sms_dir)
    ent = FederationEntity(None, fo_bundle=public_jwks_bundle(jb))
    loe = ent.get_metadata_statement(req)
    assert loe


def test_ace():
    jb = JWKSBundle('')
    for iss in ['https://example.org/', 'https://example.com/']:
        jb[iss] = build_keyjar(KEYDEFS)[1]
    kj = build_keyjar(KEYDEFS)[1]

    sign_serv = InternalSigningService('https://signer.example.com',
                                       signing_keys=kj)
    signer = Signer(sign_serv)
    signer.metadata_statements['response'] = {
        'https://example.org/': 'https://example.org/sms1'}

    ent = FederationEntity(None, keyjar=kj, signer=signer,
                           fo_bundle=public_jwks_bundle(jb))
    req = MetadataStatement(foo='bar')
    ent.ace(req, ['https://example.org/'], 'response')

    assert 'metadata_statements' in req
    assert 'signing_keys' not in req
