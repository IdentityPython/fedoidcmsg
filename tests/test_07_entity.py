from fedoidcmsg import MetadataStatement
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.entity import FederationEntity
from fedoidcmsg.entity import make_federation_entity
from fedoidcmsg.operator import Operator
from fedoidcmsg.signing_service import InternalSigningService
from fedoidcmsg.signing_service import Signer

from oidcmsg.oauth2 import Message
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import KeyJar
from oidcmsg.key_jar import public_keys_keyjar

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

    self_signer = InternalSigningService(keyjar=jb['https://example.com/'],
                                         iss='https://example.com/')
    op = Operator(self_signer=self_signer, iss='https://example.com/')
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
                                       keyjar=kj)
    signer = Signer(sign_serv)
    signer.metadata_statements['response'] = {
        'https://example.org/': 'https://example.org/sms1'
    }

    ent = FederationEntity(None, self_signer=sign_serv, signer=signer,
                           fo_bundle=public_jwks_bundle(jb))
    req = MetadataStatement(foo='bar')
    ent.ace(req, ['https://example.org/'], 'response')

    assert 'metadata_statements' in req
    assert 'signing_keys' not in req


def test_make_federation_entity():
    config = {
        'signer': {
            'signing_service': {
                'type': 'internal',
                'private_path': './private_jwks',
                'key_defs': KEYDEFS,
                'public_path': './public_jwks'
                },
            'ms_dir': 'ms_dir'
            },
        'fo_bundle': {
            'private_path': './fo_bundle_signing_keys',
            'key_defs': KEYDEFS,
            'public_path': './pub_fo_bundle_signing_keys',
            'bundle': 'bundle.json'
            },
        'private_path': './entity_keys',
        'key_defs': KEYDEFS,
        'public_path': './pub_entity_keys'
        }

    fe = make_federation_entity(config, 'https://op.example.com')
    assert fe
    assert isinstance(fe.signer, Signer)
    assert isinstance(fe.jwks_bundle, JWKSBundle)
    assert fe.iss == 'https://op.example.com'
    assert fe.signer.signing_service.iss == 'https://op.example.com'
