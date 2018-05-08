import os
from urllib.parse import quote_plus

from oidcmsg.key_jar import KeyJar
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import public_keys_keyjar
from oidcmsg.oauth2 import Message

from fedoidcmsg import MetadataStatement
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.entity import FederationEntity
from fedoidcmsg.entity import FederationEntityOOB
from fedoidcmsg.entity import make_federation_entity
from fedoidcmsg.operator import Operator
from fedoidcmsg.signing_service import InternalSigningService
from fedoidcmsg.test_utils import make_signing_sequence, create_federation_entities

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
    sms = op.pack_metadata_statement(req, sign_alg='RS256')
    sms_dir = {'https://example.com': sms}
    req['metadata_statements'] = Message(**sms_dir)
    ent = FederationEntity(None, fo_bundle=public_jwks_bundle(jb))
    loe = ent.get_metadata_statement(req)
    assert loe


def test_add_sms_spec_to_request():
    jb = JWKSBundle('')
    for iss in ['https://example.org/', 'https://example.com/']:
        jb[iss] = build_keyjar(KEYDEFS)[1]
    kj = build_keyjar(KEYDEFS)[1]

    sign_serv = InternalSigningService('https://signer.example.com',
                                       keyjar=kj)
    ent = FederationEntityOOB(None, self_signer=sign_serv,
                              fo_bundle=public_jwks_bundle(jb),
                              context='response')
    ent.metadata_statements = {
        'response': {
            'https://example.org/': 'https://example.org/sms1'
        }
    }

    req = MetadataStatement(foo='bar')
    ent.add_sms_spec_to_request(req, ['https://example.org/'])

    assert 'metadata_statement_uris' in req


def test_add_signing_keys():
    kj = build_keyjar(KEYDEFS)[1]
    sign_serv = InternalSigningService('https://signer.example.com',
                                       keyjar=kj)
    ent = FederationEntityOOB(None, self_signer=sign_serv)
    req = MetadataStatement(foo='bar')
    ent.add_signing_keys(req)
    assert 'signing_keys' in req


_path = os.path.realpath(__file__)
root_dir, _fname = os.path.split(_path)


def test_make_federation_entity():
    config = {
        'self_signer': {
            'private_path': '{}/private_jwks'.format(root_dir),
            'key_defs': KEYDEFS,
            'public_path': '{}/public_jwks'.format(root_dir)
        },
        'sms_dir': '{}/ms/https%3A%2F%2Fsunet.se'.format(root_dir),
        'fo_bundle': {
            'private_path': '{}/fo_bundle_signing_keys'.format(root_dir),
            'key_defs': KEYDEFS,
            'public_path': '{}/pub_fo_bundle_signing_keys'.format(root_dir),
            'dir': '{}/fo_jwks'.format(root_dir)
        }
    }

    fe = make_federation_entity(config, 'https://op.example.com')
    assert fe
    assert isinstance(fe, FederationEntityOOB)
    assert isinstance(fe.jwks_bundle, JWKSBundle)
    assert fe.iss == 'https://op.example.com'


def test_sequence():
    config = {
        'self_signer': {
            'private_path': '{}/private_jwks'.format(root_dir),
            'key_defs': KEYDEFS,
            'public_path': '{}/public_jwks'.format(root_dir)
        },
        'sms_dir': '{}/ms/https%3A%2F%2Fsunet.se'.format(root_dir),
        'fo_bundle': {
            'private_path': '{}/fo_bundle_signing_keys'.format(root_dir),
            'key_defs': KEYDEFS,
            'public_path': '{}/pub_fo_bundle_signing_keys'.format(root_dir),
            'dir': '{}/fo_jwks'.format(root_dir)
        },
        'context': 'discovery'
    }

    fe = make_federation_entity(config, 'https://op.example.com')

    req = MetadataStatement(foo='bar')

    fe.add_sms_spec_to_request(req)
    fe.add_signing_keys(req)
    updated_req = fe.self_sign(req, 'https://example.com')

    assert updated_req
    assert set(updated_req.keys()) == {'foo', 'signing_keys',
                                       'metadata_statements',
                                       'metadata_statement_uris'}


ENTITY = create_federation_entities(['https://op.sunet.se', 'https://sunet.se',
                                     'https://swamid.sunet.se'], KEYDEFS,
                                    root_dir=root_dir)


def test_update_metadata_statement():
    make_signing_sequence(['https://op.sunet.se', 'https://sunet.se',
                           'https://swamid.sunet.se'], ENTITY)

    op = ENTITY['https://op.sunet.se']
    metadata_statement = MetadataStatement(foo='bar')
    metadata_statement = op.update_metadata_statement(metadata_statement)
    assert metadata_statement
    assert set(metadata_statement.keys()) == {'foo', 'metadata_statements'}

    swamid = ENTITY['https://swamid.sunet.se']
    # on the RP side
    rp = FederationEntityOOB(None, 'https://rp.sunet.se')
    # Need the FO bundle, which in this case only needs Swamid's key
    jb = JWKSBundle('https://rp.sunet.se')
    _kj = KeyJar()
    _kj.import_jwks(swamid.self_signer.public_keys(), swamid.iss)
    jb['https://swamid.sunet.se'] = _kj
    rp.jwks_bundle = jb

    l = rp.get_metadata_statement(metadata_statement, MetadataStatement,
                                  'discovery')

    assert l[0].iss == 'https://op.sunet.se'
    assert l[0].fo == 'https://swamid.sunet.se'
    assert l[0].le == {'foo':'bar'}


def test_updating_metadata_no_superior():
    op = ENTITY['https://op.sunet.se']
    op.metadata_statements['discovery'] = {}
    metadata_statement = MetadataStatement(foo='bar')
    metadata_statement = op.update_metadata_statement(metadata_statement)
    assert metadata_statement
    assert set(metadata_statement.keys()) == {'foo', 'metadata_statements'}

    # swamid = ENTITY['https://swamid.sunet.se']
    # on the RP side
    rp = FederationEntityOOB(None, 'https://rp.sunet.se')

    # # Need the FO bundle, which in this case only needs Swamid's key
    # jb = JWKSBundle('https://rp.sunet.se')
    # _kj = KeyJar()
    # _kj.import_jwks(swamid.self_signer.public_keys(), swamid.iss)
    # jb['https://swamid.sunet.se'] = _kj
    # rp.jwks_bundle = jb

    l = rp.get_metadata_statement(metadata_statement, MetadataStatement,
                                  'discovery')

    assert l[0].iss == 'https://op.sunet.se'
    assert l[0].fo == 'https://op.sunet.se'
    assert l[0].le == {'foo':'bar'}
