import os
import shutil

from fedoicmsg import test_utils
from fedoicmsg.operator import Operator
from fedoicmsg.test_utils import MetaDataStore
from fedoicmsg.test_utils import make_fs_jwks_bundle
from fedoicmsg.test_utils import make_jwks_bundle
from fedoicmsg.test_utils import make_ms
from fedoicmsg.test_utils import make_signed_metadata_statement
from fedoicmsg.test_utils import unpack_using_metadata_store
from cryptojwt.jws import factory

from oicmsg.key_jar import KeyJar
from oicmsg.key_jar import build_keyjar

TEST_ISS = "https://test.example.com"
KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

SIGN_KEYJAR = build_keyjar(KEYDEFS)[1]

FO = {'swamid': 'https://swamid.sunet.se', 'feide': 'https://www.feide.no',
      'edugain': 'https://edugain.com', 'example': 'https://example.com'}
OA = {'sunet': 'https://sunet.se', 'uninett': 'https://uninett.no'}

SMS_DEF = {
    OA['sunet']: {
        "discovery": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['swamid'], 'uri': False}
            ],
            FO['feide']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['feide'], 'uri': False}
            ],
            FO['edugain']: [
                {'request': {}, 'requester': FO['swamid'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['edugain'], 'uri': True},
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {}, 'signer': FO['swamid'], 'uri': True}
            ],
            FO['example']: [
                {'request': {}, 'requester': FO['swamid'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['example'], 'uri': True},
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {}, 'signer': FO['swamid'], 'uri': False}
            ]
        }
    }
}


def test_make_jwks_bundle():
    """
    testing in-memory JWKS bundle
    """
    liss = ['https://foo.example.com', 'https://bar.example.com']
    jb = make_jwks_bundle(TEST_ISS, liss, SIGN_KEYJAR, KEYDEFS)
    assert set(jb.keys()) == set(liss)
    for iss in liss:
        _kj = jb[iss]
        assert isinstance(_kj, KeyJar)
        assert len(_kj.owners()) == 1  # Issuers
        assert list(_kj.owners())[0] == iss
        _keys = _kj.get_issuer_keys(iss)
        assert len(_keys) == 2
        assert _kj.keys_by_alg_and_usage(iss, 'RS256', 'sig')
        assert _kj.keys_by_alg_and_usage(iss, 'ES256', 'sig')


def test_make_fs_jwks_bundle():
    """
    testing on disc JWKS bundle
    """
    liss = ['https://foo.example.com', 'https://bar.example.com']
    if os.path.isdir('./fo_jwks'):
        shutil.rmtree('./fo_jwks')

    jb = make_fs_jwks_bundle(TEST_ISS, liss, SIGN_KEYJAR, KEYDEFS)
    assert set(jb.keys()) == set(liss)
    for iss in liss:
        _kj = jb[iss]
        assert isinstance(_kj, KeyJar)
        assert len(_kj.owners()) == 1  # Issuers
        assert list(_kj.owners())[0] == iss
        _keys = _kj.get_issuer_keys(iss)
        assert len(_keys) == 2
        assert _kj.keys_by_alg_and_usage(iss, 'RS256', 'sig')
        assert _kj.keys_by_alg_and_usage(iss, 'ES256', 'sig')


def test_make_signed_metadata_statements():
    mds = MetaDataStore('mds')
    mds.clear()
    liss = list(FO.values())
    liss.extend(list(OA.values()))

    key_bundle = make_fs_jwks_bundle(TEST_ISS, liss, SIGN_KEYJAR, KEYDEFS, './')

    operator = {}

    for entity, _keyjar in key_bundle.items():
        operator[entity] = Operator(iss=entity, keyjar=_keyjar)

    _spec = SMS_DEF[OA['sunet']]["discovery"][FO['swamid']]
    ms = make_signed_metadata_statement(_spec, operator, mds=mds,
                                        base_uri='https:/example.org/ms')
    assert ms

    _spec = SMS_DEF[OA['sunet']]["discovery"][FO['edugain']]
    res = make_signed_metadata_statement(_spec, operator, mds=mds,
                                         base_uri='https:/example.org/ms')
    assert list(res['ms_uri'].keys()) == [FO['edugain']]

    _spec = SMS_DEF[OA['sunet']]["discovery"][FO['example']]
    res = make_signed_metadata_statement(_spec, operator, mds=mds,
                                         base_uri='https:/example.org/ms')
    assert list(res['ms'].keys()) == [FO['example']]
    _jws = factory(res['ms'][FO['example']])
    assert _jws


def test_metadatastore():
    mds = MetaDataStore('mds')
    mds.clear()
    desc = SMS_DEF[OA['sunet']]["discovery"][FO['swamid']][0]
    operator = {}

    liss = list(FO.values())
    liss.extend(list(OA.values()))

    key_bundle = make_fs_jwks_bundle(TEST_ISS, liss, SIGN_KEYJAR, KEYDEFS, './')
    for entity, _keyjar in key_bundle.items():
        operator[entity] = Operator(iss=entity, keyjar=_keyjar)

    _x = make_ms(desc, False, operator)
    _jws = list(_x.values())[0]
    mds[mds.hash(_jws)] = _jws

    assert mds.hash(_jws) in list(mds.keys())


def test_make_signed_metadata_statement_mixed():
    liss = list(FO.values())
    liss.extend(list(OA.values()))

    key_bundle = make_fs_jwks_bundle(TEST_ISS, liss, SIGN_KEYJAR, KEYDEFS, './')

    operator = {}

    for entity, _keyjar in key_bundle.items():
        operator[entity] = Operator(iss=entity, keyjar=_keyjar)

    _spec = SMS_DEF[OA['sunet']]["discovery"][FO['swamid']]
    mds = MetaDataStore('mds')
    mds.clear()
    sms = make_signed_metadata_statement(_spec, operator, mds=mds,
                                         base_uri='https:/example.org/ms')
    assert sms

    _spec = SMS_DEF[OA['sunet']]["discovery"][FO['edugain']]

    sms = make_signed_metadata_statement(_spec, operator, mds=mds,
                                         base_uri='https:/example.org/ms')
    assert list(sms['ms_uri'].keys()) == [FO['edugain']]

    # Now parse the result

    _md0 = unpack_using_metadata_store(sms['ms_uri'][FO['edugain']], mds)

    op = Operator()
    _res = op.evaluate_metadata_statement(_md0)
    assert _res[0].le == {'federation_usage': 'discovery'}


def test_setup_ms():
    liss = list(FO.values())
    liss.extend(list(OA.values()))

    # keydefs, tool_iss, liss, ms_path
    res = test_utils.setup(KEYDEFS, 'iss', liss, 'ms', csms_def=SMS_DEF,
                           mds_dir='mds', base_url='http://example.org')

    assert res
