import json
import os

from fedoidcmsg import ClientMetadataStatement
from fedoidcmsg import MetadataStatement
from fedoidcmsg import ProviderConfigurationResponse
from fedoidcmsg import is_lesser
from fedoidcmsg import unfurl
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.bundle import verify_signed_bundle
from fedoidcmsg.operator import Operator
from fedoidcmsg.operator import le_dict
from cryptojwt import jws

from oidcmsg.exception import MissingSigningKey
from oidcmsg.oauth2 import Message
from oidcmsg.key_jar import KeyJar, public_keys_keyjar
from oidcmsg.key_jar import build_keyjar

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

KEYS = {}
ISSUER = {}
OPERATOR = {}

for entity in ['fo', 'fo1', 'org', 'inter', 'admin', 'ligo', 'op']:
    fname = os.path.join(BASE_PATH, "{}.key".format(entity))
    _keydef = KEYDEFS[:]
    _keydef[0]['key'] = fname

    _jwks, _keyjar, _kidd = build_keyjar(_keydef)
    KEYS[entity] = {'jwks': json.dumps(_jwks), 'keyjar': _keyjar, 'kidd': _kidd}
    ISSUER[entity] = 'https://{}.example.org'.format(entity)
    OPERATOR[entity] = Operator(keyjar=_keyjar, iss=ISSUER[entity])

FOP = OPERATOR['fo']
FOP.jwks_bundle = JWKSBundle(FOP.iss)
FOP.jwks_bundle[FOP.iss] = FOP.keyjar

FO1P = OPERATOR['fo1']
FO1P.jwks_bundle = JWKSBundle(FO1P.iss)
FO1P.jwks_bundle[FO1P.iss] = FO1P.keyjar

ORGOP = OPERATOR['org']
ADMINOP = OPERATOR['admin']
INTEROP = OPERATOR['inter']
LIGOOP = OPERATOR['ligo']
OPOP = OPERATOR['ligo']


def public_jwks_bundle(jwks_bundle):
    jb_copy = JWKSBundle('')
    for fo, kj in jwks_bundle.bundle.items():
        kj_copy = KeyJar()
        for owner in kj.owners():
            public_keys_keyjar(kj, owner, kj_copy, owner)
        jb_copy.bundle[fo] = kj_copy
    return jb_copy


def fo_member(*args):
    _jb = JWKSBundle('https://sunet.se/op')
    for fo in args:
        _jb[fo.iss] = fo.signing_keys_as_jwks()

    return Operator(jwks_bundle=_jb)


def test_create_metadata_statement_simple():
    ms = MetadataStatement(signing_keys=KEYS['org']['jwks'])

    assert ms
    sig_keys=ms['signing_keys']
    assert len(sig_keys['keys']) == 2


def test_create_client_metadata_statement():
    ms = MetadataStatement(signing_keys=KEYS['org']['jwks'])
    ms_jwt = ms.to_jwt(KEYS['fo']['keyjar'].get_signing_key('rsa'))

    cms = ClientMetadataStatement(
        metadata_statements=Message(**{ISSUER['org']: ms_jwt}),
        contacts=['info@example.com']
    )

    assert cms


def test_pack_and_unpack_ms_lev0():
    cms = ClientMetadataStatement(
        signing_keys=json.dumps(FOP.keyjar.export_jwks_as_json()),
        contacts=['info@example.com'])

    _jwt = FOP.pack_metadata_statement(cms, alg='RS256', scope=['openid'])

    assert _jwt
    json_ms = unfurl(_jwt)
    #  print(json_ms.keys())
    assert set(json_ms.keys()) == {'signing_keys', 'iss', 'iat', 'exp',
                                   'kid', 'scope', 'contacts', 'aud'}

    # Unpack what you have packed
    _kj = public_keys_keyjar(FOP.keyjar, '', None, FOP.iss)
    op = Operator(_kj, jwks_bundle=public_jwks_bundle(FOP.jwks_bundle))
    pr = op.unpack_metadata_statement(jwt_ms=_jwt)

    assert pr.result


def test_pack_ms_wrong_fo():
    cms = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    _jwt = FOP.pack_metadata_statement(cms, alg='RS256', scope=['openid'])

    member = fo_member(FO1P)
    pr = member.unpack_metadata_statement(jwt_ms=_jwt)
    assert pr.result is None
    assert isinstance(pr.error[_jwt], (MissingSigningKey, KeyError))

    # try:
    # except JWSException as err:
    #     assert isinstance(err, NoSuitableSigningKeys)
    # except MissingSigningKey:
    #     assert True
    # else:
    #     assert False


def test_pack_and_unpack_ms_lev1():
    # metadata statement created by the organization
    cms_org = ClientMetadataStatement(
        signing_keys=ORGOP.keyjar.export_jwks_as_json(),
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256', scope=['openid'])

    # metadata statement created by the admin
    cms_rp = ClientMetadataStatement(
        signing_keys=ADMINOP.keyjar.export_jwks_as_json(),
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    # signed by the org
    ms_rp = ORGOP.pack_metadata_statement(
        cms_rp, alg='RS256', metadata_statements=Message(**{FOP.iss: ms_org}))

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)
    assert ri.result


def test_pack_and_unpack_ms_lev2():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256', scope=['openid'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri='https://inter.example.com/tos.html'
    )

    #  signed by org
    ms_inter = ORGOP.pack_metadata_statement(
        cms_inter, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_org}))

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(
        cms_rp, alg='RS256', metadata_statements=Message(**{FOP.iss: ms_inter}))

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    assert ri.result


def test_multiple_fo_one_working():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org1 = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                          scope=['openid'])

    #  signed by FO1
    ms_org2 = FO1P.pack_metadata_statement(cms_org, alg='RS256',
                                           scope=['openid', 'address'])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    ms_rp = ORGOP.pack_metadata_statement(
        cms_rp, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_org1, FO1P.iss: ms_org2}))

    # only knows about one FO
    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    assert len(ri.result['metadata_statements']) == 1
    _key = list(ri.result['metadata_statements'].keys())[0]
    _ms = ri.result['metadata_statements'][_key]
    assert _ms['iss'] == ISSUER['fo']


def test_multiple_fo_all_working():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org1 = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                          scope=['openid'])

    #  signed by FO1
    ms_org2 = FO1P.pack_metadata_statement(cms_org, alg='RS256',
                                           scope=['openid', 'address'])

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    ms_rp = ORGOP.pack_metadata_statement(
        cms_rp, alg='RS256', metadata_statements=Message(**{FOP.iss: ms_org1,
                                                            FO1P.iss: ms_org2}))

    # knows all FO's
    receiver = fo_member(FOP, FO1P)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    assert len(ri.result['metadata_statements']) == 2
    _iss = [iss for iss, val in ri.result['metadata_statements'].items()]
    assert set(_iss) == {ISSUER['fo'], ISSUER['fo1']}


def test_is_lesser_strings():
    assert is_lesser('foo', 'foo')
    assert is_lesser('foo', 'fox') is False
    assert is_lesser('foo', 'FOO') is False


def test_is_lesser_list():
    assert is_lesser(['foo'], ['foo'])
    assert is_lesser(['foo', 'fox'], ['fox', 'foo'])
    assert is_lesser(['fee', 'foo'], ['foo', 'fee', 'fum'])
    assert is_lesser(['fee', 'fum', 'foo'], ['foo', 'fee', 'fum'])

    assert is_lesser(['fee', 'foo', 'fum'], ['foo', 'fee']) is False
    assert is_lesser(['fee', 'fum'], ['fee']) is False


def test_evaluate_metadata_statement_1():
    cms_org = ClientMetadataStatement(
        signing_keys=ORGOP.keyjar.export_jwks_as_json(),
        contacts=['info@example.com'])

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256', scope=['openid'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri='https://inter.example.com/tos.html'
    )

    #  signed by org
    ms_inter = ORGOP.pack_metadata_statement(
        cms_inter, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_org}))

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(
        cms_rp, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_inter}))

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    res = receiver.evaluate_metadata_statement(ri.result)
    assert len(res) == 1
    assert res[0].iss == ISSUER['org']
    assert sorted(list(res[0].keys())) == sorted(
        ['contacts', 'tos_uri', 'redirect_uris', 'scope'])


def test_evaluate_metadata_statement_2():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                         scope=['openid', 'email', 'address'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri='https://inter.example.com/tos.html'
    )

    #  signed by org
    ms_inter = ORGOP.pack_metadata_statement(
        cms_inter, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_org}))

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(
        cms_rp, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_inter}))

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    res = receiver.evaluate_metadata_statement(ri.result)
    assert len(res) == 1
    assert res[0].iss == ISSUER['org']
    assert res[0].fo == ISSUER['fo']
    assert sorted(list(res[0].keys())) == sorted(
        ['contacts', 'tos_uri', 'redirect_uris', 'scope'])

    assert res[0]['scope'] == ['openid', 'email', 'address']


def test_evaluate_metadata_statement_3():
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org1 = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                          claims=['email', 'email_verified',
                                                  'phone', 'phone_verified'],
                                          scope=['openid', 'email', 'phone'])

    #  signed by FO1
    ms_org2 = FO1P.pack_metadata_statement(cms_org, alg='RS256',
                                           scope=['openid', 'email', 'address'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri='https://inter.example.com/tos.html'
    )

    ms_inter = {}
    for k, v in {FOP.iss: ms_org1, FO1P.iss: ms_org2}.items():
        #  signed by org
        ms_inter[k] = ORGOP.pack_metadata_statement(
            cms_inter, alg='RS256',
            metadata_statements=Message(**{k: v}))

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(
        cms_rp, alg='RS256', metadata_statements=Message(**ms_inter))

    # knows all FO's
    receiver = fo_member(FOP, FO1P)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    res = receiver.evaluate_metadata_statement(ri.result)
    assert len(res) == 2
    assert set([r.fo for r in res]) == {ISSUER['fo'], ISSUER['fo1']}
    for r in res:
        if r.fo == ISSUER['fo']:
            assert sorted(list(r.keys())) == sorted(
                ['claims', 'contacts', 'tos_uri', 'redirect_uris', 'scope'])
            assert r['scope'] == ['openid', 'email', 'phone']
        else:
            assert sorted(list(r.keys())) == sorted(
                ['contacts', 'tos_uri', 'redirect_uris', 'scope'])
            assert r['scope'] == ['openid', 'email', 'address']


def test_evaluate_metadata_statement_4():
    """
    One 4-level (FO, Org, Inter, admin) and one 2-level (FO1, Inter, admin)
    """
    cms_org = ClientMetadataStatement(
        signing_keys=KEYS['org']['jwks'],
        contacts=['info@example.com']
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256',
                                         claims=['email', 'email_verified',
                                                 'phone', 'phone_verified'],
                                         scope=['openid', 'email', 'phone'])

    cms_inter = ClientMetadataStatement(
        signing_keys=KEYS['inter']['jwks'],
        tos_uri='https://inter.example.com/tos.html'
    )

    #  signed by org
    ms_inter0 = ORGOP.pack_metadata_statement(
        cms_inter, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_org}))

    ms_inter1 = LIGOOP.pack_metadata_statement(cms_inter, alg='ES256')

    cms_rp = ClientMetadataStatement(
        signing_keys=KEYS['admin']['jwks'],
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email']
    )

    #  signed by intermediate
    ms_rp = INTEROP.pack_metadata_statement(
        cms_rp, alg='RS256',
        metadata_statements=Message(
            **{FOP.iss: ms_inter0, LIGOOP.iss: ms_inter1}))

    # knows both FO's
    receiver = fo_member(FOP, LIGOOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=ms_rp)

    _re = receiver.evaluate_metadata_statement(ri.result)
    res = le_dict(_re)
    assert set(res.keys()) == {ISSUER['fo'], ISSUER['ligo']}
    assert sorted(list(res[ISSUER['fo']].keys())) == sorted(
        ['claims', 'contacts', 'redirect_uris', 'scope', 'tos_uri'])

    assert res[ISSUER['fo']]['scope'] == ['openid', 'email', 'phone']


def test_unpack_discovery_info():
    resp = ProviderConfigurationResponse()

    cms_org = ProviderConfigurationResponse(
        signing_keys=KEYS['org']['jwks'],
    )

    #  signed by FO
    ms_org = FOP.pack_metadata_statement(cms_org, alg='RS256')

    # Made by OP admin
    cms_sa = ProviderConfigurationResponse(
        signing_keys=KEYS['op']['jwks'],
        issuer='https://example.org/op',
        authorization_endpoint='https://example.org/op/auth'
    )

    #  signed by org
    ms_rp = ORGOP.pack_metadata_statement(
        cms_sa, alg='RS256',
        metadata_statements=Message(**{FOP.iss: ms_org}))

    # ProviderConfigurationResponse sent to the RP
    pcr = ProviderConfigurationResponse(
        issuer='https://example.org/op',
        authorization_endpoint='https://example.org/op/auth',
        metadata_statements=Message(**{FOP.iss: ms_rp})
    )

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(json_ms=pcr,
                                            cls=ProviderConfigurationResponse)

    pcr_ms = receiver.evaluate_metadata_statement(ri.result)

    assert len(pcr_ms) == 1
    assert pcr_ms[0].fo == ISSUER['fo']
    assert pcr_ms[0]['issuer'] == 'https://example.org/op'

    _ms = pcr_ms[0]
    assert _ms.unprotected_and_protected_claims() == {}


def test_create_fo_keys_bundle():
    jb = JWKSBundle(ORGOP.iss, ORGOP.keyjar)
    jb[FOP.iss] = FOP.keyjar
    jb[FO1P.iss] = FO1P.keyjar
    sb = jb.create_signed_bundle()
    _jw = jws.factory(sb)
    assert _jw


def test_create_verify_fo_keys_bundle():
    jb = JWKSBundle(ORGOP.iss, ORGOP.keyjar)
    jb[FOP.iss] = FOP.keyjar
    jb[FO1P.iss] = FO1P.keyjar
    sb = jb.create_signed_bundle()

    kj = public_keys_keyjar(ORGOP.keyjar, '', None, ORGOP.iss)

    _jwt = verify_signed_bundle(sb, kj)
    bundle = _jwt["bundle"]
    assert set(bundle.keys()) == {FOP.iss, FO1P.iss}
