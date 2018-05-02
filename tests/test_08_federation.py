import copy
import os

from oidcmsg.exception import MissingSigningKey
from oidcmsg.key_jar import KeyJar
from oidcmsg.key_jar import public_keys_keyjar
from oidcmsg.oauth2 import Message

from fedoidcmsg import ClientMetadataStatement, ProviderConfigurationResponse
from fedoidcmsg import MIN_SET
from fedoidcmsg import MetadataStatement
from fedoidcmsg import is_lesser
from fedoidcmsg import unfurl
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.operator import Operator
from fedoidcmsg.operator import le_dict
from fedoidcmsg.test_utils import create_compounded_metadata_statement
from fedoidcmsg.test_utils import create_federation_entities

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

ALL = ['https://fo.example.org', 'https://fo1.example.org',
       'https://org.example.org', 'https://inter.example.org',
       'https://admin.example.org', 'https://ligo.example.org',
       'https://op.example.org']

FEDENT = create_federation_entities(ALL, KEYDEFS)

FOP = FEDENT['https://fo.example.org']
FOP.jwks_bundle = JWKSBundle(FOP.iss)
FOP.jwks_bundle[FOP.iss] = FOP.self_signer.keyjar

FO1P = FEDENT['https://fo1.example.org']
FO1P.jwks_bundle = JWKSBundle(FO1P.iss)
FO1P.jwks_bundle[FO1P.iss] = FO1P.self_signer.keyjar

ORGOP = FEDENT['https://org.example.org']
ADMINOP = FEDENT['https://admin.example.org']
INTEROP = FEDENT['https://inter.example.org']
LIGOOP = FEDENT['https://ligo.example.org']
OPOP = FEDENT['https://op.example.org']


def clear_metadata_statements(entities):
    for fedent in entities:
        fedent.metadata_statements = copy.deepcopy(MIN_SET)


def public_jwks_bundle(jwks_bundle):
    jb_copy = JWKSBundle('')
    for fo, kj in jwks_bundle.bundle.items():
        kj_copy = KeyJar()
        for owner in kj.owners():
            public_keys_keyjar(kj, owner, kj_copy, owner)
        jb_copy.bundle[fo] = kj_copy
    return jb_copy


def fo_member(*args):
    """
    Anonymous member of a set of federations.
    Used to parse compounded metadata statements.

    :param args: The federations
    :return: An Operator instance
    """
    _jb = JWKSBundle('https://sunet.se/op')
    for fo in args:
        _jb[fo.iss] = fo.signing_keys_as_jwks()

    return Operator(jwks_bundle=_jb)


def test_create_metadata_statement_simple():
    ms = MetadataStatement()
    ORGOP.add_signing_keys(ms)
    assert ms
    sig_keys = ms['signing_keys']
    assert len(sig_keys['keys']) == 2


def test_create_client_metadata_statement():
    ms = MetadataStatement()
    ORGOP.add_signing_keys(ms)
    sms = FOP.pack_metadata_statement(ms)

    cms = ClientMetadataStatement(
        metadata_statements=Message(**{FOP.iss: sms}),
        contacts=['info@example.com']
    )

    assert cms


def test_pack_and_unpack_ms_lev0():
    cms = ClientMetadataStatement(
        signing_keys=FOP.signing_keys_as_jwks_json(),
        contacts=['info@example.com'], scope=['openid'])

    _jwt = FOP.pack_metadata_statement(cms, sign_alg='RS256')

    assert _jwt
    json_ms = unfurl(_jwt)
    #  print(json_ms.keys())
    assert set(json_ms.keys()) == {'signing_keys', 'iss', 'iat', 'exp',
                                   'kid', 'scope', 'contacts', 'aud'}

    # Unpack what you have packed
    _kj = KeyJar().import_jwks(FOP.signing_keys_as_jwks(), '')
    op = Operator(_kj, jwks_bundle=public_jwks_bundle(FOP.jwks_bundle))
    pr = op.unpack_metadata_statement(jwt_ms=_jwt)

    assert pr.result


def test_pack_ms_wrong_fo():
    cms = ClientMetadataStatement(
        signing_keys=ORGOP.signing_keys_as_jwks(),
        contacts=['info@example.com'], scope=['openid']
    )

    _jwt = create_compounded_metadata_statement([ORGOP.iss, FOP.iss], FEDENT,
                                                {ORGOP.iss: cms})

    member = fo_member(FO1P)
    pr = member.unpack_metadata_statement(jwt_ms=_jwt)
    assert pr.result is None
    assert isinstance(pr.error[_jwt], (MissingSigningKey, KeyError))


def test_pack_and_unpack_ms_lev1():
    # metadata statement created by the organization
    cms_org = ClientMetadataStatement(
        contacts=['info@example.com'], scope=['openid']
    )
    # metadata statement created by the admin
    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
    )

    clear_metadata_statements(FEDENT.values())

    _jwt = create_compounded_metadata_statement(
        [ADMINOP.iss, ORGOP.iss, FOP.iss],
        FEDENT,
        {ORGOP.iss: cms_org, ADMINOP.iss: cms_rp})

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=_jwt)
    assert ri.result


def test_pack_and_unpack_ms_lev2():
    cms_org = ClientMetadataStatement(
        contacts=['info@example.com'], scope=['openid']
    )

    cms_inter = ClientMetadataStatement(
        tos_uri='https://inter.example.com/tos.html',
    )

    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
    )

    clear_metadata_statements(FEDENT.values())

    _jwt = create_compounded_metadata_statement(
        [ADMINOP.iss, INTEROP.iss, ORGOP.iss, FOP.iss],
        FEDENT,
        {ORGOP.iss: cms_org, INTEROP.iss: cms_inter, ADMINOP.iss: cms_rp})

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=_jwt)

    assert ri.result


def test_multiple_fo_one_working():
    cms_org1 = ClientMetadataStatement(
        contacts=['info@example.com'], scope=['openid'])

    cms_none = ClientMetadataStatement()

    clear_metadata_statements(FEDENT.values())

    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, ORGOP.iss, FOP.iss], FEDENT,
        {ORGOP.iss: cms_org1, ADMINOP.iss: cms_none})

    cms_org1 = ClientMetadataStatement(
        contacts=['info@example.com'], scope=['openid', 'address'])

    clear_metadata_statements([FEDENT[ORGOP.iss]])

    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, ORGOP.iss, FO1P.iss], FEDENT,
        {ORGOP.iss: cms_org1, ADMINOP.iss: cms_none})

    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
    )

    ADMINOP.add_sms_spec_to_request(cms_rp)
    sms = ADMINOP.self_sign(cms_rp).to_dict()

    # only knows about one FO
    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(ms_dict=sms)

    assert len(ri.result['metadata_statements']) == 1
    _key = list(ri.result['metadata_statements'].keys())[0]
    _ms = ri.result['metadata_statements'][_key]
    assert _ms['iss'] == ADMINOP.iss


def test_multiple_fo_all_working():
    cms_org1 = ClientMetadataStatement(
        contacts=['info@example.com'], scope=['openid'])

    cms_none = ClientMetadataStatement()

    clear_metadata_statements(FEDENT.values())

    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, ORGOP.iss, FOP.iss], FEDENT,
        {ORGOP.iss: cms_org1, ADMINOP.iss: cms_none})

    cms_org1 = ClientMetadataStatement(
        contacts=['info@example.com'], scope=['openid', 'address'])

    clear_metadata_statements([FEDENT[ORGOP.iss]])

    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, ORGOP.iss, FO1P.iss], FEDENT,
        {ORGOP.iss: cms_org1, ADMINOP.iss: cms_none})

    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
    )

    ADMINOP.add_sms_spec_to_request(cms_rp)
    sms = ADMINOP.self_sign(cms_rp).to_dict()

    # knows all FO's
    receiver = fo_member(FOP, FO1P)
    ri = receiver.unpack_metadata_statement(ms_dict=sms)

    assert len(ri.result['metadata_statements']) == 2
    _iss = [iss for iss, val in ri.result['metadata_statements'].items()]
    assert set(_iss) == {FOP.iss, FO1P.iss}


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
    # Metadata statements created by ORG
    cms_org = ClientMetadataStatement(contacts=['info@example.com'],
                                      scope=['openid'])

    # Metadata statements created by INTER
    cms_inter = ClientMetadataStatement(
        tos_uri='https://inter.example.com/tos.html',
    )

    # Metadata statements created by ADMIN
    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
    )

    clear_metadata_statements(FEDENT.values())

    _jws = create_compounded_metadata_statement(
        [ADMINOP.iss, INTEROP.iss, ORGOP.iss, FOP.iss],
        FEDENT,
        {ORGOP.iss: cms_org, INTEROP.iss: cms_inter, ADMINOP.iss: cms_rp})

    # Unpacked by another member of the FO federation
    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=_jws)

    res = receiver.evaluate_metadata_statement(ri.result)
    assert len(res) == 1
    assert res[0].iss == ORGOP.iss
    assert set(res[0].keys()) == {'contacts', 'tos_uri', 'redirect_uris',
                                  'scope'}


def test_evaluate_metadata_statement_2():
    cms_org = ClientMetadataStatement(
        contacts=['info@example.com'],
        scope=['openid', 'email', 'address']
    )

    cms_inter = ClientMetadataStatement(
        tos_uri='https://inter.example.com/tos.html',
    )

    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
        scope=['openid', 'email'],
    )

    clear_metadata_statements(FEDENT.values())

    _jws = create_compounded_metadata_statement(
        [ADMINOP.iss, INTEROP.iss, ORGOP.iss, FOP.iss],
        FEDENT,
        {ORGOP.iss: cms_org, INTEROP.iss: cms_inter, ADMINOP.iss: cms_rp})

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(jwt_ms=_jws)

    res = receiver.evaluate_metadata_statement(ri.result)
    assert len(res) == 1
    assert res[0].iss == ORGOP.iss
    assert res[0].fo == FOP.iss
    assert set(res[0].keys()) == {'contacts', 'tos_uri', 'redirect_uris',
                                  'scope'}
    assert res[0]['scope'] == ['openid', 'email']


def test_evaluate_metadata_statement_3():
    cms_org = ClientMetadataStatement(
        contacts=['info@example.com'],
        scope=['openid', 'email', 'phone']
    )

    cms_inter = ClientMetadataStatement(
        tos_uri='https://inter.example.com/tos.html',
    )

    cms_rp = ClientMetadataStatement(
        scope=['openid', 'email'],
    )

    clear_metadata_statements(FEDENT.values())

    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, INTEROP.iss, ORGOP.iss, FOP.iss], FEDENT,
        {ORGOP.iss: cms_org, ADMINOP.iss: cms_rp, INTEROP.iss: cms_inter})

    cms_org = ClientMetadataStatement(
        contacts=['info@example.com'],
        scope=['openid', 'email', 'address'],
        claims=['email', 'email_verified']
    )

    cms_rp = ClientMetadataStatement(
        scope=['openid', 'address'],
    )

    clear_metadata_statements([FEDENT[ORGOP.iss], FEDENT[INTEROP.iss]])

    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, INTEROP.iss, ORGOP.iss, FO1P.iss], FEDENT,
        {ORGOP.iss: cms_org, ADMINOP.iss: cms_rp, INTEROP.iss: cms_inter})

    #  Create ultimate registration request and self sign
    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
    )
    ADMINOP.add_sms_spec_to_request(cms_rp)
    _sms = ADMINOP.self_sign(cms_rp).to_dict()

    # knows all FO's
    receiver = fo_member(FOP, FO1P)
    ri = receiver.unpack_metadata_statement(ms_dict=_sms)

    res = receiver.evaluate_metadata_statement(ri.result)
    assert len(res) == 2
    assert set([r.fo for r in res]) == {FOP.iss, FO1P.iss}
    for r in res:
        if r.fo == FOP.iss:
            assert set(r.keys()) == {'contacts', 'tos_uri', 'redirect_uris',
                                     'scope'}
            assert r['scope'] == ['openid', 'email']
        else:
            assert set(r.keys()) == {'contacts', 'tos_uri', 'redirect_uris',
                                     'scope', 'claims'}
            assert r['scope'] == ['openid', 'address']


def test_evaluate_metadata_statement_4():
    """
    One 4-level (FO, Org, Inter, Ligo) and one 2-level (FO1, Ligo)
    """
    cms_org = ClientMetadataStatement(
        contacts=['info@example.com'],
        claims=['email', 'email_verified',
                'phone', 'phone_verified'],
        scope=['openid', 'email', 'phone']
    )

    cms_inter = ClientMetadataStatement(
        tos_uri='https://inter.example.com/tos.html',
    )

    cms_rp = ClientMetadataStatement(
        scope=['openid', 'email'],
    )

    clear_metadata_statements(FEDENT.values())

    # 4
    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, INTEROP.iss, ORGOP.iss, FOP.iss], FEDENT,
        {ORGOP.iss: cms_org, ADMINOP.iss: cms_rp, INTEROP.iss: cms_inter})

    fop_sms = ADMINOP.metadata_statements['discovery'][FOP.iss]
    ADMINOP.metadata_statements['discovery'] = {}

    clear_metadata_statements([FEDENT[LIGOOP.iss]])

    # Need a new untainted instance
    cms_rp = ClientMetadataStatement(
        scope=['openid', 'email'],
    )

    # 2 LIGO is FO
    _ = create_compounded_metadata_statement([ADMINOP.iss, LIGOOP.iss], FEDENT,
                                             {ADMINOP.iss: cms_rp})

    cms_rp = ClientMetadataStatement(
        redirect_uris=['https://rp.example.com/auth_cb'],
    )

    ADMINOP.metadata_statements['discovery'][FOP.iss]= fop_sms
    ADMINOP.add_sms_spec_to_request(cms_rp)
    _sms = ADMINOP.self_sign(cms_rp).to_dict()

    # knows both FO's
    receiver = fo_member(FOP, LIGOOP)
    ri = receiver.unpack_metadata_statement(ms_dict=_sms)

    _re = receiver.evaluate_metadata_statement(ri.result)
    res = le_dict(_re)
    assert set(res.keys()) == {FOP.iss, LIGOOP.iss}
    assert set(res[FOP.iss].keys()) == {'claims', 'contacts', 'redirect_uris',
                                        'scope', 'tos_uri'}

    assert res[FOP.iss]['scope'] == ['openid', 'email']


def test_unpack_discovery_info():
    cms_org = ProviderConfigurationResponse()

    # Made by OP admin
    cms_sa = ProviderConfigurationResponse(
        issuer='https://example.org/op',
        authorization_endpoint='https://example.org/op/auth',
    )

    clear_metadata_statements(FEDENT.values())

    # 4
    _ = create_compounded_metadata_statement(
        [ADMINOP.iss, ORGOP.iss, FOP.iss], FEDENT,
        {ORGOP.iss: cms_org, ADMINOP.iss: cms_sa})

    cms_op = ProviderConfigurationResponse(
        issuer='https://example.org/op',
        authorization_endpoint='https://example.org/op/auth',
    )

    ADMINOP.add_sms_spec_to_request(cms_op)
    _sms = ADMINOP.self_sign(cms_op).to_dict()

    receiver = fo_member(FOP)
    ri = receiver.unpack_metadata_statement(ms_dict=_sms,
                                            cls=ProviderConfigurationResponse)

    pcr_ms = receiver.evaluate_metadata_statement(ri.result)

    assert len(pcr_ms) == 1
    assert pcr_ms[0].fo == FOP.iss
    assert pcr_ms[0]['issuer'] == 'https://example.org/op'

    _ms = pcr_ms[0]
    # This includes default claims
    assert set(_ms.unprotected_and_protected_claims().keys()) == {
        'version', 'token_endpoint_auth_methods_supported',
        'claims_parameter_supported', 'request_parameter_supported',
        'request_uri_parameter_supported', 'require_request_uri_registration',
        'grant_types_supported', 'issuer', 'authorization_endpoint'}

