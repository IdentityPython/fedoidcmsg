import shutil

from cryptojwt.jws import factory
from oidcmsg.key_jar import KeyJar
from oidcmsg.oidc import RegistrationRequest

from fedoidcmsg import MetadataStatement
from fedoidcmsg import test_utils
from fedoidcmsg.signing_service import InternalSigningService
from fedoidcmsg.signing_service import make_signing_service
from fedoidcmsg.signing_service import WebSigningServiceClient

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

TOOL_ISS = 'https://localhost'

FO = {'swamid': 'https://swamid.sunet.se', 'feide': 'https://www.feide.no'}

OA = {'sunet': 'https://sunet.se'}

IA = {}

SMS_DEF = {
    OA['sunet']: {
        "discovery": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'discovery'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        },
        "registration": {
            FO['swamid']: [
                {'request': {}, 'requester': OA['sunet'],
                 'signer_add': {'federation_usage': 'registration'},
                 'signer': FO['swamid'], 'uri': False},
            ]
        },
    }
}

liss = list(FO.values())
liss.extend(list(OA.values()))

shutil.rmtree('ms', ignore_errors=True)

signer, keybundle = test_utils.setup(
    KEYDEFS, TOOL_ISS, liss, ms_path='ms', csms_def=SMS_DEF,
    mds_dir='mds', base_url='https://localhost')


class Response(object):
    def __init__(self, status_code, text, headers):
        self.status_code = status_code
        self.text = text
        self.headers = headers


def test_make_internal_signing_service():
    config = {
        'type': 'internal',
        'private_path': './private_jwks',
        'key_defs': KEYDEFS,
        'public_path': './public_jwks'
    }
    signing_service = make_signing_service(config, 'https://example.com')
    assert signing_service.iss == 'https://example.com'
    assert len(signing_service.signing_keys.issuer_keys['']) == 1
    assert len(signing_service.signing_keys.issuer_keys[''][0]) == 2


def test_make_web_signing_service():
    config = {
        'type': 'web',
        'public_path': './public_jwks',
        'iss': 'https://example.com/mdss',
        'url': 'https://example.com/mdss'
    }
    signing_service = make_signing_service(config, 'https://example.com')
    assert signing_service.id == 'https://example.com'
    assert signing_service.iss == 'https://example.com/mdss'
    assert signing_service.url == 'https://example.com/mdss'
    assert len(signing_service.keyjar.issuer_keys[
                   'https://example.com/mdss']) == 1
    assert len(signing_service.keyjar.issuer_keys[
                   'https://example.com/mdss'][0]) == 2


def test_internal_signing_service():
    _kj = keybundle['https://swamid.sunet.se']
    iss = InternalSigningService('https://swamid.sunet.se', _kj)
    res = iss.create(
        RegistrationRequest(redirect_uris=['https://example.com/rp/cb']),
        'https://example.com/rp'
    )
    assert 'sms' in res
    _jws = factory(res['sms'])
    assert _jws.jwt.headers['alg'] == 'RS256'
    msg = _jws.jwt.payload()
    assert msg['iss'] == 'https://swamid.sunet.se'
    assert msg['aud'] == ['https://example.com/rp']


def test_signer():
    items = signer[OA['sunet']].items()
    assert set(list(items.keys())) == {'discovery', 'registration'}
    assert set(list(items['discovery'])) == {FO['swamid']}


def test_create_sms():
    s = signer[OA['sunet']]
    req = MetadataStatement(issuer='https://example.org/op')
    r = s.create_signed_metadata_statement(req, 'discovery')
    assert r


def test_web_signing_service():
    _kj = keybundle['https://swamid.sunet.se']
    iss = InternalSigningService('https://swamid.sunet.se', _kj)
    _sms = iss.create(
        RegistrationRequest(redirect_uris=['https://example.com/rp/cb']),
        'https://example.com/rp'
    )

    _jwks = _kj.export_jwks()
    _vkj = KeyJar()
    _vkj.import_jwks(_jwks, 'https://swamid.sunet.se')

    wss = WebSigningServiceClient('https://swamid.sunet.se',
                                  'https://swamid.sunet.se/mdss',
                                  'https://example.com/rp', _vkj)

    response = Response(200, _sms['sms'],
                        {'Location': 'https://swamid.sunet.se/mdss/abcdefg'})

    _res = wss.parse_response(response)

    assert set(_res.keys()) == {'sms', 'loc'}
