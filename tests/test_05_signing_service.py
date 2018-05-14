import os
import time

from cryptojwt.jws import factory
from oidcmsg.key_jar import KeyJar
from oidcmsg.oidc import RegistrationRequest

from fedoidcmsg.signing_service import InternalSigningService
from fedoidcmsg.signing_service import WebSigningServiceClient
from fedoidcmsg.signing_service import make_internal_signing_service
from fedoidcmsg.signing_service import make_signing_service
from fedoidcmsg.test_utils import create_keyjars

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

_path = os.path.realpath(__file__)
root_dir, _fname = os.path.split(_path)

KJ = create_keyjars(['https://swamid.sunet.se', 'https://sunet.se',
                     'https://op.sunet.se'], KEYDEFS, root_dir=root_dir)


class Response(object):
    def __init__(self, status_code, text, headers):
        self.status_code = status_code
        self.text = text
        self.headers = headers


def test_make_internal_signing_service():
    config = {
        'private_path': '{}/private/https%3A%2F%2Fswamid.sunet.se'.format(
            root_dir),
        'public_path': '{}/public/https%3A%2F%2Fswamid.sunet.se'.format(
            root_dir),
    }
    signing_service = make_internal_signing_service(config,
                                                    'https://swamid.sunet.se')
    assert signing_service.iss == 'https://swamid.sunet.se'
    assert len(signing_service.keyjar.issuer_keys['']) == 1
    assert len(signing_service.keyjar.issuer_keys[''][0]) == 2


def test_make_web_signing_service():
    config = {
        'type': 'web',
        'public_path': '{}/public/https%3A%2F%2Fswamid.sunet.se'.format(
            root_dir),
        'iss': 'https://swamid.sunet.se',
        'url': 'https://swamid.sunet.se/mdss'
    }
    signing_service = make_signing_service(config, 'https://example.com')
    assert signing_service.eid == 'https://example.com'
    assert signing_service.iss == 'https://swamid.sunet.se'
    assert signing_service.url == 'https://swamid.sunet.se/mdss'
    assert len(signing_service.keyjar.issuer_keys[
                   'https://swamid.sunet.se']) == 1
    assert len(signing_service.keyjar.issuer_keys[
                   'https://swamid.sunet.se'][0]) == 2


def test_internal_signing_service():
    iss = InternalSigningService('https://swamid.sunet.se',
                                 KJ['https://swamid.sunet.se'])
    res = iss.sign(
        RegistrationRequest(redirect_uris=['https://example.com/rp/cb']),
        receiver='https://example.com/rp'
    )

    _jws = factory(res)
    assert _jws.jwt.headers['alg'] == 'RS256'
    msg = _jws.jwt.payload()
    assert msg['iss'] == 'https://swamid.sunet.se'
    assert msg['aud'] == ['https://example.com/rp']


def test_web_signing_service():
    _kj = KJ['https://swamid.sunet.se']
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

    response = Response(200, _sms,
                        {'Location': 'https://swamid.sunet.se/mdss/abcdefg'})

    _res = wss.parse_response(response)

    assert set(_res.keys()) == {'sms', 'loc'}


def test_key_rotation():
    config = {
        'private_path': '{}/private/https%3A%2F%2Fswamid.sunet.se'.format(
            root_dir),
        'public_path': '{}/public/https%3A%2F%2Fswamid.sunet.se'.format(
            root_dir),
    }
    signing_service = make_internal_signing_service(config,
                                                    'https://swamid.sunet.se')
    signing_service.keyconf = KEYDEFS
    signing_service.remove_after = 1
    signing_service.rotate_keys()
    assert len(signing_service.keyjar.get_issuer_keys('')) == 4
    time.sleep(1)
    signing_service.rotate_keys()
    assert len(signing_service.keyjar.get_issuer_keys('')) == 4
