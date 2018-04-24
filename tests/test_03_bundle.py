from fedoidcmsg.bundle import JWKSBundle

from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import public_keys_keyjar

ISS = 'https://example.com'
ISS2 = 'https://example.org'

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]
SIGN_KEYS = build_keyjar(KEYDEFS)[1]

KEYJAR = {}

for iss in ['https://www.swamid.se', 'https://www.sunet.se',
            'https://www.feide.no', 'https://www.uninett.no']:
    KEYJAR[iss] = build_keyjar(KEYDEFS)[1]


def test_create():
    bundle = JWKSBundle(ISS, SIGN_KEYS)
    assert bundle


def test_set_get():
    bundle = JWKSBundle(ISS, SIGN_KEYS)
    bundle['https://www.swamid.se'] = KEYJAR['https://www.swamid.se']

    # When imported the key in issuer_keys are changed from '' to the issuer ID
    _kj = KEYJAR['https://www.swamid.se'].copy()
    _kj.issuer_keys['https://www.swamid.se'] = _kj.issuer_keys['']
    del _kj.issuer_keys['']

    _sekj = bundle['https://www.swamid.se']
    assert _sekj == _kj


def test_set_del_get():
    bundle = JWKSBundle(ISS, SIGN_KEYS)
    bundle['https://www.swamid.se'] = KEYJAR['https://www.swamid.se']
    bundle['https://www.sunet.se'] = KEYJAR['https://www.sunet.se']
    bundle['https://www.feide.no'] = KEYJAR['https://www.feide.no']

    del bundle['https://www.sunet.se']

    assert set(bundle.keys()) == {'https://www.swamid.se',
                                  'https://www.feide.no'}


def test_set_jwks():
    bundle = JWKSBundle(ISS, SIGN_KEYS)
    bundle['https://www.sunet.se'] = KEYJAR['https://www.sunet.se'].export_jwks(
        private=True)

    _kj = KEYJAR['https://www.sunet.se'].copy()
    _kj.issuer_keys['https://www.sunet.se'] = _kj.issuer_keys['']
    del _kj.issuer_keys['']

    assert bundle['https://www.sunet.se'] == _kj


def test_dumps_loads():
    bundle = JWKSBundle(ISS, SIGN_KEYS)
    bundle['https://www.swamid.se'] = KEYJAR['https://www.swamid.se']
    bundle['https://www.sunet.se'] = KEYJAR['https://www.sunet.se']
    bundle['https://www.feide.no'] = KEYJAR['https://www.feide.no']

    _str = bundle.dumps()

    fp = open('bundle.json', 'w')
    fp.write(_str)
    fp.close()

    bundle2 = JWKSBundle(ISS, SIGN_KEYS)
    bundle2.loads(_str)

    # bundle contains private keys
    # bundle2 contains the public keys
    # This comparision could be made better

    for fo, kj in bundle.items():
        assert len(kj.get_issuer_keys(fo)) == len(
            bundle2[fo].get_issuer_keys(fo))


def test_sign_verify():
    bundle = JWKSBundle(ISS, SIGN_KEYS)
    bundle['https://www.swamid.se'] = KEYJAR['https://www.swamid.se']
    bundle['https://www.sunet.se'] = KEYJAR['https://www.sunet.se']
    bundle['https://www.feide.no'] = KEYJAR['https://www.feide.no']

    _jws = bundle.create_signed_bundle()

    bundle2 = JWKSBundle(ISS2)
    verify_keys = public_keys_keyjar(SIGN_KEYS.copy(), '', None, ISS)

    bundle2.upload_signed_bundle(_jws, verify_keys)

    assert set(bundle.keys()) == set(bundle2.keys())

    # Again can't compare straight off because bundle contains private keys
    # while bundle2 contains the public equivalents.
    for iss, kj in bundle.items():
        assert len(kj.get_issuer_keys(iss)) == len(
            bundle2[iss].get_issuer_keys(iss))
