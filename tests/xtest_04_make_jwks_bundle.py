import os

from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.bundle import verify_signed_bundle
from fedoidcmsg.test_utils import make_jwks_bundle

from oidcmsg.key_jar import KeyJar
from oidcmsg.key_jar import build_keyjar

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]


def test_create():
    jb = make_jwks_bundle('', ['fo0', 'fo1', 'fo2', 'fo3'], None,
                          KEYDEFS)

    assert len(jb.keys()) == 4


def test_dumps():
    jb = make_jwks_bundle('', ['fo0', 'fo1', 'fo2', 'fo3'], None,
                          KEYDEFS)

    bs = jb.dumps()
    assert len(bs) > 2000  # Can't know the exact length


def test_dump_load():
    jb = make_jwks_bundle('', ['fo0', 'fo1', 'fo2', 'fo3'], None,
                          KEYDEFS)

    bs = jb.dumps()

    receiver = JWKSBundle('')
    receiver.loads(bs)

    assert len(receiver.keys()) == 4
    assert set(receiver.keys()) == {'fo0', 'fo1', 'fo2', 'fo3'}


def test_create_verify():
    sign_keyjar = build_keyjar(KEYDEFS)[1]
    jb = make_jwks_bundle('https://example.com', ['fo0', 'fo1', 'fo2', 'fo3'],
                          sign_keyjar, KEYDEFS)

    _jws = jb.create_signed_bundle()
    _jwks = sign_keyjar.export_jwks()

    kj = KeyJar()
    kj.import_jwks(_jwks, 'https://example.com')
    bundle = verify_signed_bundle(_jws, kj)

    assert bundle
