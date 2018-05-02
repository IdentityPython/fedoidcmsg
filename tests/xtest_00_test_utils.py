import os
import shutil

from cryptojwt.jws import factory
from oidcmsg.key_jar import KeyJar
from oidcmsg.key_jar import build_keyjar

from fedoidcmsg import test_utils
from fedoidcmsg.operator import Operator
from fedoidcmsg.signing_service import InternalSigningService
from fedoidcmsg.test_utils import MetaDataStore
from fedoidcmsg.test_utils import unpack_using_metadata_store

TEST_ISS = "https://test.example.com"
KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

SIGN_KEYJAR = build_keyjar(KEYDEFS)[1]

FO = {
    'swamid': 'https://swamid.sunet.se', 'feide': 'https://www.feide.no',
    'edugain': 'https://edugain.com', 'example': 'https://example.com'
}
OA = {'sunet': 'https://sunet.se', 'uninett': 'https://uninett.no'}
EO = {'foodle.rp': 'https://foodle.uninett.no'}

