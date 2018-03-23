import shutil

from fedoidcmsg import MetadataStatement
from fedoidcmsg import test_utils

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


def test_signer():
    items = signer[OA['sunet']].items()
    assert set(list(items.keys())) == {'discovery', 'registration'}
    assert set(list(items['discovery'])) == {FO['swamid']}


def test_create_sms():
    s = signer[OA['sunet']]
    req = MetadataStatement(issuer='https://example.org/op')
    r = s.create_signed_metadata_statement(req, 'discovery')
    assert r
