import os

import pytest
from oidcmsg.jwt import JWT
from oidcmsg.key_jar import init_key_jar
from requests import request

from fedoidcmsg.entity import FederationEntitySwamid
from fedoidcmsg.entity import make_federation_entity

_path = os.path.realpath(__file__)
root_dir, _fname = os.path.split(_path)

KEYDEFS = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]


class TestFederationEntity(object):
    @pytest.fixture(autouse=True)
    def create_federation_entity(self):
        config = {
            'self_signer': {
                'private_path': '{}/private_jwks'.format(root_dir),
                'key_defs': KEYDEFS,
                'public_path': '{}/public_jwks'.format(root_dir)
            },
            'mdss_endpoint': 'https://swamid.sunet.se/mdss',
            'mds_owner': 'https://swamid.sunet.se',
            'fo_bundle': {
                'private_path': '{}/fo_bundle_signing_keys'.format(root_dir),
                'key_defs': KEYDEFS,
                'public_path': '{}/pub_fo_bundle_signing_keys'.format(root_dir),
                'dir': '{}/public'.format(root_dir)
            }
        }
        self.fe = make_federation_entity(config, 'https://op.example.com',
                                         httpcli=request)

    def test_make_federation_entity(self):
        assert self.fe
        assert isinstance(self.fe, FederationEntitySwamid)
        assert self.fe.iss == 'https://op.example.com'

    def test_add_sms_spec_to_request(self, httpserver):
        msg = {
            "application_type": "web",
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "subject_type": "pairwise",
            "sector_identifier_uri":
                "https://other.example.net/file_of_redirect_uris.json",
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "contacts": ["ve7jtb@example.org", "mary@example.org"],
            "request_uris": [
                "https://client.example.org/rf.txt"
                "#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
        }

        payload = {
            "https://swamid.sunet.se/": "https://mdss.sunet.se/getsms/https%3A%2F%2Frp.example.com%2Fms.jws/https%3A%2F%2Fswamid.sunet.se%2F"
        }
        # Swamid keys
        kj = init_key_jar(
            private_path='private/https%3A%2F%2Fswamid.sunet.se',
            public_path='public/https%3A%2F%2Fswamid.sunet.se',
            iss=self.fe.mds_owner
        )

        alice = JWT(kj, iss=self.fe.mds_owner, lifetime=600)
        _jwt = alice.pack(payload=payload)

        httpserver.serve_content(_jwt)
        aug_msg = self.fe.add_sms_spec_to_request(req=msg, url=httpserver.url)
        assert 'signed_metadata_statement_uris' in aug_msg
