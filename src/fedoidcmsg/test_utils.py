import copy
import hashlib
import json
import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus
from urllib.parse import urlparse

from cryptojwt import as_bytes
from oidcmsg.key_jar import build_keyjar, init_key_jar
from oidcmsg.key_jar import KeyJar

from fedoidcmsg import MetadataStatement
from fedoidcmsg import unfurl
from fedoidcmsg.bundle import FSJWKSBundle
from fedoidcmsg.bundle import JWKSBundle
from fedoidcmsg.bundle import keyjar_to_jwks_private
from fedoidcmsg.entity import make_federation_entity
from fedoidcmsg.file_system import FileSystem
from fedoidcmsg.operator import Operator
from fedoidcmsg.signing_service import InternalSigningService


# def make_fs_jwks_bundle(iss, fo_liss, sign_keyjar, keydefs, base_path=''):
#     """
#     Given a list of Federation identifiers creates a FSJWKBundle containing all
#     the signing keys.
#
#     :param iss: The issuer ID of the entity owning the JWKSBundle
#     :param fo_liss: List with federation identifiers as keys
#     :param sign_keyjar: Keys that the JWKSBundle owner can use to sign
#         an export version of the JWKS bundle.
#     :param keydefs: What type of keys that should be created for each
#         federation. The same for all of them.
#     :param base_path: Where the pem versions of the keys are stored as files
#     :return: A FSJWKSBundle instance.
#     """
#     jb = FSJWKSBundle(iss, sign_keyjar, 'fo_jwks',
#                       key_conv={'to': quote_plus, 'from': unquote_plus})
#
#     jb.clear()  # start from scratch
#
#     # Need to save the private parts on disc
#     jb.bundle.value_conv['to'] = keyjar_to_jwks_private
#
#     for entity in fo_liss:
#         _name = entity.replace('/', '_')
#         try:
#             _ = jb[entity]
#         except KeyError:
#             fname = os.path.join(base_path, 'keys', "{}.key".format(_name))
#             _keydef = copy.deepcopy(keydefs)
#             _keydef[0]['key'] = fname
#
#             _keyjar = build_keyjar(_keydef)[1]
#             jb[entity] = _keyjar
#
#     return jb
#
#
# def make_jwks_bundle(iss, fo_liss, sign_keyjar, keydefs):
#     """
#     Given a list of Federation identifiers creates a FSJWKBundle containing all
#     the signing keys.
#
#     :param iss: The issuer ID of the entity owning the JWKSBundle
#     :param fo_liss: List of federation identifiers
#     :param sign_keyjar: Keys that the JWKSBundel owner can use to sign
#         an export version of the JWKS bundle.
#     :param keydefs: What type of keys that should be created for each
#         federation. The same for all of them.
#     :return: A JWKSBundle instance.
#     """
#     jb = JWKSBundle(iss, sign_keyjar)
#
#     for entity in fo_liss:
#         _keydef = copy.deepcopy(keydefs)
#         _jwks, _keyjar, _kidd = build_keyjar(_keydef)
#         jb[entity] = _keyjar
#
#     return jb
#
#
# def make_ms(desc, leaf, operator, sup=None):
#     """
#     Construct a signed metadata statement
#
#     :param desc: A description of who wants who to signed what.
#         represented as a dictionary containing: 'request', 'requester',
#         'signer' and 'signer_add'.
#     :param leaf: if the requester is the entity operator/agent
#     :param operator: A dictionary containing Operator instance as values.
#     :param sup: Superiors.
#     :return: A dictionary with the FO ID as key and the signed metadata
#         statement as value.
#     """
#     req = MetadataStatement(**desc['request'])
#     _requester = operator[desc['requester']]
#     req['signing_keys'] = _requester.self_signer.public_keys()
#
#     _signer = operator[desc['signer']]
#     if sup is None:
#         sup = {}
#
#     _fo = _signer.iss
#
#     try:
#         _ms = sup['ms']
#     except KeyError:
#         pass
#     else:
#         req['metadata_statements'] = dict(_ms.items())
#         if len(_ms):
#             _fo = list(_ms.keys())[0]
#         else:
#             _fo = ''
#
#     try:
#         _ms_uri = sup['ms_uri']
#     except KeyError:
#         pass
#     else:
#         req['metadata_statement_uris'] = dict(_ms_uri.items())
#         if len(_ms_uri):
#             _fo = list(_ms_uri.keys())[0]
#         else:
#             _fo = ''
#
#     req.update(desc['signer_add'])
#
#     if leaf:
#         jwt_args = {'recv': _requester.iss}
#     else:
#         jwt_args = {}
#
#     ms = _signer.pack_metadata_statement(req, jwt_args=jwt_args)
#
#     return {_fo: ms}
#
#
# def make_signed_metadata_statement(ms_chain, operator, mds=None, base_uri=''):
#     """
#     Based on a set of metadata statement descriptions build a compounded
#     metadata statement.
#
#     :param ms_chain:
#     :param operator:
#     :param mds:
#     :param base_uri;
#     :return: xyz
#     """
#     _sup = {}
#     depth = len(ms_chain)
#     i = 1
#     leaf = False
#
#     for desc in ms_chain:
#         if i == depth:
#             leaf = True
#         if desc['uri'] is True:
#             _x = make_ms(desc, leaf, operator, _sup)
#             _sup = {'ms_uri': {}}
#             for k, v in _x.items():
#                 _sup['ms_uri'][k] = '{}/{}'.format(base_uri, mds.add(v))
#         else:
#             _sup = {'ms': make_ms(desc, leaf, operator, _sup)}
#         i += 1
#
#     return _sup
#
#
# def make_signed_metadata_statements(smsdef, operator, mds_dir='', base_uri=''):
#     """
#     Create a compounded metadata statement.
#
#     :param smsdef: A list of descriptions of how to sign metadata statements
#     :param operator: A dictionary with operator ID as keys and Operator
#         instances as values
#     :param mds_dir:
#     :param base_uri:
#     :return: A compounded metadata statement
#     """
#     res = []
#
#     if mds_dir:
#         mds = MetaDataStore(mds_dir)
#     else:
#         mds = None
#
#     for ms_chain in smsdef:
#         res.append(make_signed_metadata_statement(ms_chain, operator,
#                                                   mds, base_uri))
#
#     return res
#
#
# def init(keydefs, tool_iss, liss, lifetime):
#     # The FOs signing keys
#     sig_keys = build_keyjar(keydefs)[1]
#     key_bundle = make_fs_jwks_bundle(tool_iss, liss, sig_keys, keydefs, './')
#
#     # sig_keys = build_keyjar(keydefs)[1]
#
#     operator = {}
#
#     for entity, _keyjar in key_bundle.items():
#         _keyjar[''] = _keyjar[entity]
#         self_signer = InternalSigningService(entity, _keyjar)
#         operator[entity] = Operator(iss=entity, self_signer=self_signer,
#                                     lifetime=lifetime)
#
#     return {'operator': operator, 'key_bundle': key_bundle}
#
#
# def setup_ms(csms_def, ms_path, mds_dir, base_url, operators):
#     """
#
#     :param csms_def: Definition of which signed metadata statements to build
#     :param ms_path: Where to store the signed metadata statements and uris
#     :param mds_dir: Directory where singed metadata statements published using
#         ms_uri are kept
#     :param base_url: Common base URL to all metadata_statement_uris
#     :param operators: Dictionary with federation Operators
#     :return: A tuple of (Signer dictionary and FSJWKSBundle instance)
#     """
#
#     mds = MetaDataStore(mds_dir)
#     mds.clear()
#
#     for iss, sms_def in csms_def.items():
#         ms_dir = os.path.join(ms_path, quote_plus(iss))
#         for context, spec in sms_def.items():
#             _dir = os.path.join(ms_dir, context)
#             metadata_statements = FileSystem(
#                 _dir, key_conv={'to': quote_plus, 'from': unquote_plus})
#             metadata_statements.clear()
#             for fo, _desc in spec.items():
#                 res = make_signed_metadata_statement(_desc, operators, mds,
#                                                      base_url)
#                 try:
#                     metadata_statements.update(res['ms'])
#                 except KeyError:
#                     pass
#
#                 try:
#                     metadata_statements.update(res['ms_uri'])
#                 except KeyError:
#                     pass
#
#     signers = {}
#     for iss, sms_def in csms_def.items():
#         ms_dir = os.path.join(ms_path, quote_plus(iss))
#         signers[iss] = {
#             'self_signer': operators[iss].self_signer,
#             'ms_dir': ms_dir
#         }
#
#     return signers
#
#
# def setup(keydefs, tool_iss, liss, ms_path, csms_def=None, mds_dir='',
#           base_url='', lifetime=86400):
#     """
#
#     :param keydefs: Definition of which signing keys to create/load
#     :param tool_iss: An identifier for the JWKSBundle instance
#     :param liss: List of federation entity IDs
#     :param csms_def: Definition of which signed metadata statements to build
#     :param ms_path: Where to store the signed metadata statements and uris
#     :param mds_dir: Where to store the uri -> metadata statement mapping
#     :param base_url: Common base URL to all metadata_statement_uris
#     :param lifetime: Life time of signatures.
#     :return: A tuple of (Signer dictionary and FSJWKSBundle instance)
#     """
#
#     _init = init(keydefs, tool_iss, liss, lifetime)
#
#     signers = setup_ms(csms_def, ms_path, mds_dir, base_url, _init['operator'])
#
#     return signers, _init['key_bundle']
#
#
# class MetaDataStore(FileSystem):
#     @staticmethod
#     def hash(value):
#         _hash = hashlib.sha256()
#         _hash.update(as_bytes(value))
#         return _hash.hexdigest()
#
#     def add(self, value):
#         _key = self.hash(value)
#         self[_key] = value
#         return _key
#
#
# def unpack_using_metadata_store(url, mds):
#     p = urlparse(url)
#     _jws0 = mds[p.path.split('/')[-1]]
#     _md0 = unfurl(_jws0)
#
#     _mds = {}
#     if 'metadata_statement_uris' in _md0:
#         for _fo, _url in _md0['metadata_statement_uris'].items():
#             p = urlparse(_url)
#             _jws = mds[p.path.split('/')[-1]]
#             _md = unfurl(_jws)
#             if 'metadata_statement_uris' in _md:
#                 _mdss = {}
#                 for fo, _urlu in _md['metadata_statement_uris'].items():
#                     _mdss[fo] = unpack_using_metadata_store(_urlu, mds)
#                 _md['metadata_statement'] = _mdss
#                 del _md['metadata_statement_uris']
#             _mds[_fo] = json.dumps(_md)
#
#         _md0['metadata_statements'] = _mds
#         del _md0['metadata_statement_uris']
#
#     return _md0
#
#
# def own_sign_keys(sigkey_name, issuer, sig_def_keys):
#     try:
#         jwks = json.loads(open(sigkey_name, 'r').read())
#         sign_kj = KeyJar()
#         sign_kj.import_jwks(jwks, issuer)
#     except FileNotFoundError:
#         jwks, sign_kj, _ = build_keyjar(sig_def_keys)
#         sign_kj.issuer_keys[issuer] = sign_kj.issuer_keys['']
#         fp = open(sigkey_name, 'w')
#         fp.write(json.dumps(sign_kj.export_jwks(private=True, issuer=issuer)))
#         fp.close()
#
#     return sign_kj


def make_signing_sequence(entity_id, entity_dict):
    n = len(entity_id)
    i = n-1
    fo = entity_dict[entity_id[i]].iss
    sms = None
    i -= 1
    while i >= 0:
        metadata_statement = MetadataStatement()
        ent = entity_dict[entity_id[i]]
        ent.add_signing_keys(metadata_statement)
        # sends metadata to superior for signing
        sup = entity_dict[entity_id[i+1]]
        sup.add_sms_spec_to_request(metadata_statement)
        sms = sup.self_signer.sign(metadata_statement, ent.iss)
        # superior returns signed metadata statement who stores it
        ent.metadata_statements['discovery'][fo] = sms
        i -= 1
    return sms


def create_keyjars(owners, keydefs):
    res = {}
    for entity in owners:
        _id = quote_plus(entity)
        conf = {
                'private_path': 'private/{}.json'.format(_id),
                'key_defs': keydefs,
                'public_path': 'public/{}.json'.format(_id)
        }
        res[entity] = init_key_jar(**conf)
    return res


def create_federation_entities(entities, keydefs):
    res = {}
    for entity in entities:
        _id = quote_plus(entity)
        conf = {
            'self_signer': {
                'private_path': 'private/{}.json'.format(_id),
                'key_defs': keydefs,
                'public_path': 'public/{}.json'.format(_id)
            },
            'sms_dir': '',
            'context': 'discovery'
        }
        res[entity] = make_federation_entity(conf, entity)
    return res


def create_compounded_metadata_statement(entity_id, entity_dict, statement):
    n = len(entity_id)
    i = n-1
    fo = entity_dict[entity_id[i]].iss
    sms = None
    i -= 1
    while i >= 0:
        cms = statement[entity_id[i]]
        ent = entity_dict[entity_id[i]]
        ent.add_signing_keys(cms)
        sup = entity_dict[entity_id[i+1]]
        sup.add_sms_spec_to_request(cms)
        sms = sup.self_signer.sign(cms, ent.iss)
        # superior returns signed metadata statement who stores it
        ent.metadata_statements['discovery'][fo] = sms
        i -= 1

    return sms
