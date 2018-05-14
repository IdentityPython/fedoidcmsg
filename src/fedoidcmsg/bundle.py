#!/usr/bin/env python3
import json
import os
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from oidcmsg.jwt import JWT
from oidcmsg.key_jar import build_keyjar
from oidcmsg.key_jar import init_key_jar
from oidcmsg.key_jar import KeyJar

from fedoidcmsg.file_system import FileSystem
from fedoidcmsg.signing_service import KJ_SPECS


class JWKSBundle(object):
    """
    A class to keep a number of signing keys from different issuers.
    Behaves as a dictionary with issuer IDs as keys and
    :py:class:`oidcmsg.key_jar.KeyJar` instances as values.
    """

    def __init__(self, iss, sign_keys=None):
        """

        :param iss: Issuer identifier, will be used as the value of 'iss'
            when a signed JWT containg the bundle is constructed.
        :param sign_keys: Keys that this entity can use to sign JWTs.
        :type sign_keys: py:class:`oidcmsg.key_jar.KeyJar` instance
        """
        self.iss = iss
        self.sign_keys = sign_keys
        self.bundle = {}  # In memory database

    def __setitem__(self, key, value):
        """
        Add a set of keys, as a KeyJar or a JWKS under an issuer ID

        :param key: issuer ID
        :type: String
        :param value: Cryptographic keys that should be connected to to an
         issuer ID.
        :type value: KeyJar or a JWKS (JSON document)
        """
        if not isinstance(value, KeyJar):
            kj = KeyJar()
            if isinstance(value, dict):
                kj.import_jwks(value, issuer=key)
            else:
                kj.import_jwks_as_json(value, issuer=key)
            value = kj
        else:
            _val = value.copy()
            _iss = list(_val.owners())
            if _iss == ['']:
                _val.issuer_keys[key] = _val.issuer_keys['']
                del _val.issuer_keys['']
            elif len(_iss) == 1:
                if _iss[0] != key:
                    _val.issuer_keys[key] = _val.issuer_keys[_iss[0]]
                    del _val.issuer_keys[_iss[0]]
            else:
                raise ValueError('KeyJar contains to many issuers')

            value = _val

        self.bundle[key] = value

    def __getitem__(self, item):
        """
        Returns a KeyJar instance representing the keys belonging to an
        issuer
        
        :param item: Issuer ID
        :return: A KeyJar instance
        """
        kj = self.bundle[item]
        if item not in list(kj.issuer_keys.keys()):
            kj.issuer_keys[item] = kj.issuer_keys['']
            del kj.issuer_keys['']

        return kj

    def __delitem__(self, key):
        """
        Remove the KeyJar that belong to a specific issuer
        
        :param key: Issuer ID
        """
        del self.bundle[key]

    def create_signed_bundle(self, sign_alg='RS256', iss_list=None):
        """
        Create a signed JWT containing a dictionary with Issuer IDs as keys
        and JWKSs as values. If iss_list is empty then all available issuers are
        included.
        
        :param sign_alg: Which algorithm to use when signing the JWT
        :param iss_list: A list of issuer IDs who's keys should be included in 
            the signed bundle.
        :return: A signed JWT
        """
        data = self.dict(iss_list)
        _jwt = JWT(self.sign_keys, iss=self.iss, sign_alg=sign_alg)
        return _jwt.pack({'bundle':data})

    def loads(self, jstr):
        """
        Upload a bundle from an unsigned JSON document

        :param jstr: A bundle as a dictionary or a JSON document
        """
        if isinstance(jstr, dict):
            _info = jstr
        else:
            _info = json.loads(jstr)

        for iss, jwks in _info.items():
            kj = KeyJar()
            if isinstance(jwks, dict):
                kj.import_jwks(jwks, issuer=iss)
            else:
                kj.import_jwks_as_json(jwks, issuer=iss)
            self.bundle[iss] = kj
        return self

    def dumps(self, iss_list=None):
        """
        Dumps a bundle of keys into a string. If iss_list is empty then all
        available issuers are included
        
        :param iss_list: List of issuers who's keys should be dumped
        :return: A JSON document
        """
        return json.dumps(self.dict(iss_list))

    def __str__(self):
        return json.dumps(self.dict())

    def keys(self):
        """
        Return a list of all issuers kept in this bundle.
        
        :return: List of Issuer IDs
        """
        return self.bundle.keys()

    def items(self):
        return self.bundle.items()

    def dict(self, iss_list=None):
        """
        Return the bundle of keys as a dictionary with the issuer IDs as
        the keys and the key sets represented as JWKS instances.
        
        :param iss_list: List of Issuer IDs that should be part of the 
         output
        :rtype: Dictionary  
        """
        _int = {}
        for iss, kj in self.bundle.items():
            if iss_list is None or iss in iss_list:
                try:
                    _int[iss] = kj.export_jwks_as_json(issuer=iss)
                except KeyError:
                    _int[iss] = kj.export_jwks_as_json()
        return _int

    def upload_signed_bundle(self, sign_bundle, ver_keys):
        """
        Input is a signed JWT with a JSON document representing the key bundle 
        as body. This method verifies the signature and the updates the instance
        bundle with whatever was in the received package. Note, that as with 
        dictionary update if an Issuer ID already exists in the instance bundle
        that will be overwritten with the new information.
        
        :param sign_bundle: A signed JWT
        :param ver_keys: Keys that can be used to verify the JWT signature.
        """
        jwt = verify_signed_bundle(sign_bundle, ver_keys)
        self.loads(jwt['bundle'])

    def as_keyjar(self):
        """
        Convert a key bundle into a KeyJar instance.
        
        :return: An :py:class:`oidcmsg.key_jar.KeyJar` instance 
        """
        kj = KeyJar()
        for iss, k in self.bundle.items():
            try:
                kj.issuer_keys[iss] = k.issuer_keys[iss]
            except KeyError:
                kj.issuer_keys[iss] = k.issuer_keys['']
        return kj


def verify_signed_bundle(signed_bundle, ver_keys):
    """
    Verify the signature of a signed JWT.

    :param signed_bundle: A signed JWT where the body is a JWKS bundle
    :param ver_keys: Keys that can be used to verify signatures of the
        signed_bundle.
    :type ver_keys: A :py:class:`oidcmsg.key_jar.KeyJar` instance
    :return: The bundle or None
    """
    _jwt = JWT(ver_keys)
    return _jwt.unpack(signed_bundle)


def get_bundle(iss, ver_keys, bundle_file):
    """
    Read a signed JWKS bundle from disc, verify the signature and
    instantiate a JWKSBundle instance with the information from the file.
    
    :param iss:
    :param ver_keys:
    :param bundle_file:
    :return:
    """
    fp = open(bundle_file, 'r')
    signed_bundle = fp.read()
    fp.close()
    return JWKSBundle(iss, None).upload_signed_bundle(signed_bundle, ver_keys)


def get_signing_keys(eid, keydef, key_file):
    """
    If the *key_file* file exists then read the keys from there, otherwise
    create the keys and store them a file with the name *key_file*.

    :param eid: The ID of the entity that the keys belongs to
    :param keydef: What keys to create
    :param key_file: A file name
    :return: A :py:class:`oidcmsg.key_jar.KeyJar` instance
    """
    if os.path.isfile(key_file):
        kj = KeyJar()
        kj.import_jwks(json.loads(open(key_file, 'r').read()), eid)
    else:
        kj = build_keyjar(keydef)[1]
        # make it know under both names
        fp = open(key_file, 'w')
        fp.write(json.dumps(kj.export_jwks()))
        fp.close()
        kj.issuer_keys[eid] = kj.issuer_keys['']

    return kj


def jwks_to_keyjar(jwks, iss=''):
    """
    Convert a JWKS to a KeyJar instance.

    :param jwks: String representation of a JWKS
    :return: A :py:class:`oidcmsg.key_jar.KeyJar` instance
    """
    if not isinstance(jwks, dict):
        try:
            jwks = json.loads(jwks)
        except json.JSONDecodeError:
            raise ValueError('No proper JSON')

    kj = KeyJar()
    kj.import_jwks(jwks, issuer=iss)
    return kj


def k_to_j(keyjar, private=False):
    k = list(keyjar.owners())
    if len(k) == 1:
        return json.dumps(keyjar.export_jwks(issuer=k[0], private=private))
    elif len(k) == 2 and '' in k:
        k.remove('')
        return json.dumps(keyjar.export_jwks(issuer=k[0], private=private))
    else:
        raise ValueError('Too many issuers')


def keyjar_to_jwks(keyjar):
    """
    Convert a KeyJar instance to a JWKS (JSON document).
    
    :param keyjar: A :py:class:`oidcmsg.key_jar.KeyJar` instance
    """
    return k_to_j(keyjar)


def keyjar_to_jwks_private(keyjar):
    """
    Convert a KeyJar instance to a JWKS (JSON document).
    Including the private key.
    
    :param keyjar: A :py:class:`oidcmsg.key_jar.KeyJar` instance
    """
    return k_to_j(keyjar, private=True)


class FSJWKSBundle(JWKSBundle):
    """
    A JWKSBundle that keeps the key information in a 
    :py:class:`fedoidc.file_system.FileSystem` instance.
    """
    def __init__(self, iss, sign_keys=None, fdir='./', key_conv=None):
        """

        :param iss: Issuer ID for this entity
        :param sign_keys: Signing Keys used by this entity to sign JWTs
        :param fdir: A directory where JWKS can be stored
        :param key_conv: Specification of directory key to file name conversion.
            A set of keys are represented in the local cache as a KeyJar 
            instance and as a JWKS on disc.
        """
        JWKSBundle.__init__(self, iss, sign_keys=sign_keys)
        self.bundle = FileSystem(fdir, key_conv=key_conv,
                                 value_conv={'to': keyjar_to_jwks,
                                             'from': jwks_to_keyjar})

    def clear(self):
        self.bundle.clear()


def make_jwks_bundle(config, eid):
    _args = dict([(k,v) for k,v in config.items() if k in KJ_SPECS])
    _kj = init_key_jar(**_args)

    if 'dir' in config:
        jb = FSJWKSBundle(eid, _kj, config['dir'],
                          key_conv={'to': quote_plus, 'from': unquote_plus})
    else:
        jb = JWKSBundle(eid, _kj)
        if 'bundle' in config:
            jb.loads(open(config['bundle']).read())
        elif 'signed_bundle' in config:
            _kj = jwks_to_keyjar(open(config['verification_keys']).read())
            jb.upload_signed_bundle(open(config['signed_bundle']).read(),
                                    _kj)
    return jb