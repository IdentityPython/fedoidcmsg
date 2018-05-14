from urllib.parse import quote_plus

from oidcmsg.key_jar import init_key_jar

from fedoidcmsg import MetadataStatement
from fedoidcmsg.entity import make_federation_entity


def make_signing_sequence(entity_id, entity_dict, context='discovery',
                          lifetime=86400):
    """
    Signing sequence with nothing but keys no actual content

    :param entity_id: A list of entity IDs
    :param entity_dict: A dictionayr with entity IDs as keys and
        :py:class:`fedoidcmsg.entity.FederationEntity` instances as values.
    :param context:
    :param lifetime: The lifetime of the JWT signatures
    :return: A signed compounded metadata statement
    """
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
        sup.add_sms_spec_to_request(metadata_statement, context=context)
        sms = sup.self_signer.sign(metadata_statement, ent.iss,
                                   lifetime=lifetime)
        # superior returns signed metadata statement the subordinate stores it
        try:
            ent.metadata_statements[context][fo] = sms
        except KeyError:
            ent.metadata_statements[context] = {fo: sms}
        i -= 1
    return sms


def create_keyjars(owners, keydefs, root_dir='.'):
    res = {}
    for entity in owners:
        _id = quote_plus(entity)
        conf = {
                'private_path': '{}/private/{}'.format(root_dir, _id),
                'key_defs': keydefs,
                'public_path': '{}/public/{}'.format(root_dir, _id)
        }
        res[entity] = init_key_jar(**conf)
    return res


def create_federation_entities(entities, keydefs, root_dir='.',
                               context='discovery'):
    res = {}
    for entity in entities:
        _id = quote_plus(entity)
        conf = {
            'self_signer': {
                'private_path': '{}/private/{}'.format(root_dir, _id),
                'key_defs': keydefs,
                'public_path': '{}/public/{}'.format(root_dir, _id)
            },
            'sms_dir': '',
            'context': context
        }
        res[entity] = make_federation_entity(conf, entity)
    return res


def create_compounded_metadata_statement(entity_id, entity_dict, statement,
                                         context='discovery', lifetime=86400):
    """

    :param entity_id:
    :param entity_dict:
    :param statement:
    :param context:
    :param lifetime:
    :return:
    """
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
        sup.add_sms_spec_to_request(cms, context=context)
        sms = sup.self_signer.sign(cms, ent.iss, lifetime=lifetime)
        # superior returns signed metadata statement who stores it
        try:
            ent.metadata_statements[context][fo] = sms
        except KeyError:
            ent.metadata_statements[context] = {fo: sms}
        i -= 1

    return sms
