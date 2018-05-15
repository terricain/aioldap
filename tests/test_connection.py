import uuid

import pytest

import aioldap


async def test_connect(ldap_params):
    """
    This tests that:
      connections actually work
      extended requests somewhat work
      and that the extended whoami request works
    """

    conn = aioldap.LDAPConnection()
    await conn.bind(
        bind_dn=ldap_params['user'],
        bind_pw=ldap_params['password'],
        host=ldap_params['host'],
        port=ldap_params['port']
    )

    result = await conn.whoami()
    assert result == 'dn:' + ldap_params['user'], "Not returning the correct binded user"


async def test_add(ldap_params):
    """
    This tests that:
      add works
      search base works
    """

    conn = aioldap.LDAPConnection()
    await conn.bind(
        bind_dn=ldap_params['user'],
        bind_pw=ldap_params['password'],
        host=ldap_params['host'],
        port=ldap_params['port']
    )

    dn = user_entry('add', ldap_params['test_ou1'])
    await conn.add(
        dn=dn,
        object_class='inetOrgPerson',
        attributes={
            'description': 'some desc',
            'cn': 'some_user',
            'sn': 'some user'
        }
    )

    # Now search for user
    async for user in conn.search(dn, search_filter='(uid=*)', search_scope='BASE', attributes='*'):
        assert user['dn'] == dn
        assert user['attributes'].get('cn')[0] == 'some_user'
        assert user['attributes'].get('sn')[0] == 'some user'
        assert user['attributes'].get('description')[0] == 'some desc'
        break
    else:
        pytest.fail('Did not find user')


def user_entry(test_name, ou_dn):
    return 'uid=test_{0}_{1},{2}'.format(test_name, str(uuid.uuid4()), ou_dn)

