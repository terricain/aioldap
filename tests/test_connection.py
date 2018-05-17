import asyncio

import pytest

import aioldap
import aioldap.exceptions


@pytest.mark.run_loop
async def test_connect(ldap_connection, ldap_params, tls_enabled, loop):
    """
    This tests that:
      connections actually work
      extended requests somewhat work
      and that the extended whoami request works
    """

    conn = ldap_connection()
    if tls_enabled == 'tls':
        await conn.start_tls()

    await conn.bind()

    await conn.unbind()


@pytest.mark.run_loop
async def test_whoami(ldap_connection, ldap_params, tls_enabled, loop):
    """
    This tests that:
      connections actually work
      extended requests somewhat work
      and that the extended whoami request works
    """

    conn = ldap_connection()
    if tls_enabled == 'tls':
        await conn.start_tls()

    await conn.bind()

    result = await conn.whoami()
    assert result == ldap_params['whoami'], "Not returning the correct binded user"


@pytest.mark.run_loop
async def test_anonymous(ldap_connection, ldap_params, loop):
    """
    This tests that:
      connections actually work
      extended requests somewhat work
      and that the extended whoami request works
    """

    conn = ldap_connection()

    await conn.bind(bind_dn='', bind_pw='')

    result = await conn.whoami()
    assert result == '', "Not returning the correct binded user"


@pytest.mark.run_loop
async def test_bad_bind_creds(ldap_connection, ldap_params, loop):
    """
    This tests that:
      connections actually work
      extended requests somewhat work
      and that the extended whoami request works
    """

    conn = ldap_connection()

    with pytest.raises(aioldap.exceptions.LDAPBindException):
        await conn.bind(bind_dn='cn=LOL', bind_pw='Invalid')


@pytest.mark.run_loop
async def test_add(ldap_connection, ldap_params, tls_enabled, loop, user_entry):
    """
    This tests that:
      add works
      search base works
    """

    conn = ldap_connection()
    if tls_enabled == 'tls':
        await conn.start_tls()
    await conn.bind()

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
    result = await conn.search(dn, search_filter='(uid=*)', search_scope='BASE', attributes='*')
    for user in result['entries']:
        assert user['dn'] == dn
        assert user['attributes'].get('cn')[0] == 'some_user'
        assert user['attributes'].get('sn')[0] == 'some user'
        assert user['attributes'].get('description')[0] == 'some desc'
        break
    else:
        pytest.fail('Did not find user')


@pytest.mark.run_loop
async def test_delete(ldap_connection, ldap_params, tls_enabled, loop, user_entry):
    """
    This tests that:
      delete works
      delete non-existant raises error
      delete error suppress
    """

    conn = ldap_connection()
    if tls_enabled == 'tls':
        await conn.start_tls()
    await conn.bind()

    dn = user_entry('delete', ldap_params['test_ou1'])
    await conn.add(
        dn=dn,
        object_class='inetOrgPerson',
        attributes={
            'description': 'some desc',
            'cn': 'some_user',
            'sn': 'some user'
        }
    )

    await conn.delete(dn)  # If it doesnt raise an exception, all is good

    try:
        await conn.delete(dn)
        pytest.fail('Deleting non-existant entry did not raise an exception')
    except aioldap.exceptions.LDAPDeleteException:
        pass

    # Should suppress exception
    await conn.delete(dn, ignore_no_exist=True)


@pytest.mark.run_loop
async def test_modify(ldap_connection, ldap_params, tls_enabled, loop, user_entry):
    """
    This tests that:
      modify_add works
      modify_replace works
    """

    conn = ldap_connection()
    if tls_enabled == 'tls':
        await conn.start_tls()
    await conn.bind()

    dn = user_entry('modify', ldap_params['test_ou1'])
    await conn.add(
        dn=dn,
        object_class='inetOrgPerson',
        attributes={
            'description': 'some desc',
            'cn': 'some_user',
            'sn': 'some user',
            'employeeType': ['type1', 'type2']
        }
    )

    await conn.modify(
        dn=dn,
        changes={
            'sn': [('MODIFY_REPLACE', 'some other user')],
            'employeeType': [
                ('MODIFY_ADD', 'type3'),
                ('MODIFY_DELETE', 'type1'),
            ]
        }
    )

    # Now search for user
    result = await conn.search(dn, search_filter='(uid=*)', search_scope='BASE', attributes='*')
    for user in result['entries']:
        assert user['dn'] == dn
        assert len(user['attributes'].get('sn')) == 1
        assert user['attributes'].get('sn')[0] == 'some other user'

        assert len(user['attributes'].get('employeeType')) == 2
        assert 'type3' in user['attributes'].get('employeeType')
        assert 'type2' in user['attributes'].get('employeeType')
        assert 'type1' not in user['attributes'].get('employeeType')
        break
    else:
        pytest.fail('Did not find user')


@pytest.mark.run_loop
async def test_paged_search(ldap_connection, ldap_params, tls_enabled, loop, user_entry):
    """
    This tests that:
      modify_add works
      modify_replace works
    """
    # import logging
    # logger = logging.getLogger('aioldap')
    # if not logger.handlers:
    #     logger.addHandler(logging.StreamHandler())
    # caplog.set_level(logging.DEBUG, logger='aioldap')

    conn = ldap_connection()
    if tls_enabled == 'tls':
        await conn.start_tls()
    await conn.bind()

    for _ in range(0, 50):
        await conn.add(
            dn=user_entry('paged_search', ldap_params['test_ou2']),
            object_class='inetOrgPerson',
            attributes={
                'description': 'some desc',
                'cn': 'some_user',
                'sn': 'some user'
            },
            timeout=10
        )

    result = await conn.search(ldap_params['test_ou2'], '(uid=*)', timeout=10)
    user_list = [user['dn'] for user in result['entries']]
    user_list2 = [user['dn'] async for user in conn.paged_search(ldap_params['test_ou2'], '(uid=*)', page_size=50, timeout=10)]

    assert set(user_list) == set(user_list2), "Search != Paged Search"


@pytest.mark.run_loop
async def test_mass_add(ldap_connection, ldap_params, loop, user_entry):
    """
    This tests that:
      modify_add works
      modify_replace works
    """

    conn = ldap_connection()
    await conn.bind()

    coro_list = []
    dn_list = set()
    for _ in range(0, 50):
        entry = user_entry('paged_search', ldap_params['test_ou3'])
        dn_list.add(entry)
        coro_list.append(conn.add(
            dn=entry,
            object_class='inetOrgPerson',
            attributes={
                'description': 'some desc',
                'cn': 'some_user',
                'sn': 'some user'
            }
        ))

    await asyncio.gather(*coro_list)

    result = await conn.search(ldap_params['test_ou3'], '(uid=*)')
    user_list = [user['dn'] for user in result['entries']]

    # Basically as uvloop test then adds more users we should just check we've found the ones we've added this time
    # Really we should make an OU for the test
    assert len(dn_list - set(user_list)) == 0
