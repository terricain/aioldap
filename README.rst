=======
aioldap
=======

.. image:: https://img.shields.io/pypi/v/aioldap.svg
        :target: https://pypi.python.org/pypi/aioldap

.. image:: https://img.shields.io/travis/terrycain/aioldap.svg
        :target: https://travis-ci.org/terrycain/aioldap

.. image:: https://codecov.io/gh/terrycain/aioldap/branch/master/graph/badge.svg
        :target: https://codecov.io/gh/terrycain/aioldap
        :alt: Code coverage

.. image:: https://readthedocs.org/projects/aioldap/badge/?version=latest
        :target: https://aioldap.readthedocs.io
        :alt: Documentation Status

.. image:: https://pyup.io/repos/github/terrycain/aioldap/shield.svg
     :target: https://pyup.io/repos/github/terrycain/aioldap/
     :alt: Updates

Not entirely ready, literally just started. Might shuffle things around a bit etc...

This was initially going to be a complete "from scratch" LDAP library for asyncio. Having used ldap3 for quite a
while I thought: wouldn't it be nice to have something ldap3-like but using normal asyncio. So I wrote this library which
is sort of based around ldap3, it uses ldap3's encoding and decoding functions and I just dealt with the actual packet
handoff. As as for why I made this, well because I can... and because I was bored.

I wouldn't quite call this production ready yet, and it could do with a bit of cleaning up but if anyone actually
finds this library useful, raise an issue with anything you have and I'll be happy to help out.

In its current form it only supports Python3.6 as I have an async generator in the code, am looking at making it
Python3.5 compatible too.

Documentation
-------------
Eventually will be on readthedocs


Example
-------

Simple example of using aioboto3 to put items into a dynamodb table

.. code-block:: python
    conn = aioldap.LDAPConnection()
    await conn.bind(
        bind_dn=ldap_params['user'],
        bind_pw=ldap_params['password'],
        host=ldap_params['host'],
        port=ldap_params['port']
    )

    dn = user_entry('modify', ldap_params['test_ou1'])
    await conn.add(
        dn=dn,
        object_class='inetOrgPerson',
        attributes={'description': 'some desc', 'cn': 'some_user', 'sn': 'some user', 'employeeType': ['type1', 'type2']}
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
    async for user in conn.search(dn, search_filter='(uid=*)', search_scope='BASE', attributes='*'):
        assert user['dn'] == dn


Credits
-------

All of the credit goes to @cannatag who literally had done all of the hard work for me.