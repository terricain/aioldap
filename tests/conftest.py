import asyncio
import gc
import os
import socket
import ssl
import time
import uuid

import ldap3
import pytest
import uvloop
from docker import APIClient

import aioldap


def pytest_generate_tests(metafunc):
    if 'loop_type' in metafunc.fixturenames:
        loop_type = ['asyncio', 'uvloop'] if uvloop else ['asyncio']
        metafunc.parametrize("loop_type", loop_type)

    if 'tls_enabled' in metafunc.fixturenames:
        metafunc.parametrize("tls_enabled", ['plain', 'tls'])


# Copied most from aiopg
@pytest.fixture(scope='session')
def unused_port():
    def f():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
    return f


@pytest.yield_fixture
def loop(request, loop_type):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(None)

    if uvloop and loop_type == 'uvloop':
        loop = uvloop.new_event_loop()
    else:
        loop = asyncio.new_event_loop()

    yield loop

    if not loop._closed:
        loop.call_soon(loop.stop)
        loop.run_forever()
        loop.close()
    gc.collect()
    asyncio.set_event_loop(None)


@pytest.mark.tryfirst
def pytest_pycollect_makeitem(collector, name, obj):
    if collector.funcnamefilter(name):
        if not callable(obj):
            return
        item = pytest.Function(name, parent=collector)
        if 'run_loop' in item.keywords:
            return list(collector._genfunctions(name, obj))


@pytest.mark.tryfirst
def pytest_pyfunc_call(pyfuncitem):
    """
    Run asyncio marked test functions in an event loop instead of a normal
    function call.
    """
    if 'run_loop' in pyfuncitem.keywords:
        funcargs = pyfuncitem.funcargs
        loop = funcargs['loop']
        testargs = {arg: funcargs[arg]
                    for arg in pyfuncitem._fixtureinfo.argnames}
        loop.run_until_complete(pyfuncitem.obj(**testargs))
        return True


def pytest_runtest_setup(item):
    if 'run_loop' in item.keywords and 'loop' not in item.fixturenames:
        # inject an event loop fixture for all async tests
        item.fixturenames.append('loop')


@pytest.fixture(scope='session')
def docker():
    return APIClient(version='auto')


@pytest.fixture(scope='session')
def session_id():
    """Unique session identifier, random string."""
    return str(uuid.uuid4())


@pytest.fixture(scope='session')
def ldap_server(unused_port, docker, request):
    docker.pull('minkwe/389ds:latest')

    ssl_directory = os.path.join(os.path.dirname(__file__), 'resources', 'ssl')
    ca_file = os.path.join(ssl_directory, 'ca.pem')

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.check_hostname = False
    ctx.load_verify_locations(cafile=ca_file)

    host = "127.0.0.1"
    host_port = unused_port()
    server_params = {
        'host': host, 'port': host_port, 'base_dn': 'dc=example,dc=com',
        'user': 'cn=Directory Manager', 'password': 'password',
        'test_ou1': 'ou=test1,dc=example,dc=com',
        'test_ou2': 'ou=test2,dc=example,dc=com',
        'test_ou3': 'ou=test3,dc=example,dc=com',
        'whoami': 'dn: cn=directory manager',
        'ctx': ctx
    }

    container_args = {
        'image': 'minkwe/389ds:latest',
        'name': 'aioldap-test-server-{0}'.format(session_id()),
        'ports': [389],
        'detach': True,
        'hostname': 'ldap.example.com',
        'environment': {
            'DIR_HOSTNAME': 'ldap.example.com',
            'DIR_MANAGER_PASSWORD': server_params['password'],
            'DIR_SUFFIX': server_params['base_dn']
        },
        'host_config': docker.create_host_config(
            port_bindings={389: (host, host_port)},
            binds={
               ssl_directory: {'bind': '/certs', 'ro': False},
            }
        ),
        'volumes': ['/certs']
    }

    container = docker.create_container(**container_args)

    try:
        docker.start(container=container['Id'])
        delay = 0.001

        # 389 takes at least 15 to come up, go down, come up with SSL
        time.sleep(15)

        for i in range(100):
            try:
                server = ldap3.Server(host=host, port=host_port, get_info=None)
                conn = ldap3.Connection(server, user='cn=Directory Manager', password=server_params['password'])
                conn.bind()

                whoami = conn.extend.standard.who_am_i()
                assert whoami == 'dn: cn=directory manager', "Unexpected bind user"

                # Create an OU to throw some stuff
                res = conn.add(server_params['test_ou1'], object_class='organizationalUnit')
                assert res, "Failed to create ou=test1"
                res = conn.add(server_params['test_ou2'], object_class='organizationalUnit')
                assert res, "Failed to create ou=test2"
                res = conn.add(server_params['test_ou3'], object_class='organizationalUnit')
                assert res, "Failed to create ou=test3"

                break
            except AssertionError as err:
                pytest.fail(str(err))
            except Exception as err:
                if delay > 40:
                    pytest.fail('container startup took too long')

                time.sleep(delay)
                delay *= 2
        else:
            pytest.fail("Cannot start LDAP server")

        container['host'] = host
        container['port'] = host_port
        container['ldap_params'] = server_params

        yield container
    finally:
        docker.kill(container=container['Id'])
        docker.remove_container(container['Id'])


@pytest.fixture
def ldap_params(ldap_server):
    return dict(**ldap_server['ldap_params'])


@pytest.fixture
def user_entry():
    def _f(test_name, ou_dn):
        return 'uid=test_{0}_{1},{2}'.format(test_name, str(uuid.uuid4()), ou_dn)
    return _f


@pytest.fixture
def ldap_connection(ldap_params):
    def _f() -> aioldap.LDAPConnection:
        server = aioldap.Server(
            host=ldap_params['host'],
            port=ldap_params['port'],
            ssl_context=ldap_params['ctx']
        )
        conn = aioldap.LDAPConnection(
            server=server,
            user=ldap_params['user'],
            password=ldap_params['password']
        )
        return conn

    return _f
