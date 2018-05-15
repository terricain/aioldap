import asyncio
import contextlib
import gc
import socket
import time
import uuid

import ldap3
import pytest
from docker import APIClient


# Copied most from aiopg
@pytest.fixture(scope='session')
def unused_port():
    def f():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]
    return f

@pytest.fixture
def loop(request):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(None)

    yield loop

    if not loop._closed:
        loop.call_soon(loop.stop)
        loop.run_forever()
        loop.close()
    gc.collect()
    asyncio.set_event_loop(None)


@pytest.mark.tryfirst
def pytest_pycollect_makeitem(collector, name, obj):
    if collector.funcnamefilter(name) and asyncio.iscoroutinefunction(obj):
        return list(collector._genfunctions(name, obj))


@contextlib.contextmanager
def _passthrough_loop_context(loop):
    if loop:
        # loop already exists, pass it straight through
        yield loop
    else:
        # this shadows loop_context's standard behavior
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)
        yield loop
        closed = loop.is_closed()
        if not closed:
            loop.call_soon(loop.stop)
            loop.run_forever()
            loop.close()
            gc.collect()
        asyncio.set_event_loop(None)


@pytest.mark.tryfirst
def pytest_pyfunc_call(pyfuncitem):
    """
    Run asyncio marked test functions in an event loop instead of a normal
    function call.
    """
    if asyncio.iscoroutinefunction(pyfuncitem.function):
        existing_loop = pyfuncitem.funcargs.get('loop', None)
        with _passthrough_loop_context(existing_loop) as _loop:
            testargs = {arg: pyfuncitem.funcargs[arg]
                        for arg in pyfuncitem._fixtureinfo.argnames}

            task = _loop.create_task(pyfuncitem.obj(**testargs))
            _loop.run_until_complete(task)

        return True


@pytest.fixture(scope='session')
def docker():
    return APIClient(version='auto')


@pytest.fixture(scope='session')
def session_id():
    """Unique session identifier, random string."""
    return str(uuid.uuid4())


@pytest.fixture(scope='session')
def ldap_server(unused_port, docker, request):
    docker.pull('osixia/openldap:1.2.1')

    container_args = dict(
        image='osixia/openldap:1.2.1',
        name='aioldap-test-server-{0}'.format(session_id()),
        ports=[389],
        detach=True,
    )

    # bound IPs do not work on OSX
    host = "127.0.0.1"
    host_port = unused_port()
    container_args['host_config'] = docker.create_host_config(port_bindings={389: (host, host_port)})
    container = docker.create_container(**container_args)

    try:
        docker.start(container=container['Id'])
        server_params = {
            'host': host, 'port': host_port, 'base_dn': 'dc=example,dc=org',
            'user': 'cn=admin,dc=example,dc=org', 'password': 'admin',
            'test_ou1': 'ou=test1,dc=example,dc=org',
            'test_ou2': 'ou=test2,dc=example,dc=org',
        }
        delay = 0.001

        for i in range(100):
            try:
                server = ldap3.Server(host=host, port=host_port, get_info=None)
                conn = ldap3.Connection(server, user='cn=admin,dc=example,dc=org', password='admin')
                conn.bind()

                assert conn.extend.standard.who_am_i() == 'dn:cn=admin,dc=example,dc=org', "Unexpected bind user"

                # Create an OU to throw some stuff
                res = conn.add('ou=test1,dc=example,dc=org', object_class='organizationalUnit')
                assert res, "Failed to create ou=test1,dc=example,dc=org"

                break
            except AssertionError as err:
                pytest.fail(str(err))
            except Exception as err:
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
def make_connection(loop, pg_params):

    conns = []

    @asyncio.coroutine
    def go(*, no_loop=False, **kwargs):
        nonlocal conn
        params = pg_params.copy()
        params.update(kwargs)
        useloop = None if no_loop else loop
        conn = yield from aiopg.connect(loop=useloop, **params)
        conn2 = yield from aiopg.connect(loop=useloop, **params)
        cur = yield from conn2.cursor()
        yield from cur.execute("DROP TABLE IF EXISTS foo")
        yield from conn2.close()
        conns.append(conn)
        return conn

    yield go

    for conn in conns:
        loop.run_until_complete(conn.close())
