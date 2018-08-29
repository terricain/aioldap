import asyncio
import asyncio.sslproto
import logging
import ssl
from copy import deepcopy
from typing import Union, AsyncGenerator, Dict, List, Optional, Any

from aioldap.exceptions import LDAPBindException, LDAPStartTlsException, LDAPChangeException, LDAPModifyException, \
    LDAPDeleteException, LDAPAddException, LDAPExtendedException

from async_timeout import timeout as async_timeout

# LDAP3 includes
from ldap3.operation.bind import bind_response_to_dict_fast
from ldap3.operation.extended import extended_operation, extended_response_to_dict_fast
from ldap3.operation.modify import modify_operation
from ldap3.operation.add import add_operation
from ldap3.operation.delete import delete_operation
from ldap3.operation.search import search_operation, search_result_entry_response_to_dict_fast
from ldap3.protocol.convert import build_controls_list
from ldap3.protocol.rfc2696 import paged_search_control
from ldap3.protocol.rfc4511 import BindRequest, Version, AuthenticationChoice, \
    Simple, LDAPMessage, MessageID, ProtocolOp, Sequence, UnbindRequest
from ldap3.strategy.base import BaseStrategy  # Consider moving this to utils
from ldap3.utils.asn1 import decode_message_fast, encode, ldap_result_to_dict_fast
from ldap3.utils.dn import safe_dn
from ldap3.utils.conv import to_unicode


logger = logging.getLogger('aioldap')


class Server(object):
    def __init__(self, host: str, port: int=None, use_ssl: bool=False, ssl_context: Optional[ssl.SSLContext]=None):
        self.host = host
        self.port = port
        if port is None:
            self.port = 636 if use_ssl else 389
        self.use_ssl = use_ssl
        self.ssl_ctx = ssl_context if ssl_context else ssl.create_default_context()


class LDAPResponse(object):
    def __init__(self, loop, onfinish=None):
        self._onfinish = onfinish
        self.started = asyncio.Event(loop=loop)
        self.finished = asyncio.Event(loop=loop)
        self.data = None
        self.additional = {}
        self.exception = None

    async def wait(self):
        await self.finished.wait()
        try:
            if callable(self._onfinish):
                self._onfinish()
        finally:
            if self.exception:
                raise self.exception


class LDAPClientProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop

        self.transport = None
        self._original_transport = None
        self._using_tls = False
        self._tls_event = asyncio.Event(loop=loop)
        self._is_bound = False

        self.unprocessed = b''
        self.messages = []

        self.responses = {}  # type:Dict[Union[str, int], LDAPResponse]

    def send(self, msg: Sequence, unbind=False) -> LDAPResponse:
        msg_id = int(msg['messageID'])

        if unbind:
            msg_id = 'unbind'

        response = LDAPResponse(onfinish=lambda: self.remove_msg_id_response(msg_id), loop=self.loop)
        self.responses[msg_id] = response

        payload = encode(msg)
        logger.debug('Sending request id {0}'.format(msg_id))
        self.transport.write(payload)
        logger.debug('Sent request id {0}'.format(msg_id))
        response.started.set()

        return response

    def remove_msg_id_response(self, msg_id: Union[str, int]):
        try:
            del self.responses[msg_id]
        except KeyError:
            pass

    def connection_made(self, transport):
        if self._original_transport is None:
            self.transport = transport
        else:
            self._using_tls = True
            self._tls_event.set()

    def eof_received(self):
        if self._using_tls:
            return False
        return super(LDAPClientProtocol, self).eof_received()

    def data_received(self, data):
        try:
            logger.debug('data_received: len {0}'.format(len(data)))
            self.unprocessed += data

            if len(data) > 0:
                length = BaseStrategy.compute_ldap_message_size(self.unprocessed)
                logger.debug('data_received: msg_length {0}'.format(length))

                while len(self.unprocessed) >= length != -1:
                    logger.debug('data_received: appended msg, len: {0}'.format(len(self.unprocessed[:length])))
                    self.messages.append(self.unprocessed[:length])
                    self.unprocessed = self.unprocessed[length:]

                    length = BaseStrategy.compute_ldap_message_size(self.unprocessed)
                    logger.debug('data_received: msg_length {0}'.format(length))

                while self.messages:
                    msg = self.messages.pop(0)

                    try:
                        msg_asn = decode_message_fast(msg)
                    except Exception as err:
                        logger.warning('data_received: Caught exception whilst decoding message')
                        continue
                    msg_id = msg_asn['messageID']
                    logger.debug('data_received: Decoded message, id {0}'.format(msg_id))
                    is_list = False
                    finish = False

                    msg_additional = {}

                    if msg_asn['protocolOp'] == 1:  # Bind request, only 1, finished after this
                        msg_data = bind_response_to_dict_fast(msg_asn['payload'])
                        logger.debug('data_received: id {0}, bind'.format(msg_id))
                        finish = True
                    elif msg_asn['protocolOp'] == 4:  # Search response, can be N,
                        is_list = True
                        msg_data = search_result_entry_response_to_dict_fast(msg_asn['payload'], None, None, False)
                        logger.debug('data_received: id {0}, search response'.format(msg_id))
                    elif msg_asn['protocolOp'] == 5:  # Search result done
                        finish = True
                        msg_data = None  # Clear msg_data

                        controls = msg_asn.get('controls')  # Get default doesnt work here
                        if not controls:
                            controls = []

                        controls = [BaseStrategy.decode_control_fast(control[3]) for control in controls]
                        msg_additional = {
                            'asn': msg_asn,
                            'controls': {item[0]: item[1] for item in controls}
                        }
                        logger.debug('data_received: id {0}, search done'.format(msg_id))

                    elif msg_asn['protocolOp'] == 7:  # Modify response, could merge with 9,11
                        msg_data = ldap_result_to_dict_fast(msg_asn['payload'])
                        logger.debug('data_received: id {0}, modify response'.format(msg_id))
                        finish = True
                    elif msg_asn['protocolOp'] == 9:  # Add response
                        msg_data = ldap_result_to_dict_fast(msg_asn['payload'])
                        logger.debug('data_received: id {0}, add response'.format(msg_id))
                        finish = True
                    elif msg_asn['protocolOp'] == 11:  # Del response
                        msg_data = ldap_result_to_dict_fast(msg_asn['payload'])
                        logger.debug('data_received: id {0}, del response'.format(msg_id))
                        finish = True
                    elif msg_asn['protocolOp'] == 24:
                        msg_data = extended_response_to_dict_fast(msg_asn['payload'])
                        logger.debug('data_received: id {0}, extended response'.format(msg_id))
                        finish = True
                    else:
                        raise NotImplementedError()

                    if msg_id not in self.responses:
                        # TODO raise some flags, this aint good
                        logger.warning('data_received: unknown msg id {0}'.format(msg_id))
                    else:
                        # If we have data to store
                        if msg_data:
                            # If data is a singular item
                            if not is_list:
                                self.responses[msg_id].data = msg_data

                            # If data is an element of a continiously expanding set
                            else:
                                try:
                                    self.responses[msg_id].data.append(msg_data)
                                except AttributeError:
                                    self.responses[msg_id].data = [msg_data]
                        if msg_additional:
                            self.responses[msg_id].additional = msg_additional

                        # Mark request as done
                        if finish:
                            self.responses[msg_id].finished.set()
                            logger.debug('data_received: id {0}, marked finished'.format(msg_id))

        except Exception as err:
            print()

    def connection_lost(self, exc):
        logger.debug('Connection lost')

        self._is_bound = False
        for key, response in self.responses.items():
            if key != 'unbind':
                response.exception = ConnectionResetError('LDAP Server dropped the connection')
            response.finished.set()

        if self._original_transport is not None:
            self._original_transport.close()
        super().connection_lost(exc)
        self.transport = None

    async def start_tls(self, ctx):
        ssl_proto = asyncio.sslproto.SSLProtocol(
            self.loop,
            self,
            ctx,
            None,
            server_side=False
        )

        self._original_transport = self.transport
        self._original_transport.set_protocol(ssl_proto)

        self.transport = ssl_proto._app_transport
        ssl_proto.connection_made(self._original_transport)

        # Wait for handshake
        await self._tls_event.wait()

    @property
    def is_bound(self) -> bool:
        return self._is_bound

    @is_bound.setter
    def is_bound(self, value: bool):
        self._is_bound = value

    @staticmethod
    def encapsulate_ldap_message(message_id, obj_name, obj, controls=None):
        ldap_message = LDAPMessage()
        ldap_message['messageID'] = MessageID(message_id)
        ldap_message['protocolOp'] = ProtocolOp().setComponentByName(obj_name, obj)

        msg_controls = build_controls_list(controls)
        if msg_controls:
            ldap_message['controls'] = msg_controls

        return ldap_message


class LDAPConnection(object):
    def __init__(self, server: Server, user: str=None, password: str=None, loop: asyncio.AbstractEventLoop=None):
        # TODO add option for wait timeout
        self._responses = {}
        self._msg_id = 0
        self._proto = None  # type: LDAPClientProtocol
        self._socket = None
        self.loop = loop
        if self.loop is None:
            self.loop = asyncio.get_event_loop()

        self.server = server
        self.bind_dn = user
        self.bind_pw = password

    def __del__(self):
        self.close()

    def close(self):
        if self._proto:
            try:
                if self._proto._original_transport:
                    self._proto._original_transport.close()
            except:  # noqa: E722
                pass
            try:
                if self._proto.transport:
                    self._proto.transport.close()
            except:  # noqa: E722
                pass
        if self._socket:
            try:
                self._socket.close()
            except:  # noqa: E722
                pass

        self._proto = None
        self._socket = None

    @property
    def _next_msg_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    async def bind(self, bind_dn: str=None, bind_pw: str=None):
        """
        Bind to LDAP server

        Creates a connection to the LDAP server if there isnt one

        :param bind_dn: Bind DN
        :param bind_pw: Bind password
        :param host: LDAP Host
        :param port: LDAP Port
        :raises LDAPBindException: If credentials are invalid
        """
        # Create proto if its not created already
        if self._proto is None or self._proto.transport.is_closing():
            self._socket, self._proto = await self.loop.create_connection(lambda: LDAPClientProtocol(self.loop), self.server.host, self.server.port)

        if bind_dn is None:
            bind_dn = self.bind_dn
        if bind_pw is None:
            bind_pw = self.bind_pw

        # If bind_dn is still None or '' then set up for anon bind
        if not bind_dn:
            bind_dn = ''
            bind_pw = ''

        # TODO check if already bound

        # Create bind packet
        bind_req = BindRequest()
        bind_req['version'] = Version(3)
        bind_req['name'] = bind_dn
        bind_req['authentication'] = AuthenticationChoice().setComponentByName('simple', Simple(bind_pw))

        # As were binding, msg ID should be 1
        self._msg_id = 0

        # Get next msg ID
        msg_id = self._next_msg_id

        # Generate ASN1 form of LDAP bind request
        ldap_msg = LDAPClientProtocol.encapsulate_ldap_message(msg_id, 'bindRequest', bind_req)

        # Send request to LDAP server, as multiple LDAP queries can run simultaneously, were given an object to wait on
        # which will return once done.
        resp = self._proto.send(ldap_msg)
        await resp.wait()  # TODO wrap with timeout

        # If the result is non-zero for a bind, we got some invalid creds yo
        if resp.data['result'] != 0:
            raise LDAPBindException("Invalid Credentials")

        # Ok we got success, this is used in other places as a guard if your not bound
        self._proto.is_bound = True

    async def search(self, search_base: str, search_filter: str, search_scope: str='SUBTREE', dereference_aliases: str='ALWAYS',
                     attributes: Optional[Union[str, List[str]]]=None, size_limit: int=0, time_limit: int=0, types_only: bool=False,
                     auto_escape: bool=True, auto_encode: bool=True, schema=None, validator=None, check_names: bool=False, cookie=None,
                     timeout: Optional[int]=None, get_operational_attributes: bool=False,
                     page_size=0) -> Dict[str, Any]:
        if not self.is_bound:
            raise LDAPBindException('Must be bound')

        search_base = safe_dn(search_base)

        if not attributes:
            attributes = ['1.1']
        elif attributes == '*':
            attributes = ['*']
        if isinstance(attributes, str):
            attributes = [attributes]

        if get_operational_attributes and isinstance(attributes, list):
            attributes.append('+')
        elif get_operational_attributes and isinstance(attributes, tuple):
            attributes += ('+',)

        controls = []
        if page_size:
            controls.append(paged_search_control(False, page_size, cookie))
        if not controls:
            controls = None

        search_req = search_operation(
            search_base, search_filter, search_scope, dereference_aliases, attributes, size_limit,
            time_limit, types_only, auto_escape=auto_escape, auto_encode=auto_encode,
            schema=schema, validator=validator, check_names=check_names
        )

        msg_id = self._next_msg_id

        ldap_msg = LDAPClientProtocol.encapsulate_ldap_message(msg_id, 'searchRequest', search_req, controls=controls)

        resp = self._proto.send(ldap_msg)

        if timeout:
            with async_timeout(timeout):
                await resp.wait()
        else:
            await resp.wait()

        try:
            cookie = resp.additional['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        except KeyError:
            cookie = None

        if not isinstance(resp.data, list):
            data = []
        else:
            data = resp.data

        return {
            'entries': data,
            'cookie': cookie
        }

    async def paged_search(self, search_base: str, search_filter: str, search_scope: str='SUBTREE', dereference_aliases: str='ALWAYS',
                           attributes: Optional[Union[str, List[str]]]=None, size_limit: int=0, time_limit: int=0, types_only: bool=False,
                           auto_escape: bool=True, auto_encode: bool=True, schema=None, validator=None, check_names: bool=False,
                           timeout: Optional[int]=None, get_operational_attributes: bool=False,
                           page_size=500) -> AsyncGenerator[dict, None]:
        if not self.is_bound:
            raise LDAPBindException('Must be bound')

        cookie = True  # True so loop runs once
        while cookie is not None and cookie != b'':
            response = await self.search(
                search_base, search_filter, search_scope=search_scope, dereference_aliases=dereference_aliases,
                attributes=attributes, size_limit=size_limit, time_limit=time_limit, types_only=types_only,
                auto_escape=auto_escape, auto_encode=auto_encode, schema=schema, validator=validator, check_names=check_names,
                timeout=timeout, get_operational_attributes=get_operational_attributes, page_size=page_size, cookie=None if cookie is True else cookie
            )

            while response['entries']:
                yield response['entries'].pop()

            cookie = response['cookie']

    async def unbind(self):
        if not self.is_bound:
            return  # Exit quickly if were already unbound

        # Create unbind request
        unbind_req = UnbindRequest()
        msg_id = self._next_msg_id

        # Generate final LDAP ASN message
        ldap_msg = LDAPClientProtocol.encapsulate_ldap_message(msg_id, 'unbindRequest', unbind_req)

        # Send and wait, when unbinding, the server terminates the connection, so when it does that, the
        # asyncio.Event for the unbind request is set(). As there is no response from the server, we get
        # no msg_id, therefore we tell send() its a special case.
        resp = self._proto.send(ldap_msg, unbind=True)
        await resp.wait()

        # If the underlying transport is closing, remove references to it.
        if self._proto.transport is None or self._proto.transport.is_closing():
            self._proto = None

    async def start_tls(self, ctx: Optional[ssl.SSLContext]=None):
        if self._proto is None or self._proto.transport.is_closing():
            self._socket, self._proto = await self.loop.create_connection(lambda: LDAPClientProtocol(self.loop), self.server.host, self.server.port)

        # Get SSL context from server obj, if it wasnt provided, it'll be the default one
        ctx = ctx if ctx else self.server.ssl_ctx

        resp = await self.extended('1.3.6.1.4.1.1466.20037')

        if resp.data['description'] != 'success':
            raise LDAPStartTlsException('Server doesnt want us to use TLS. {0}'.format(resp.data.get('message')))

        await self._proto.start_tls(ctx)

    async def extended(self, request_name: str, request_value=None, controls=None, no_encode=None):
        """
        Performs an extended operation
        """

        # Create unbind request
        extended_req = extended_operation(request_name, request_value, no_encode=no_encode)
        msg_id = self._next_msg_id

        # Generate final LDAP ASN message
        ldap_msg = LDAPClientProtocol.encapsulate_ldap_message(msg_id, 'extendedReq', extended_req, controls=controls)

        resp = self._proto.send(ldap_msg)
        await resp.wait()

        return resp

    async def modify(self, dn: str, changes: Dict[str, List[tuple]], controls=None, auto_encode: bool=True):
        """
        Modify attributes of entry

        - changes is a dictionary in the form {'attribute1': change), 'attribute2': [change, change, ...], ...}
        - change is (operation, [value1, value2, ...])
        - operation is 0 (MODIFY_ADD), 1 (MODIFY_DELETE), 2 (MODIFY_REPLACE), 3 (MODIFY_INCREMENT)
        """
        dn = safe_dn(dn)

        if not isinstance(changes, dict):
            raise LDAPChangeException('Changes is not a dict')

        if not changes:
            raise LDAPChangeException('Changes dict cannot be empty')

        modify_req = modify_operation(dn, changes, auto_encode, None, validator=None, check_names=False)
        msg_id = self._next_msg_id

        # Generate final LDAP ASN message
        ldap_msg = LDAPClientProtocol.encapsulate_ldap_message(msg_id, 'modifyRequest', modify_req, controls=controls)

        resp = self._proto.send(ldap_msg)
        await resp.wait()

        if resp.data['result'] != 0:
            raise LDAPModifyException(
                'Failed to modify dn {0}. Msg {1} {2} {3}'.format(dn,
                                                                  resp.data['result'],
                                                                  resp.data.get('message'),
                                                                  resp.data.get('description'))
            )

    async def delete(self, dn: str, controls=None, ignore_no_exist=False):
        """
        Delete the entry identified by the DN from the DIB.
        """
        dn = safe_dn(dn)

        del_req = delete_operation(dn)
        msg_id = self._next_msg_id

        # Generate final LDAP ASN message
        ldap_msg = LDAPClientProtocol.encapsulate_ldap_message(msg_id, 'delRequest', del_req, controls=controls)

        resp = self._proto.send(ldap_msg)
        await resp.wait()

        if resp.data['result'] != 0 and not (ignore_no_exist and resp.data['result'] == 32):
            raise LDAPDeleteException(
                'Failed to modify dn {0}. Msg {1} {2} {3}'.format(dn,
                                                                  resp.data['result'],
                                                                  resp.data.get('message'),
                                                                  resp.data.get('description'))
            )

    async def add(self, dn: str, object_class: Optional[Union[List[str], str]]=None,
                  attributes: Dict[str, Union[List[str], str]]=None, controls=None,
                  auto_encode: bool=True, timeout: Optional[int]=None):
        """
        Add dn to the DIT, object_class is None, a class name or a list
        of class names.

        Attributes is a dictionary in the form 'attr': 'val' or 'attr':
        ['val1', 'val2', ...] for multivalued attributes
        """
        _attributes = deepcopy(attributes)  # dict could change when adding objectClass values
        dn = safe_dn(dn)

        attr_object_class = []

        if object_class is not None:
            if isinstance(object_class, str):
                attr_object_class.append(object_class)
            else:
                attr_object_class.extend(object_class)

        # Look through attributes to see if object classes are specified there
        object_class_attr_name = ''
        if _attributes:
            for attr in _attributes:
                if attr.lower() == 'objectclass':
                    object_class_attr_name = attr

                    obj_class_val = _attributes[object_class_attr_name]
                    if isinstance(obj_class_val, str):
                        attr_object_class.append(obj_class_val)
                    else:
                        attr_object_class.extend(obj_class_val)
                    break
        else:
            _attributes = {}

        if not object_class_attr_name:
            object_class_attr_name = 'objectClass'

        # So now we have attr_object_class, which contains any passed in object classes and any we've found in attributes.
        # Converts objectclass to unicode in case of bytes value, also removes dupes
        attr_object_class = list(set([to_unicode(object_class) for object_class in attr_object_class]))
        _attributes[object_class_attr_name] = attr_object_class

        add_request = add_operation(dn, _attributes, auto_encode, None, validator=None, check_names=False)
        msg_id = self._next_msg_id

        # Generate final LDAP ASN message
        ldap_msg = LDAPClientProtocol.encapsulate_ldap_message(msg_id, 'addRequest', add_request, controls=controls)

        resp = self._proto.send(ldap_msg)
        if timeout:
            with async_timeout(timeout):
                await resp.wait()
        else:
            await resp.wait()

        if resp.data['result'] != 0:
            raise LDAPAddException(
                'Failed to modify dn {0}. Msg {1} {2} {3}'.format(dn,
                                                                  resp.data['result'],
                                                                  resp.data.get('message'),
                                                                  resp.data.get('description'))
            )

    async def whoami(self):
        resp = await self.extended('1.3.6.1.4.1.4203.1.11.3')

        if resp.data['result'] != 0:
            raise LDAPExtendedException(
                'Failed to perform extended query. Msg {0} {1} {2}'.format(resp.data['result'],
                                                                           resp.data.get('message'),
                                                                           resp.data.get('description'))
            )

        result = resp.data.get('responseValue')
        if isinstance(result, bytes):
            result = result.decode()

        return result

    @property
    def is_bound(self) -> bool:
        return self._proto is not None and self._proto.is_bound

# TODO get schema ldap3/core/server.py:L377-440
