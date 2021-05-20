class LDAPException(Exception):
    pass


class LDAPBindException(LDAPException):
    pass


class LDAPStartTlsException(LDAPException):
    pass


class LDAPChangeException(LDAPException):
    pass


class LDAPModifyException(LDAPException):
    pass


class LDAPDeleteException(LDAPException):
    pass


class LDAPAddException(LDAPException):
    pass


class LDAPExtendedException(LDAPException):
    pass


class OperationNotSupported(Exception):
    def __init__(self, code):
        message = f'This LDAP operation with code {code} is not supported'
        super().__init__(message)
