

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
