class VenafiError(Exception):
    pass


class VenafiConnectionError(VenafiError):
    pass


class ServerUnexptedBehavior(VenafiError):
    pass


class BadData(VenafiError):
    pass


class ClientBadData(BadData):
    pass
