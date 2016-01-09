class AsymException(Exception):
    pass


class MissingKeyException(AsymException):
    pass


class MissingAESException(MissingKeyException):
    message = "Missing AES key. Set or generate one"


class MissingRSAPublicException(MissingAESException):
    message = "Missing public RSA key. Set or generate one to use RSA encryption"


class MissingRSAPrivateException(MissingAESException):
    message = "Missing private RSA key. Set or generate one to use RSA decrypt"
