import hashlib
import hmac


def _sha1_hmac(secret, document):
    """
        Calculate the Base 64 encoding of the HMAC for the given document.
    """
    return hmac.new(secret, document, hashlib.sha1).digest().encode("base64")[:-1]


def fost_hmac_signature(secret, method, path, timestamp):
    """
        Calculate the signature for the given secret and arguments.
    """
    document = "%s %s\n%s" % (method, path, timestamp)
    return _sha1_hmac(secret, document)
