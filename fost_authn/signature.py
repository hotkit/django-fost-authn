import hashlib
import hmac
import logging


def sha1_hmac(secret, document):
    """
        Calculate the Base 64 encoding of the HMAC for the given document.
    """
    return hmac.new(secret, document, hashlib.sha1).digest().encode("base64")[:-1]


def fost_hmac_signature(secret, method, path, timestamp, headers = {}, body = ''):
    """
        Calculate the signature for the given secret and arguments.
    """
    signed_headers, header_values = 'X-FOST-Headers', []
    for header, value in headers.items():
        signed_headers += ' ' + header
        header_values.append(value)
    document = "%s %s\n%s\n%s\n%s" % (method, path, timestamp,
        '\n'.join([signed_headers] + header_values), body)
    signature = sha1_hmac(secret, document)
    logging.info("Calculated signature %s for headers %s and document\n%s",
        signature, headers, document)
    return document, signature, headers
