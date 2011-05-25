import hashlib
import hmac
import logging


def sha1_hmac(secret, document):
    """
        Calculate the Base 64 encoding of the HMAC for the given document.
    """
    return hmac.new(secret, document, hashlib.sha1).digest().encode("base64")[:-1]


def fost_hmac_url_signature(
    key, secret, host, path, query_string, expires):
    """
        Return a signature that corresponds to the signed URL.
    """
    if query_string:
        document = '%s%s?%s\n%s' % (host, path, query_string, expires)
    else:
        document = '%s%s\n%s' % (host, path, expires)
    signature = sha1_hmac(secret, document)
    return signature


def fost_hmac_request_signature(
    secret, method, path, timestamp, headers = {}, body = ''):
    """
        Calculate the signature for the given secret and arguments.
    """
    signed_headers, header_values = 'X-FOST-Headers', []
    for header, value in headers.items():
        signed_headers += ' ' + header
        header_values.append(value)
    return fost_hmac_request_signature_with_headers(
        secret, method, path, timestamp,
        [signed_headers] + header_values, body)


def fost_hmac_request_signature_with_headers(
    secret, method, path, timestamp, headers, body):
    """
        Calculate the signature for the given secret and other arguments.

        The headers must be the correct header value list in the proper order.
    """
    document = "%s %s\n%s\n%s\n%s" % (
        method, path,
        timestamp,
        '\n'.join(headers),
        body)
    signature = sha1_hmac(secret, document)
    logging.info("Calculated signature %s for document\n%s", signature, document)
    return document, signature
