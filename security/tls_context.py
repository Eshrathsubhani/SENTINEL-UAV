"""TLS contexts for mutually authenticated gateway connections."""

import ssl


def _context(protocol, *, ca_file, cert_file, key_file):
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca_file)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context


def client_context(*, ca_file, cert_file, key_file):
    context = _context(ssl.PROTOCOL_TLS_CLIENT, ca_file=ca_file,
                       cert_file=cert_file, key_file=key_file)
    context.hostname_checks_common_name = False
    return context


def server_context(*, ca_file, cert_file, key_file):
    return _context(ssl.PROTOCOL_TLS_SERVER, ca_file=ca_file,
                    cert_file=cert_file, key_file=key_file)
