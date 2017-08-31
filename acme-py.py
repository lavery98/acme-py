#!/usr/bin/env python

import argparse
import subprocess
import sys
import re
import logging

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

# Default config
CA_API_URL = "https://acme-staging.api.letsencrypt.org"
API_DIR_NAME = "directory"

# Logger
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_crt(account_key, csr, log=LOGGER):
    # parse account key to get public key
    log.info("Parsing account key...")

    proc = subprocess.Popen(["openssl", "rsa", "-in", account_key, "-noout", "-text"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    pub_hex, pub_exp = re.search(r"modulus:\n\s+00:([a-f0-9\:\s]+?)\npublicExponent:\s([0-9]+)", out.decode("utf8"), re.MULTILINE|re.DOTALL).groups()

    log.debug("modulus: " + pub_hex)
    log.debug("public exponent: " + pub_exp)

    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    header = {
        "alg": "RS256",
        "jwk": {
            "e": "",
            "kty": "RSA",
            "n": "",
        },
    }

    log.debug("header: " + str(header))

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-key", required=True, help="Path to your account private key")
    parser.add_argument("--csr", required=True, help="Path to your certificate signing request")
    parser.add_argument("--acme-dir", default=None, help="Path to the ACME challenge directory")

    challenges = parser.add_mutually_exclusive_group(required=True)
    challenges.add_argument("--http", action="store_true", help="Use HTTP challenge")
    #challenges.add_argument("--tls", action="store_true", help="Use TLS challenge")
    challenges.add_argument("--dns", action="store_true", help="Use DNS challenge")

    logging_amount = parser.add_mutually_exclusive_group()
    logging_amount.add_argument("--debug", action="store_true", help="Enable debug log messages")
    logging_amount.add_argument("--quiet", action="store_true", help="Disable logging apart from errors")

    args = parser.parse_args(argv)

    if args.http and not args.acme_dir:
        parser.error("--acme-dir is required for the HTTP challenge")

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.quiet:
        LOGGER.setLevel(logging.ERROR)

    get_crt(args.account_key, args.csr)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
