#!/usr/bin/env python

import argparse
import subprocess
import json
import sys
import base64
import binascii
import hashlib
import logging

try:
    from urllib.request import urlopen
    from urllib.request import Request
    from urllib.error   import HTTPError
except ImportError:
    from urllib2 import urlopen
    from urllib2 import Request
    from urllib2 import HTTPError

# Default config
CA_API_URL = "https://acme-staging.api.letsencrypt.org"
API_DIR_NAME = "directory"

# Logger
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def tobase64(x):
    return base64.urlsafe_b64encode(x).decode('utf8').replace("=", "")

def ssl_rsa_get_public_key(private_key, log=LOGGER):
    log.debug("Calling OpenSSL to get public key from private key")
    proc = subprocess.Popen(["openssl", "rsa", "-in", private_key, "-noout", "-text", "-modulus"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    for line in out.split("\n"):
        if line[0:14] == "publicExponent":
            exponent = line.split(')')[0].split('(')[1][2:]
        if line[0:8] == "Modulus=":
            modulus = line[8:]

    if (len(exponent) % 2):
        exponent = "0" + exponent

    exponent = binascii.unhexlify(exponent.encode("utf-8"))
    modulus = binascii.unhexlify(modulus.encode("utf-8"))
    return (exponent, modulus)

def ssl_rsa_signsha256(private_key, data, log=LOGGER):
    log.debug("Calling OpenSSL to sign some data with your private key")
    proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", private_key],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(data.encode('utf8'))
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    return out

def create_jws(private_key, jwk, nonce, payload = {}):
    header = {}
    header["alg"] = "RS256"
    header["jwk"] = jwk

    payloaddata = tobase64(json.dumps(payload).encode('utf8'))

    protected = {}
    protected["nonce"] = nonce
    protecteddata = tobase64(json.dumps(protected).encode('utf8'))

    signdata = "%s.%s" % (protecteddata, payloaddata)
    signature = ssl_rsa_signsha256(private_key, signdata)
    signature = tobase64(signature)

    return json.dumps({"header":header, "payload": payloaddata, "protected": protecteddata, "signature": signature})

def httpquery(url = "", data = None, headers = {}, timeout = 60, log = LOGGER):
    log.debug("Sending a HTTP request to " + url)

    try:
        req = Request(url, data = data, headers = headers)
        r = urlopen(req, timeout = timeout)
    except HTTPError as e:
        r = e
    except Exception as e:
        return { "status": -1, "error": str(e) }

    headers = {}

    for h, v in r.info().items():
        headers[h.lower()] = v

    response = {
        "status": r.code,
        "error": "http error %d %s" % (r.code, r.msg),
        "headers": headers,
        "body": r.read()
    }

    if "content-type" in response["headers"]:
        if response["headers"]["content-type"].lower() == "application/json":
            response["jsonbody"] = json.loads(response["body"])
        if response["headers"]["content-type"].lower() == "application/problem+json":
            response["jsonbody"] = json.loads(response["body"])

    log.debug("Response: " + str(response))

    return response

def get_crt(account_key, csr, log=LOGGER):
    # parse account key to get public key
    log.info("Parsing account key...")
    # TODO: catch thrown errors
    e, n = ssl_rsa_get_public_key(account_key)

    log.debug("Creating JWK object")
    jwk = {
        "e": tobase64(e),
        "kty": "RSA",
        "n": tobase64(n)
    }
    log.debug("JWK object created " + str(jwk))

    log.debug("Creating JWK thumbprint")
    jwk_string = '{"e":"%s","kty","RSA","n","%s"}' % (tobase64(e), tobase64(n))
    thumbprint = tobase64(hashlib.sha256(jwk_string.encode('utf8')).digest())
    log.debug("JWK thumbprint created")
    log.info('Parsed!')

    # get the ACME urls from the server
    acmenonce = None

    def _httpquery(url = "", data = None, headers = {}, timeout = 60):
        response = httpquery(url = url, data = data, headers = headers, timeout = timeout)
        if response["status"] != -1:
            acmenonce = response["headers"]["replay-nonce"]
        return response

    log.debug("Asking server for ACME urls")
    response = _httpquery(CA_API_URL + "/" + API_DIR_NAME)

    # find domains
    log.info("Parsing CSR...")

    # TODO: parse the CSR

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
