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
API_META = "meta"
API_NEW_REG = "new-reg"
API_NEW_AUTHZ = "new-authz"

# Logger
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def tobase64(x):
    return tostr(base64.urlsafe_b64encode(tobytes(x))).replace("=", "")

def tostr(x):
    if isinstance(x, str):
        return x
    if isinstance(x, bytes):
        r = ""
        if len(x) > 0 and isinstance(x[0], int):
            for ch in x: r += chr(ch)
        else:
            for ch in x: r += ch
        return r
    raise TypeError("tostr() accepts only <type 'str'> or <class 'bytes'> not %s" % (type(x)))

def tobytes(x):
    try:
        if isinstance(x, unicode):
            x = str(x)
    except NameError:
        pass

    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        r = []
        for ch in x:
            r.append(ord(ch))
        return bytes(r)
    raise TypeError("tobytes() accepts only <type 'str'> or <class 'bytes'> not %s" % (type(x)))

def tojson(x):
    return tobytes(json.dumps(x))

def ssl_rsa_get_public_key(private_key, log=LOGGER):
    log.debug("Calling OpenSSL to get public key from private key")
    proc = subprocess.Popen(["openssl", "rsa", "-in", private_key, "-noout", "-text", "-modulus"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    for line in tostr(out).split("\n"):
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

def ssl_read_csr(csr, log=LOGGER):
    log.debug("Calling OpenSSL to read the provided certificate signing request")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-noout", "-text"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    domains = set([])
    subject_alt_line = False

    for line in tostr(out).split("\n"):
        if line.strip()[0:12] == "Subject: CN=":
            domains.add(line.strip()[12:])
        if subject_alt_line:
            subject_alt_line = False

            for san in line.strip().split(", "):
                if san.startswith("DNS:"):
                    domains.add(san[4:])
        if line.strip() == "X509v3 Subject Alternative Name:":
            subject_alt_line = True

    log.debug("Domains: " + str(domains))
    return domains

def create_jws(private_key, jwk, nonce, payload = {}):
    header = {}
    header["alg"] = "RS256"
    header["jwk"] = jwk

    payloaddata = tobase64(tojson(payload))

    protected = {}
    protected["nonce"] = tostr(nonce)
    protecteddata = tobase64(tojson(protected))

    signdata = "%s.%s" % (protecteddata, payloaddata)
    signature = ssl_rsa_signsha256(private_key, tobytes(signdata))
    signature = tobase64(signature)

    return tojson({"header":header, "payload": payloaddata, "protected": protecteddata, "signature": signature})

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

def get_crt(account_key, csr, email, log=LOGGER):
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
    thumbprint = tobase64(hashlib.sha256(tobytes(jwk_string)).digest())
    log.debug("JWK thumbprint created")
    log.info('Parsed!')

    # get the ACME urls from the server
    acmenonce = None

    def _httpquery(url = "", data = None, headers = {}, timeout = 60):
        response = httpquery(url = url, data = data, headers = headers, timeout = timeout)
        if response["status"] != -1:
            acmenonce = response["headers"]["replay-nonce"]
        return response, acmenonce

    log.debug("Asking server for ACME urls")
    response, acmenonce = _httpquery(CA_API_URL + "/" + API_DIR_NAME)
    if response["status"] != 200:
        raise Exception("ACME query for directory failed: %s" % response["error"])
    directory = response["jsonbody"]

    # TODO: ask if user agrees to given TOS

    # find domains
    log.info("Parsing CSR...")
    domains = ssl_read_csr(csr)
    log.info('Parsed!')

    # register an account on the server
    log.info("Registering account...")

    payload = {
        "resource": API_NEW_REG,
        "agreement": directory[API_META]['terms-of-service'],
    }

    if email is not None:
        payload["contact"] = ["mailto:%s" % (email)]

    response, acmenonce = _httpquery(directory[API_NEW_REG], create_jws(account_key, jwk, acmenonce, payload), {'content-type': 'application/json'})
    if response["status"] == 200:
        log.info("Registered!")
    elif response["status"] == 409:
        log.info("Already registered!")
    else:
        raise Exception("Failed to register: %s" % response["error"])

    # get challenge for each domain
    challenges = []
    log.info("Getting challenges for each domain")

    for domain in domains:
        # get new challenge
        log.debug("Getting challenge for " + domain)

        payload = {
            "resource": API_NEW_AUTHZ,
            "identifier": {"type": "dns", "value": domain},
        }

        response, acmenonce = _httpquery(directory[API_NEW_AUTHZ], create_jws(account_key, jwk, acmenonce, payload), {'content-type': 'application/json'})
        if response["status"] != 201:
            raise Exception("Failed to get auth: %s" % response["error"])

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-key", required=True, help="Path to your account private key")
    parser.add_argument("--csr", required=True, help="Path to your certificate signing request")
    parser.add_argument("--email", default=None, help="Email to which notifications will be sent from the CA")
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

    get_crt(args.account_key, args.csr, args.email)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
