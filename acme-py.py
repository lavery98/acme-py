#!/usr/bin/env python

import argparse
import subprocess
import json
import sys
import base64
import binascii
import time
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

# Store ACME nonce value
ACME_NONCE = None

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

def ssl_rsa_get_public_key(private_key):
    LOGGER.debug("Calling OpenSSL to get public key from private key")
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

def ssl_rsa_signsha256(private_key, data):
    LOGGER.debug("Calling OpenSSL to sign some data with your private key")
    proc = subprocess.Popen(["openssl", "dgst", "-sha256", "-sign", private_key],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(data.encode('utf8'))
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))

    return out

def ssl_read_csr(csr):
    LOGGER.debug("Calling OpenSSL to read the provided certificate signing request")
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

    LOGGER.debug("Domains: " + str(domains))
    return domains

def ssl_get_csr(csr):
    LOGGER.debug("Calling OpenSSL to get the provided certificate signing request")
    proc = subprocess.Popen(["openssl", "req", "-in", csr, "-outform", "DER"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err))
    return out

def get_jwk(account_key):
    # parse account key to get public key
    LOGGER.info("Parsing account key...")
    # TODO: catch thrown errors
    e, n = ssl_rsa_get_public_key(account_key)

    LOGGER.debug("Creating JWK object")
    jwk = {
        "e": tobase64(e),
        "kty": "RSA",
        "n": tobase64(n)
    }
    LOGGER.debug("JWK object created " + str(jwk))

    LOGGER.debug("Creating JWK thumbprint")
    jwk_string = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = tobase64(hashlib.sha256(tobytes(jwk_string)).digest())
    LOGGER.debug("JWK thumbprint created")
    LOGGER.info('Parsed!')

    return jwk, thumbprint

def create_jws(private_key, jwk, payload = {}):
    header = {}
    header["alg"] = "RS256"
    header["jwk"] = jwk

    payloaddata = tobase64(tojson(payload))

    protected = {}
    protected["nonce"] = tostr(ACME_NONCE)
    protecteddata = tobase64(tojson(protected))

    signdata = "%s.%s" % (protecteddata, payloaddata)
    signature = ssl_rsa_signsha256(private_key, tobytes(signdata))
    signature = tobase64(signature)

    return tojson({"header":header, "payload": payloaddata, "protected": protecteddata, "signature": signature})

def httpquery(url = "", data = None, headers = {}, timeout = 60):
    LOGGER.debug("Sending a HTTP request to " + url)

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

    LOGGER.debug("Response: " + str(response))

    global ACME_NONCE
    ACME_NONCE = response["headers"]["replay-nonce"]
    return response

def get_directory():
    LOGGER.debug("Asking server for ACME directory")
    response = httpquery(CA_API_URL + "/" + API_DIR_NAME)
    if response["status"] != 200:
        raise Exception("ACME query for directory failed: %s" % (response["error"]))
    return response["jsonbody"]

def parse_csr(csr):
    LOGGER.info("Parsing CSR...")
    domains = ssl_read_csr(csr)
    LOGGER.info('Parsed!')
    return domains

def register_account(account_key, email, jwk, directory):
    LOGGER.info("Registering account...")

    # TODO: ask if user agrees to TOS

    payload = {
        "resource": API_NEW_REG,
        "agreement": directory[API_META]['terms-of-service'],
    }

    if email is not None:
        payload["contact"] = ["mailto:%s" % (email)]

    jws = create_jws(account_key, jwk, payload)
    response = httpquery(directory[API_NEW_REG], jws, {'content-type': 'application/json'})

    if response["status"] == 200:
        LOGGER.info("Registered!")
    elif response["status"] == 409:
        LOGGER.info("Already registered!")
    else:
        raise Exception("Failed to register: %s" % (response["error"]))

    return response

def get_challenges(account_key, jwk, thumbprint, directory, domains, challenge_type):
    LOGGER.info("Getting challenges for each domain")
    challenges = []

    for domain in domains:
        # get new challenge
        LOGGER.debug("Getting challenge for " + domain + "...")

        payload = {
            "resource": API_NEW_AUTHZ,
            "identifier": {"type": "dns", "value": domain},
        }

        jws = create_jws(account_key, jwk, payload)
        response = httpquery(directory[API_NEW_AUTHZ], jws, {'content-type': 'application/json'})
        if response["status"] != 201:
            raise Exception("Failed to get auth: %s" % (response["error"]))

        for c in response["jsonbody"]["challenges"]:
            if c["type"] == challenge_type:
                challenge = c
                break

        keyauthorization = "%s.%s" % (challenge["token"], thumbprint)
        challenges.append([domain, challenge, keyauthorization])

    return challenges

def verify_challenges(account_key, jwk, challenges):
    LOGGER.info("Verifying challenges...")

    for challenge in challenges:
        LOGGER.info("Verifying " + challenge[0] + "...")

        payload = {
            "resource": "challenge",
            "keyAuthorization": challenge[2],
        }

        jws = create_jws(account_key, jwk, payload)
        response = httpquery(challenge[1]["uri"], jws, {'content-type': 'application/json'})
        if response["status"] != 202:
            raise Exception("Failed to verify challenge: %s" % (response["error"]))

        timeouts = [10, 100, 1000]
        success = False
        for timeout in timeouts:
            response = httpquery(challenge[1]["uri"])
            if response["status"] != 202:
                raise Exception("Failed to verify challenge: %s" % (response["error"]))

            if response["jsonbody"]["status"] == "pending":
                time.sleep(timeout)
            elif response["jsonbody"]["status"] == "valid":
                LOGGER.info("%s verified!" % (challenge[0]))
                success = True
                break
            else:
                raise Exception("Failed to pass challenge for domain %s: %s" % (challenge[0], response["jsonbody"]))

        if not success:
            raise Exception("Failed to pass challenge for domain %s: Request still pending" % (challenge[0]))

def get_crt(account_key, jwk, directory, csr):
    LOGGER.info("Signing certificate...")

    csr_data = ssl_get_csr(csr)

    payload = {
        "resource": API_NEW_CERT,
        "csr": tobase64(csr_data),
    }

    jws = create_jws(account_key, jwk, payload)
    response = httpquery(directory[API_NEW_CERT], jws, {"Accept": "application/pkix-cert", 'content-type': 'application/json'})
    if response["status"] != 201:
        raise Exception("Failed to sign certificate: %s" %s (response["error"]))

def get_cert_http(account_key, csr, email, acme_dir):
    # get the jwk for this account key
    jwk, thumbprint = get_jwk(account_key)

    # get the directory
    directory = get_directory()

    # get domains
    domains = parse_csr(csr)

    # register an account on the server
    register_account(account_key, email, jwk, directory)

    # get the challenges for each domain
    challenges = get_challenges(account_key, jwk, thumbprint, directory, domains, "http-01")

    # TODO: create token file

    # verify the challenges
    verify_challenges(account_key, jwk, challenges)

    # get the certificate
    get_crt(account_key, jwk, csr)

def get_cert_dns(account_key, csr, email):
    # get the jwk for this account key
    jwk, thumbprint = get_jwk(account_key)

    # get the directory
    directory = get_directory()

    # get domains
    domains = parse_csr(csr)

    # register an account on the server
    register_account(account_key, email, jwk, directory)

    # get the challenges for each domain
    challenges = get_challenges(account_key, jwk, thumbprint, directory, domains, "dns-01")

    # print out the DNS entries to be created
    LOGGER.info("Add the following to your DNS zone file")

    for challenge in challenges:
        dnskey = tobase64(hashlib.sha256(tobytes(challenge[2])).digest())
        LOGGER.info("_acme-challenge." + challenge[0] + ". TXT " + dnskey)

    LOGGER.info("Press Enter to continue once you have added the DNS records")
    raw_input()

    # verify the challenges
    verify_challenges(account_key, jwk, challenges)

    LOGGER.info("All the DNS records can now be removed")

    # get the certificate
    get_crt(account_key, jwk, csr)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-key", required=True, help="Path to your account private key")
    parser.add_argument("--csr", default=None, help="Path to your certificate signing request")
    parser.add_argument("--email", default=None, help="Email to which notifications will be sent from the CA")
    parser.add_argument("--acme-dir", default=None, help="Path to the ACME challenge directory")

    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--http", action="store_true", help="Use HTTP challenge")
    #modes.add_argument("--tls", action="store_true", help="Use TLS challenge")
    modes.add_argument("--dns", action="store_true", help="Use DNS challenge")

    logging_amount = parser.add_mutually_exclusive_group()
    logging_amount.add_argument("--debug", action="store_true", help="Enable debug log messages")
    logging_amount.add_argument("--quiet", action="store_true", help="Disable logging apart from errors")

    args = parser.parse_args(argv)

    if args.http and not args.acme_dir:
        parser.error("--acme-dir is required for the HTTP challenge")

    if (args.http or args.dns) and not args.csr:
        parser.error("--csr is required for the HTTP and DNS challenges")

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.quiet:
        LOGGER.setLevel(logging.ERROR)

    if args.http:
        get_cert_http(args.account_key, args.csr, args.email, args.acme_dir)
    else:
        get_cert_dns(args.account_key, args.csr, args.email)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
