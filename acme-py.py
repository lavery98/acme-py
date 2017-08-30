#!/usr/bin/env python

import argparse
import sys

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None, help="Configuration file")
    parser.add_argument("--acme-dir", default=None, help="Path to the ACME challenge directory")

    challenges = parser.add_mutually_exclusive_group(required=True)
    challenges.add_argument("--http", action="store_true", help="Use HTTP challenge")
    #challenges.add_argument("--tls", action="store_true", help="Use TLS challenge")
    challenges.add_argument("--dns", action="store_true", help="Use DNS challenge")

    args = parser.parse_args(argv)

    if args.http and not args.acme_dir:
        parser.error("--acme-dir is required for the HTTP challenge")

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
