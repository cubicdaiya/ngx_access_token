# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
#
# signature generator
#

import sys
import hmac
from hashlib import sha1
import base64
import binascii
import argparse

def build_parser():
    parser = argparse.ArgumentParser(description='Signature Generator', add_help=False)
    parser.add_argument('-p', '--public', action='store',      type=str,      help='public-key')
    parser.add_argument('-s', '--secret', action='store',      type=str,      help='secret-key', required=True)
    parser.add_argument('-m', '--method', action='store',      type=str,      help='http-method')
    parser.add_argument('-u', '--uri',    action='store',      type=str,      help='uri')
    parser.add_argument('-t', '--time',   action='store',      type=str,      help='epoch')
    parser.add_argument('-r', '--raw',    action='store',      type=str,      help='http-method + uri + epoch + public-key')
    parser.add_argument('--help',         action='store_true', default=False, help='show this help message and exit')
    return parser

def build_raw(args):
    if args.public is None or \
       args.method is None or \
       args.uri    is None or \
       args.time   is None:
        raise Exception
    return args.method + args.uri +  args.time + args.public

if __name__ == '__main__':
    parser = build_parser()
    args = parser.parse_args()

    if args.help == True:
        parser.print_help()
        sys.exit(0)

    if args.raw is not None:
        raw = args.raw
    else:
        try:
            raw = build_raw(args)
        except:
            parser.print_help()
            sys.exit(0)

    hashed = hmac.new(args.secret, raw, sha1)
    print binascii.b2a_base64(hashed.digest())[:-1]
