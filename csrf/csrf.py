
# csrf.py - simple, low-level, framework-agnostic, BREACH-resistant,
# time-windowed/expiring CSRF tokens (for Unix-like systems)

# Copyright © 2016 - 2018 Ben Golightly <golightly.ben@googlemail.com>

# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

import binascii
import datetime
import hashlib
import hmac
import os

# please don't edit these at runtime, they're good settings
RANDOM_BITS = 128
HASH_FUNCTION = hashlib.sha256
HASH_FUNCTION_BITS = 256
DATETIME_FORMAT = "%Y.%m.%d.%H.%M" # YYYY.MM.DD.HH.NN (16 chars)
DATETIME_FORMAT_LENGTH = 16
VERSION = "v1"

class Error(Exception):
    pass

def constant_time_compare(a, b):
    return hmac.compare_digest(a, b)

def gensalt(bits=RANDOM_BITS):
    # note - secrets module not available until Python 3.6
    # note - os.urandom becomes blocking in Python 3.6 so we open /dev/urandom directly

    with open("/dev/urandom", "rb") as fp:
        return fp.read(bits//8)


def generate(server_secret, session_secret, form_id, time):
    # impure function
    salt = gensalt()
    return _generate(server_secret, session_secret, form_id, time, salt)


def _generate(server_secret, session_secret, form_id, time, salt):
    # pure function
    time = time.strftime(DATETIME_FORMAT)
    if type(form_id) is str: form_id = form_id.encode('utf-8')
    hasher = HASH_FUNCTION
    msg = hasher(b'|'.join((salt, server_secret, session_secret, form_id, time.encode('ascii')))).digest()
    return "|".join((VERSION, time, binascii.hexlify(salt).decode('ascii'), binascii.hexlify(msg).decode('ascii')))


def check(server_secret, session_secret, form_id, window, server_time, token):
    """throws csrf.Error"""
    if not valid(server_secret, session_secret, form_id, window, server_time, token):
        raise csrf.Error


def valid(server_secret, session_secret, form_id, window, server_time, token):
    # pure function
    if len(token) != len(VERSION) + DATETIME_FORMAT_LENGTH + 3 + (2*RANDOM_BITS//8) + (2*HASH_FUNCTION_BITS//8):
        return False
    if token.count("|") != 3:
        return False

    try:
        version,time,salt,msg = token.split("|")

        if version != VERSION:
            return False

        if len(time) != DATETIME_FORMAT_LENGTH:
            return False

        if len(salt) != (2 * RANDOM_BITS) // 8:
            return False

        # len(msg) implied

        if time.count(".") != DATETIME_FORMAT.count("."):
            return False

        try:
            time = datetime.datetime.strptime(time, DATETIME_FORMAT).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return False

        if (server_time - time) <= window[0]:
            return False
        
        if (server_time - time) >= window[1]:
            return False

        salt = binascii.unhexlify(salt.encode('ascii'))
        msg = binascii.unhexlify(msg.encode('ascii'))
   
        server_token = _generate(server_secret, session_secret, form_id, time, salt)
        return constant_time_compare(token, server_token)

    except UnicodeEncodeError:
        return False
    except binascii.Error:
        return False




