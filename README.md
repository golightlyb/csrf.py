csrf.py - simply generate & validate BREACH-resistant CSRF tokens
=================================================================

For Python >= 3.4

Features
--------

* Generate a unique token per-request (mitigate BREACH)
* Expire tokens after a certain time
* Unique token per-form
* Combines server secret + session secret + random salt + server time + per-form-ID
* Supports multiple servers, even with clock times that differ
* Uses cryptographically secure primitives

Requirements
-----------

* `/dev/urandom/` (e.g. any Unix-like system)
* Python >= 3.4 (3.3 should also work, but untested)


Example
-------

```python3
import binascii
import csrf
import datetime

# Generate this secret once per-application and keep it secure!
# (you'll want to share it across servers)
# OWASP recommends: at least 128 bits == 16 bytes == 32 hex chars
SERVER_SECRET = binascii.unhexlify(b"0123456789ABCDEF0123456789ABCDEF")

# Generate this secret per-user session and keep it secure!
# (it could be, for example, simply the generated session ID)
# for anonymous users, use a pre-defined value
# OWASP recommends: at least 128 bits == 16 bytes == 32 hex chars
SESSION_SECRET = binascii.unhexlify(b"ABCDEF0123456789ABCDEF0123456789")


# A unique ID for each form. This doesn't need to be secure.
# It ensures that even if a an individual form has the CSRF token leaked
# through an XSS vulnerability on the page, it cannot be reused against other
# forms. String or bytes is fine.
FORM_ID = 'example-login-form'


# How long is a CSRF token valid between? (start, end)
# We allow a start time of 90 minutes into the past in case two webservers
# have inaccurate/misconfigured times!
WINDOW = (datetime.timedelta(minutes=-90), datetime.timedelta(hours=36))


# use UTC time instead of local time if using multiple servers
utctime = datetime.datetime.now(datetime.timezone.utc)


# generate the token!
token = csrf.generate(SERVER_SECRET, SESSION_SECRET, FORM_ID, utctime)


# a few minutes later...
if not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime + datetime.timedelta(minutes=5), token):
    # handle somehow
    raise Exception("CSRF token invalid or expired")


# or
try:
    csrf.check(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime + datetime.timedelta(minutes=5), token):
except csrf.Error:
    # handle somehow
    throw

```


Installation
------------

    sudo pip3 install csrf --upgrade



Reference
---------

### csrf.generate

    csrf.generate(server_secret, session_secret, form_id, utctime): str

* `server_secret: bytes` - at least 128 bits from a cryptographically secure random number source.
* `session_secret: bytes` - at least 128 bits from a cryptographically secure random number source.
* `form_id: str|bytes` - a simple unique ID for a request end point e.g. "login-form".
* `utctime: datetime.datetime` - the current datetime (i.e. now) that the token is
being generated at, with a UTC timezone.
* returns a string, the meaning of which should be considered opaque, except for the
first two bytes which represents the version. For version "v1", the string length
is always exactly 117 characters. Also, the string only ever contains ASCII characters.


### csrf.valid

    csrf.valid(server_secret, session_secret, form_id, window, utctime, token): boolean

* `server_secret: bytes` - at least 128 bits from a cryptographically secure random number source.
* `session_secret: bytes` - at least 128 bits from a cryptographically secure random number source.
* `form_id: str|bytes` - a simple unique ID for a request end point e.g. "login-form".
* `window` - a 2-tuple `(start_time: datetime.timedelta, end_time: datetime.timedelta)` defining the window in
which a token is considered to be current and not expired. The `start_time` should be negative, e.g. a timedelta of -90 minutes,
to tolerate the fact that multiple servers may validate CSRF tokens with inaccurate clocks. The `end_time` should be some reasonable
limit for your application. For non-critical applications, perhaps a timedelta of 36 hours.
* `utctime: datetime.datetime` - the current datetime (i.e. now) that the token
is being checked at, with a UTC timezone. This may be later than the time the
token was generated at.
* `token: str` - a previously generated token from a call to `csrf.generate`
(even if the function was called by another process or another server, as long
as the server_secret is the same)
* returns `True` iff the token is considered valid and has not expired


### csrf.check

    csrf.check(server_secret, session_secret, form_id, window, utctime, token)
    throws csrf.Error

* `server_secret: bytes` - at least 128 bits from a cryptographically secure random number source.
* `session_secret: bytes` - at least 128 bits from a cryptographically secure random number source.
* `form_id: str|bytes` - a simple unique ID for a request end point e.g. "login-form".
* `window` - a 2-tuple `(start_time: datetime.timedelta, end_time: datetime.timedelta)` defining the window in
which a token is considered to be current and not expired. The `start_time` should be negative, e.g. a timedelta of -90 minutes,
to tolerate the fact that multiple servers may validate CSRF tokens with inaccurate clocks. The `end_time` should be some reasonable
limit for your application. For non-critical applications, perhaps a timedelta of 36 hours.
* `utctime: datetime.datetime` - the current datetime (i.e. now) that the token
is being checked at, with a UTC timezone. This may be later than the time the
token was generated at.
* `token: str` - a previously generated token from a call to `csrf.generate`
(even if the function was called by another process or another server, as long
as the server_secret is the same)
* No return value, but raises an exception of type `csrf.Error` if the
token is invalid or expired


### csrf.Error

    class csrf.Error(Exception)

* inherits from `Exception`


COPYING
-------

[GNU All-Permissive License](https://www.gnu.org/licenses/license-list.en.html#GNUAllPermissive)

```
Copyright (C) 2018 Ben Golightly <golightly.ben@googlemail.com>

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without any warranty.
```

