import binascii
import csrf
import datetime
import timeit

# Generate this secret once per-application and keep it secure!
# (you'll want to share it across servers)
# OWASP recommends: at least 128 bits == 16 bytes == 32 hex chars
SERVER_SECRET = binascii.unhexlify(b"0123456789ABCDEF0123456789ABCDEF")

# Generate this secret per-user session and keep it secure!
# (it could be, for example, simply the generated session ID)
# for anonymous users, use a pre-defined value
# OWASP recommends: at least 128 bits == 16 bytes == 32 hex chars
SESSION_SECRET = binascii.unhexlify(b"ABCDEF0123456789ABCDEF0123456789")


# A unique ID for each form. This doesn't need to be secure, just unique(ish)
# This could literally be just a fully qualified class name / filename + lineno.
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



# benchmark
print("Benchmarking...")

for i in [1, 10, 100, 1000]:

    iterations=i
    taken = timeit.repeat(
        "csrf.generate(SERVER_SECRET, SESSION_SECRET, FORM_ID, utctime)",
        "from __main__ import SERVER_SECRET, SESSION_SECRET, FORM_ID, utctime, csrf",
        repeat=5, number=iterations)

    print("%d iterations, repeated 5 times" % iterations)
    _min, _max, _avg = min(taken), max(taken), (sum(taken) / len(taken))
    print("Minimum: %f seconds, %f millisecs/token" % (_min, 1000.0*_min/iterations))
    print("Maximum: %f seconds, %f millisecs/token" % (_max, 1000.0*_max/iterations))
    print("Average: %f seconds, %f millisecs/token" % (_avg, 1000.0*_avg/iterations))




token = csrf.generate(SERVER_SECRET, SESSION_SECRET, FORM_ID, utctime)
print("Example generated token: %s" % repr(token))
print("Generated at: %s" % repr(utctime))


# check time windows
# note - borderline times (e.g. on the exact minute) can go each way (seconds are chopped off the CSRF timestamp)
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime - datetime.timedelta(hours=2), token)
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime - datetime.timedelta(minutes=91), token)
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime - datetime.timedelta(minutes=90), token)
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime - datetime.timedelta(hours=1), token)
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime, token)
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime + datetime.timedelta(hours=1), token)
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime + datetime.timedelta(hours=35), token)
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime + datetime.timedelta(hours=35, minutes=59), token)
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime + datetime.timedelta(hours=36, minutes=1), token)
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime + datetime.timedelta(hours=37), token)


# check valid and invalid strings
then = datetime.datetime(2018, 6, 17, 10, 43, 8, 304433, tzinfo=datetime.timezone.utc)


# normal known-good (repeats to show pure function)
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')
assert csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# changed version
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v0|2018.06.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# changed form id
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, "a-different-form", WINDOW, then, 'v1|2018.06.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# changed date
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.44|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# changed salt
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|9e7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# changed hash
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|9e7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# invalid |s
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|9d7b9a77245c2e82|a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# invalid dates
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|abcd.06.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.13.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|20181.6.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# invalid non-hex salts
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|NOTHEX77245c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|NOTEHEX¹²45c2e82a5ec51ae4c9d82ad|059098a094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')

# invalid non-hex hashes
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|NOTHEXa094fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')
assert not csrf.valid(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, then, 'v1|2018.06.17.10.43|9d7b9a77245c2e82a5ec51ae4c9d82ad|NOTHEX¹²94fcc900361b5fe16046c7eb78b5523a3a826535a88a5be9718da623')



# check exception throwing version

csrf.check(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime, token)

try:
    csrf.check(SERVER_SECRET, SESSION_SECRET, FORM_ID, WINDOW, utctime, 'invalid_token')
    raise AssertionError
except:
    pass


