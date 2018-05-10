import hashlib
import random

def new_secrets(pw):
    pw_hash, pw_salt = secret_salt(pw)
    cookie_token = make_token()
    cookie_hash, cookie_salt = secret_salt(cookie_token)
    user_secrets = {
        "pw_hash": pw_hash,
        "pw_salt": pw_salt,
        "cookie_hash": cookie_hash,
        "cookie_salt": cookie_salt,
    }
    return cookie_token, user_secrets

def make_token():
    return "".join(str(random.SystemRandom().randint(0,26)) for _ in range(16))

def secret_salt(s, salt=None):
    if not salt:
        salt = make_token()
    return hashlib.sha256(s + salt).hexdigest(), salt
