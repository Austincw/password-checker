import requests
import hashlib
import sys


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Errors fetching: {res.status_code}, check the api and try again."
        )
    return res


def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_pwd_char, tail = sha1pwd[:5], sha1pwd[5:]
    res = request_api_data(first5_pwd_char)
    return get_password_leak_count(res, tail)


def main(args):
    for pwd in args:
        count = pwned_api_check(pwd)
        if count:
            print(f"{pwd} was found {count} times.  You should change your password")
        else:
            print(f"{pwd} was not found.  Good choice!")
    return "done"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
