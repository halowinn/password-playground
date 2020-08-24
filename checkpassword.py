import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'http://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, try again with new API!')
    return res


def get_pass_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5char, tail = sha1pass[:5], sha1pass[5:]
    respond = request_api_data(first5char)
    return get_pass_leaks_count(respond, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. CHANGE IMMEDIATELY!')
        else:
            print(f'{password} is SAFE!')
    return 'ALL checked!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
