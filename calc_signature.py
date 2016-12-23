import hmac
from hashlib import sha256


def make_hmac_sha256(key, msg, hex=False):
    if hex:
        sig = hmac.new(key, msg.encode('utf-8'), sha256).hexdigest()
    else:
        sig = hmac.new(key, msg.encode('utf-8'), sha256).digest()
    return sig


if __name__ == "__main__":
    import sys
    string_to_sign = sys.argv[1]
    secret_key = sys.argv[2]
    signing_date = sys.argv[3]
    region = sys.argv[4]
    service = sys.argv[5]

    k_date = make_hmac_sha256(
        ('AWS4' + secret_key).encode('utf-8'), signing_date)
    k_region = make_hmac_sha256(k_date, region)
    k_service = make_hmac_sha256(k_region, service)
    k_signing = make_hmac_sha256(k_service, 'aws4_request')

    signature = make_hmac_sha256(k_signing, string_to_sign, True)

    print signature
