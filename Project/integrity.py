import hmac
import hashlib


@staticmethod
def generate_digest(message, key, mac_algorithm):
    # Ensure 'key' is bytes
    key = key.encode() if isinstance(key, str) else key
    # Use a proper hashing algorithm
    hash_obj = hashlib.new(mac_algorithm, key + message)
    return hash_obj.digest()

@staticmethod
def verify_digest(digest, computed_digest):
    return hmac.compare_digest(digest, computed_digest)
