import hmac
import hashlib

class Integrity:

    def generate_digest(message, mac_key, mac_algorithm):
        secret_key = bytes(mac_key)
        mac = hmac.new(secret_key, message, hashlib.new(mac_algorithm))
        return mac.digest()

    def verify_digest(digest, computed_digest):
        return hmac.compare_digest(digest, computed_digest)
