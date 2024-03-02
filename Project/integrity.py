import hmac
import hashlib

def generate_digest(message, key, mac_algorithm):
    """
    Generate a digest for the given message using the specified key and MAC algorithm.
  
    Args:
        message (bytes or str): The message to generate the digest for.
        key (bytes or str): The key used for generating the digest.
        mac_algorithm (str): The MAC algorithm to use for hashing.
  
    Returns:
        bytes: The generated digest.
    """
    # Ensure 'key' is bytes
    key = key.encode() if isinstance(key, str) else key
    # Use a proper hashing algorithm
    hash_obj = hashlib.new(mac_algorithm, key + message)
    return hash_obj.digest()

def verify_digest(digest, computed_digest):
    """
    Verify the integrity of a digest.
   
    Args:
        digest (bytes): The original digest to compare against.
        computed_digest (bytes): The computed digest to compare with the original.

    Returns:
        bool: True if the digests match, False otherwise.
    """
    return hmac.compare_digest(digest, computed_digest)
