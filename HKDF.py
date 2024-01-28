import hmac
import hashlib
from math import ceil


def calculate_digest(key,message):
    key = bytes(key, 'utf-8')
    message = bytes(message, 'utf-8')
    dig = hmac.new(key, message, hashlib.sha256)
    return dig.hexdigest()

hash = calculate_digest("hello", "the quick brown fox jumps over the lazy dog")

def HKDF(inputKeyMaterial, salt, info, length):
    if len(salt) == 0:
        salt = bytes([0]* len(hash))
    pseudorandomKey = hmac.new(salt, inputKeyMaterial, hashlib.sha256)
    t = b""
    outputKeyMaterial = b""
    for i in range(ceil((length/len(hash)))):
        t = hmac.new(pseudorandomKey, t + info + bytes([1+i]))
        outputKeyMaterial += t
    return outputKeyMaterial[:length]
key = HKDF()