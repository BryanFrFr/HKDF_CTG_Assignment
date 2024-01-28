import hashlib
import hmac

def hkdf_extract(salt, input_key_material):
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()
# Creates pseudorandom key. pseudorandom key acts as a "randomness extractor"

def hkdf_expand(prk, info, length):
    okm = b""
    t = b""
    info = info + bytes([1])

    while len(okm) < length:
        t = hmac.new(prk, t + info, hashlib.sha256).digest()
        okm += t

    return okm[:length]
# Takes pseudorandom key and information to generate output of specified length
# Repeatedly calls on hmac and prepends output of previouse hash block (vairable t in this case) to info

def hkdf(salt, input_key_material, info, length):
    prk = hkdf_extract(salt, input_key_material)
    return hkdf_expand(prk, info, length)
# Executes both functions performing full hkdf process

# Example case:
salt = b'random_salt' #In real life salt value is a randomly generated large number
input_key_material = b'secret_key'
info = b'additional_info'
length = 32  # Length of the derived key in bytes

derived_key = hkdf(salt, input_key_material, info, length)
print("Derived Key:", derived_key)