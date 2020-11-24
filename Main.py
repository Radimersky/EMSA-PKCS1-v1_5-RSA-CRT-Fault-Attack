import sys
import math

from Crypto.Util.number import bytes_to_long
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512


# The RSA signature s is computed as:
# s = m^d (mod N)

def get_key_from_file(file_path):
    with open(file_path, 'r') as f:
        key = RSA.import_key(f.read())
    return key


def get_signature_from_file(file_path):
    with open(file_path, 'rb') as f:
        s = f.read()
    return s


def get_message_from_file(file_path):
    with open(file_path, 'r') as f:
        m = f.read()
    return m


def get_txt_message_hash_sha512(text):
    binary_message = text.encode('utf-8')
    hash_message = SHA512.new(binary_message)
    return hash_message


# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def fault_attack_rsa(hash, key, incorrectSignature, originalMessage):
    n = key.n
    e = key.e

    # create padded message
    random_key = RSA.generate(key.size_in_bits())
    random_key_signature = pkcs1_15.new(random_key).sign(hash)
    m = pow(bytes_to_long(random_key_signature), random_key.e, random_key.n)

    s = bytes_to_long(incorrectSignature)

    # s_ = ((s'^e mod N) - m) mod N
    s_ = ((pow(s, e, n)) - m) % n

    # p = GCD(((s'^e mod N) - m) mod N, N)
    p = math.gcd(n, s_)
    q = n // p

    if n != (q * p):
        raise Exception('q*p is not equal to N')

    phi = ((p - 1) * (q - 1))
    d = modinv(e, phi)

    if ((d * e) % phi) != 1:
        raise Exception('((d * e) % phi) is not equal to 1')

    private_key = RSA.construct((n, e, d, p, q))

    # Create a valid signature of the message
    h = SHA512.new(originalMessage.encode())
    random_key_signature = pkcs1_15.new(private_key).sign(h)

    signature_output = open("good_sig.sha512", "wb")
    signature_output.write(random_key_signature)

    print("Private key N")
    print(hex(private_key.n))
    print("Private key prime p")
    print(hex(private_key.p))
    print("Private key prime q")
    print(hex(private_key.q))
    print("Private key d")
    print(hex(private_key.d))
    print("the modulus N from the public key")
    print(hex(n))
    print("the faulty signature to the power e modulo N (i.e. (s'^e mod N))")
    print(hex(pow(s, e, n)))
    print("the hash of the message padded according to the PKCS #1 v1.5 format")
    print(hex(m))
    print("the prime factor of N obtained from the GCD computation")
    print(hex(p))
    print("a valid signature of the message")
    print(hex(bytes_to_long(random_key_signature)))



keyPath = sys.argv[1]
messagePath = sys.argv[2]
signaturePath = sys.argv[3]

public_key = get_key_from_file(keyPath)
signature = get_signature_from_file(signaturePath)
message = get_message_from_file(messagePath)

binaryMessage = message.encode('utf-8')
hashMessage = SHA512.new(binaryMessage)

try:
    pkcs1_15.new(public_key).verify(hashMessage, signature)
    print("Correct signature")
except (ValueError, TypeError):
    fault_attack_rsa(hashMessage, public_key, signature, message)
