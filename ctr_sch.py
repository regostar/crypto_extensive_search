
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify


key = b'\x11\x69\x96\x53'*4
nonce = b'\x35\x69\x96\x11'*3

# AES CTR Encryption
def aes_encrypt(key, nonce, plaintext):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext.encode())
    return hexlify(ciphertext).decode()

# AES CTR Decryption
def aes_decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted_text = cipher.decrypt(unhexlify(ciphertext))
    return decrypted_text.decode()

# HTTP request and response - https://developer.mozilla.org/en-US/docs/Web/HTTP/Session
http_request = '''GET / HTTP/1.1
Host: developer.mozilla.org
Accept-Language: fr
'''
http_response = '''POST /contact_form.php HTTP/1.1
Host: developer.mozilla.org
Content-Length: 64
Content-Type: application/x-www-form-urlencoded

name=Joe%20User&request=Send%20me%20one%20of%20your%20catalogue
'''

# Encryption
encrypted_request = aes_encrypt(key, nonce, http_request)
encrypted_response = aes_encrypt(key, nonce, http_response)

# Decryption
decrypted_request = aes_decrypt(key, nonce, encrypted_request)
decrypted_response = aes_decrypt(key, nonce, encrypted_response)

print("Encrypted HTTP Request:", encrypted_request)
print("Encrypted HTTP Response:", encrypted_response)
print("Decrypted HTTP Request:", decrypted_request)
print("Decrypted HTTP Response:", decrypted_response)


# Let's consider we forgot the first 4 bytes of the key
# we start from 0000 + part of key
new_key =  b'\x11\x69\x96\x53'*3
# '\x00'*4 + new_key is the start
for i in range(256**4):
    # 00 to FF is 256 = 2 pow 8 so each byte can have 256 possibilities
    # We need to find 4 bytes

    # construct prefix - 
    possible_prefix = i.to_bytes(4, byteorder='big')

    # add it to the part of the key which we know for sure
    possible_key = possible_prefix + new_key
    possible_enc_request = aes_encrypt(possible_key, nonce, http_request)
    possible_enc_response = aes_encrypt(possible_key, nonce, http_response)
    # print(possible_key)
    if possible_enc_request == encrypted_request and possible_enc_response == encrypted_response:
        print("Key found")
        print("Key :- 0x", possible_key.hex())
        break
    



