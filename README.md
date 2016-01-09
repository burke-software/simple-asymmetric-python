# simple-asymmetric-python

[![Build Status](https://travis-ci.org/burke-software/simple-asymmetric-python.svg?branch=master)](https://travis-ci.org/burke-software/simple-asymmetric-python)

An easy way to do combined AES and RSA encryption with python

Currently a work in progress and not publically vetted. Do not use unless you wish to inspect the underlying code and verify it is secure.

# To do

- Get code peer reviewed
- Port to javascript (with feature parity and interoperability)

# Installation

`pip install simple-asymmetric`

# Example usage

## Simple usage

```
asym = AsymCrypt()
public, private = asym.make_rsa_keys()
aes_key = asym.make_aes_key()

ciphertext_aes = asym.rsa_encrypt(aes_key)
asym.rsa_decrypt(text)

msg = 'hello' * 200  # Too long for RSA encrypt
ciphertext = asym.encrypt(msg)
asym.decrypt(ciphertext)
b'hellohellohellohello......
```

## Bob and Alice example

This example shows how we could share secrets between two entities

```
# Set up Bob and Alice with rsa keys. Bob will make a aes key that will be shared.
bob = AsymCrypt()
alice = AsymCrypt()
bob.make_rsa_keys(bits=2048)
alice.make_rsa_keys(bits=2048)
bob.make_aes_key()

# Send the aes key to Alice. It's unnecessary to encrypt it but let's do so 
# to show it it's done. We could safely post the encrypted aes key in the public.
# Behind the scenes RSA public and private key encryption is taking place.
shared_encrypted_aes = bob.get_encrypted_aes_key(alice.public_key)
alice.set_aes_key_from_encrypted(shared_encrypted_aes)

# Now that both Bob and Alice have the aes key - they can communicate easily.
# msg_ciphertext can sefely be posted in public.
msg = "hello"
msg_ciphertext = bob.encrypt(msg)
decrypted_msg = alice.decrypt(msg_ciphertext)

print(decrypted_msg.decode())  # Decode to make it a unicode string.
"hello"
```
