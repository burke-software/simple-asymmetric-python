# simple-asymmetric-python

An easy way to do combined AES and RSA encryption with python

Currently a work in progress and not publically vetted. Do not use unless you wish to inspect the underlying code and verify it is secure.

# To do

- Document public functions
- Get code peer reviewed
- Make friendly exceptions
- Make a Bob and Alice example with two instances of AsymCrypt and sharing of public key + encrypted aes key.
- Unit tests
- Port to javascript (with feature parity and interoperability)

# Example usage

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
