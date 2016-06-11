import unittest
from .asymmetric_encryption import AsymCrypt
from .exceptions import (
    MissingAESException, MissingRSAPrivateException, MissingRSAPublicException)


class TestAsymCrypt(unittest.TestCase):
    aes_key = b'uaBbv71UYwAndWfYRGO6lqgkJTylUdqLzCGJ7xLyvq4='
    public_key = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArWrCwDnza3+IRvpCHvKa\nQatyDFFlDrAQvYuZvISkoT+52KOHkCuWbCu/a+mBR1zHS2o75Vvnc0i8T1LWwnQ3\n2xzi4Hhec2i/NLxq72eqmmPY8joSpg6Qpp9CKeGTVt9wLl8ZVnRbI9zAyjY483bk\nCqd/oQvGDC5RVVq7J1gjvyVA6skIH0I5lHYOgsr4cDYUhIt8agN3IuglKZMCySYH\n29C5eWa9trUm6lMsnluu4fWdy14xIIWsG9O7XHtDNmbBTIOExnzCkL7uXaPSthW4\ncoBBV4d5XZ62HTsF6seISuKAQ8VRkY7dwv8K6a4XqJQ5g3/3nNjdjDFo7koCsR7y\nuQIDAQAB\n-----END PUBLIC KEY-----'
    private_key = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEArWrCwDnza3+IRvpCHvKaQatyDFFlDrAQvYuZvISkoT+52KOH\nkCuWbCu/a+mBR1zHS2o75Vvnc0i8T1LWwnQ32xzi4Hhec2i/NLxq72eqmmPY8joS\npg6Qpp9CKeGTVt9wLl8ZVnRbI9zAyjY483bkCqd/oQvGDC5RVVq7J1gjvyVA6skI\nH0I5lHYOgsr4cDYUhIt8agN3IuglKZMCySYH29C5eWa9trUm6lMsnluu4fWdy14x\nIIWsG9O7XHtDNmbBTIOExnzCkL7uXaPSthW4coBBV4d5XZ62HTsF6seISuKAQ8VR\nkY7dwv8K6a4XqJQ5g3/3nNjdjDFo7koCsR7yuQIDAQABAoIBAGAZz77y3mBuFjkv\nKkE4NB+8QMFuwc/35e8EU7fS0eDCDd1uEgvk+8EKJVRJ3GiNk6vJPVQHMCYE4sYa\npASyntmAEoJOchkGrR8uYxw0mKhiOLFTWU5IuAR+MQ5AgYQc4m/wJ3xvkqo3BWeJ\n0Nmqwwjcda/rdF7/s/bXBuvwvi6ILv665ZtVwMKtUuY851s0riwUN4cIiifyw/GQ\nLNCrkH2+V3SOMZ8OTOXfMFbDD1cAe4QSPgeFNL/3bKu1e0/Z5b6GLIA9zkiR+0i5\nxq9LDKba/gCyej+YZz9A57MpDi1zmsNV/BPhx9Ns5jY8G9dE1n6/w0Fyf0v+i/93\nhWb1XJkCgYEA0SBF3KgErqsXtz7U05ih0lbKUXnOaJMWewhj0w+zRi9nhJ5X3G2q\nwt+VTyLtoRRW1vklZ9L+zApsfbAROdtA+TA7NFKiu7/de1hzGTWGkqcMEdx3CpLP\nQz7nNchfSAgLagxW6Kb7ob8ytMaegK1id4bOaJ4eV5xemsK3ncf/0OcCgYEA1El9\ntivdU0A5S42qZl4OiD0pHN/E1LOQcwwxKE2Vipzek03NPWtFNOmDRg8mVpbS4MkE\niiH8BnKep4oHY0ac4cBPSQ/7QE2992ge1ru3B8gLcpoeNrJuS6pKr2KPfVQnV+tT\noNtdXoR6EJz9VS12QpbSZF6ClAuOAjgCaIfFi18CgYAoaDr3esOE2Gw5rPtEc055\nLOnkuktmq10BospfAr6aBhjTaCED53DCPJ9F7jLKF/r7iKJwoDU5SZ5S3s1FR5cT\nTv1xi7ID4vuxlJKQwWXiOkK7xMR/l4RSsvnLy46VhXBnKkE0rOccBqyOf34q0NWg\n0LxbPIoSVZV2A7+kzfsg6wKBgA0RIP3PoWX4dA5kf/KhI3/bU+aFF5aIHwIV5Ai5\nDdVkZobmqRV4vt/M59muIQv/aKeReAgQo3S6JW3mnyHLPOjgb4DtzOdeYa0S6aMK\nFvARrjK1rdpsDUH3D3XQOUjbnzhYMeOa3RpuSR0wrJ9LlxXuNrEa6Cq4s1sLm4pX\noR89AoGAOYgo70h6Csg45494yzTsys+gLTytw+wEbefYD4uMLidCgO3hjbuO7G1g\nsOtVPsRVD+8b7qg+45hDMLrcepJeCs751Z6gLCFkJJq2owoSkxxwtDUXgQkZ9NBr\n6dNOEvjztvCkv0n1knFdG1A3VPYHpTI5QIKpA7UxPbdH2p3YkZc=\n-----END RSA PRIVATE KEY-----'

    def test_bob_alice(self):
        bob = AsymCrypt()
        alice = AsymCrypt()
        bob.make_rsa_keys(bits=2048)
        alice.make_rsa_keys(bits=2048)
        bob.make_aes_key()

        shared_encrypted_aes = bob.get_encrypted_aes_key(alice.public_key)
        alice.set_aes_key_from_encrypted(shared_encrypted_aes)

        msg = "hello"
        msg_ciphertext = bob.encrypt(msg)
        self.assertNotEqual(msg_ciphertext, msg)
        decrypted_msg = alice.decrypt(msg_ciphertext).decode()
        self.assertEqual(decrypted_msg, msg)

    def test_bob_alice_base64(self):
        bob = AsymCrypt()
        alice = AsymCrypt()
        bob.make_rsa_keys(bits=2048)
        alice.make_rsa_keys(bits=2048)
        bob.make_aes_key()

        shared_encrypted_aes = bob.get_encrypted_aes_key(alice.public_key, True)
        alice.set_aes_key_from_encrypted(shared_encrypted_aes, True)

        msg = "hello"
        msg_ciphertext = bob.encrypt(msg)
        self.assertNotEqual(msg_ciphertext, msg)
        decrypted_msg = alice.decrypt(msg_ciphertext).decode()
        self.assertEqual(decrypted_msg, msg)

    def test_return_data(self):
        """ This tests that key data is returned and able to be decoded for
        storage.
        Might be useful to gather generated key and ciphertext data in other
        tests
        """
        bob = AsymCrypt()
        alice = AsymCrypt()

        bob_keys = bob.make_rsa_keys(bits=2048)
        self.assertIn('PRIVATE', bob_keys[0].decode())
        self.assertIn('PUBLIC', bob_keys[1].decode())

        alice_passphrase = '123456'
        alice_keys = alice.make_rsa_keys(bits=2048, passphrase=alice_passphrase)
        self.assertIn('PRIVATE', alice_keys[0].decode())
        self.assertIn('PUBLIC', alice_keys[1].decode())

        aes_key = bob.make_aes_key()
        self.assertTrue(aes_key.decode())

        aes_ciphertext = bob.get_encrypted_aes_key(alice.public_key, True)
        self.assertTrue(aes_ciphertext.decode())
        alice.set_aes_key_from_encrypted(aes_ciphertext, True)

        msg = "hello"
        msg_ciphertext = bob.encrypt(msg)
        self.assertTrue(msg_ciphertext.decode())
        decrypted_msg = alice.decrypt(msg_ciphertext).decode()
        self.assertTrue(decrypted_msg)

        print(bob_keys[0].decode())
        print(bob_keys[1].decode())
        print(alice_passphrase)
        print(alice_keys[0].decode())
        print(alice_keys[1].decode())
        print(aes_key.decode())
        print(aes_ciphertext.decode())
        print(msg_ciphertext.decode())
        print(decrypted_msg)

    def test_encrypt_decrypt(self):
        asym = AsymCrypt(aes_key=self.aes_key,
                         public_key=self.public_key,
                         private_key=self.private_key)
        msg = "hello"
        ciphertext = asym.encrypt(msg)
        self.assertNotEqual(ciphertext, msg)
        decrypted_msg = asym.decrypt(ciphertext).decode()
        self.assertEqual(decrypted_msg, msg)

    def test_passphrase(self):
        asym = AsymCrypt()
        private, public, passphrase = asym.make_rsa_keys_with_passphrase()

        asym = AsymCrypt()
        asym.set_private_key(private, passphrase=passphrase)
        self.assertTrue(self.private_key)

    def test_unencrypted_rsa_private_key(self):
        asym = AsymCrypt()
        private, public = asym.make_rsa_keys()

        asym = AsymCrypt()
        asym.set_private_key(private)
        asym.set_public_key(public)
        self.assertTrue(self.private_key)
        msg = 'hello'
        ciphertext = asym.rsa_encrypt(msg)
        self.assertNotEqual(ciphertext, msg)
        plaintext = asym.rsa_decrypt(ciphertext).decode()
        self.assertEqual(msg, plaintext)


    def test_exceptions(self):
        asym = AsymCrypt()

        with self.assertRaises(MissingAESException):
            asym.encrypt('foo')

        with self.assertRaises(MissingAESException):
            asym.decrypt(b'foo')

        with self.assertRaises(MissingRSAPublicException):
            asym.rsa_encrypt('foo')

        with self.assertRaises(MissingRSAPrivateException):
            asym.rsa_decrypt(b'foo')
