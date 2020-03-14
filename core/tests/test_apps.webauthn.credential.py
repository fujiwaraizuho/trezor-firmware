from common import *
import storage
from apps.common import mnemonic
from apps.webauthn.credential import Fido2Credential, truncate_utf8
from trezor.crypto.curve import nist256p1
from trezor.crypto.hashlib import sha256


class TestCredential(unittest.TestCase):
    def test_fido2_credential_decode(self):
        mnemonic_secret = b"all all all all all all all all all all all all"
        mnemonic.get_secret = lambda: mnemonic_secret
        storage.is_initialized = lambda: True

        cred_id = (
            b"f1d0020013e65c865634ad8abddf7a66df56ae7d8c3afd356f76426801508b2e"
            b"579bcb3496fe6396a6002e3cd6d80f6359dfa9961e24c544bfc2f26acec1b8d8"
            b"78ba56727e1f6a7b5176c607552aea63a5abe5d826d69fab3063edfa0201d9a5"
            b"1013d69eddb2eff37acdd5963f"
        )

        rp_id = "example.com"
        rp_id_hash = sha256(rp_id).digest()

        user_id = (
            b"3082019330820138a0030201023082019330820138a003020102308201933082"
        )

        user_name = "johnpsmith@example.com"

        creation_time = 2

        public_key = (
            b"a501020326200121582051f0d4c307bc737c90ac605c6279f7d01e451798aa7b"
            b"74df550fdb43a7760c7c22582002b5107fef42094d00f52a9b1e90afb90e1b9d"
            b"ecbf15a6f13d4f882de857e2f4"
        )

        cred_random = (
            b"36a9b5d71c13ed54594474b54073af1fb03ea91cd056588909dae43ae2f35dbf"
        )

        # Load credential.
        cred = Fido2Credential.from_cred_id(unhexlify(cred_id), rp_id_hash)
        self.assertIsNotNone(cred)

        # Check credential data.
        self.assertEqual(hexlify(cred.id), cred_id)
        self.assertEqual(cred.rp_id, rp_id)
        self.assertEqual(cred.rp_id_hash, rp_id_hash)
        self.assertEqual(hexlify(cred.user_id), user_id)
        self.assertEqual(cred.user_name, user_name)
        self.assertEqual(cred.creation_time, creation_time)
        self.assertTrue(cred.hmac_secret)
        self.assertIsNone(cred.rp_name)
        self.assertIsNone(cred.user_display_name)

        # Check credential keys.
        self.assertEqual(hexlify(cred.hmac_secret_key()), cred_random)
        self.assertEqual(hexlify(cred.public_key()), public_key)

    def test_truncation(self):
        self.assertEqual(truncate_utf8("", 3), "")
        self.assertEqual(truncate_utf8("a", 3), "a")
        self.assertEqual(truncate_utf8("ab", 3), "ab")
        self.assertEqual(truncate_utf8("abc", 3), "abc")
        self.assertEqual(truncate_utf8("abcd", 3), "abc")
        self.assertEqual(truncate_utf8("abcde", 3), "abc")
        self.assertEqual(truncate_utf8("a\u0123", 3), "a\u0123")  # b'a\xc4\xa3'
        self.assertEqual(truncate_utf8("a\u1234", 3), "a")  # b'a\xe1\x88\xb4'
        self.assertEqual(truncate_utf8("ab\u0123", 3), "ab")  # b'ab\xc4\xa3'
        self.assertEqual(truncate_utf8("ab\u1234", 3), "ab")  # b'ab\xe1\x88\xb4'
        self.assertEqual(truncate_utf8("abc\u0123", 3), "abc")  # b'abc\xc4\xa3'
        self.assertEqual(truncate_utf8("abc\u1234", 3), "abc")  # b'abc\xe1\x88\xb4'
        self.assertEqual(truncate_utf8("\u1234\u5678", 0), "")  # b'\xe1\x88\xb4\xe5\x99\xb8
        self.assertEqual(truncate_utf8("\u1234\u5678", 1), "")  # b'\xe1\x88\xb4\xe5\x99\xb8
        self.assertEqual(truncate_utf8("\u1234\u5678", 2), "")  # b'\xe1\x88\xb4\xe5\x99\xb8
        self.assertEqual(truncate_utf8("\u1234\u5678", 3), "\u1234")  # b'\xe1\x88\xb4\xe5\x99\xb8
        self.assertEqual(truncate_utf8("\u1234\u5678", 4), "\u1234")  # b'\xe1\x88\xb4\xe5\x99\xb8
        self.assertEqual(truncate_utf8("\u1234\u5678", 5), "\u1234")  # b'\xe1\x88\xb4\xe5\x99\xb8
        self.assertEqual(truncate_utf8("\u1234\u5678", 6), "\u1234\u5678")  # b'\xe1\x88\xb4\xe5\x99\xb8
        self.assertEqual(truncate_utf8("\u1234\u5678", 7), "\u1234\u5678")  # b'\xe1\x88\xb4\xe5\x99\xb8

        cred = Fido2Credential()
        cred.truncate_names()
        self.assertIsNone(cred.rp_name)
        self.assertIsNone(cred.user_name)
        self.assertIsNone(cred.user_display_name)

        cred.rp_name = "a" * 62 + "\u0123"
        cred.user_name = "a" * 63 + "\u0123"
        cred.user_display_name = "a" * 64 + "\u0123"
        cred.truncate_names()
        self.assertEqual(cred.rp_name, "a" * 62 + "\u0123")
        self.assertEqual(cred.user_name, "a" * 63)
        self.assertEqual(cred.user_display_name, "a" * 64)

if __name__ == '__main__':
    unittest.main()
