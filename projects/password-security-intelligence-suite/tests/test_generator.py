import string
import unittest

from passintel.generator import generate_passphrase, generate_password


class GeneratorTests(unittest.TestCase):
    def test_password_length_and_classes(self):
        value = generate_password(32)
        self.assertEqual(len(value), 32)
        self.assertTrue(any(c.islower() for c in value))
        self.assertTrue(any(c.isupper() for c in value))
        self.assertTrue(any(c.isdigit() for c in value))
        self.assertTrue(any(c in string.punctuation for c in value))

    def test_password_rejects_short_length(self):
        with self.assertRaises(ValueError):
            generate_password(8)

    def test_passphrase_shape(self):
        value = generate_passphrase(5)
        self.assertEqual(len(value.split("-")), 6)  # five words + numeric component


if __name__ == "__main__":
    unittest.main()
