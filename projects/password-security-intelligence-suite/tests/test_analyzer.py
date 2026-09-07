import unittest

from passintel import PasswordPolicy, analyze_password


class AnalyzerTests(unittest.TestCase):
    def test_common_password_is_weak(self):
        result = analyze_password("password")
        self.assertLess(result.score, 30)
        self.assertTrue(any(f.code == "common_password" for f in result.findings))

    def test_sequence_is_detected(self):
        result = analyze_password("Abcd1234!xyz")
        self.assertTrue(any(f.code == "sequential" for f in result.findings))

    def test_repeated_substring_is_detected(self):
        result = analyze_password("Ab1!Ab1!Ab1!Ab1!")
        self.assertTrue(any(f.code == "repeated_substring" for f in result.findings))

    def test_strong_random_like_password_scores_high(self):
        result = analyze_password("vQ9!mZ2#Lx7@Np4$Rt8&")
        self.assertGreaterEqual(result.score, 80)
        self.assertEqual(result.rating, "Very Strong")

    def test_result_never_contains_plaintext_field(self):
        secret = "DoNotStore-Me-928!"
        payload = analyze_password(secret).to_dict()
        self.assertNotIn("password", payload)
        self.assertNotIn(secret, repr(payload))

    def test_custom_policy(self):
        policy = PasswordPolicy(min_length=20)
        result = analyze_password("Abcdefghijk1!", policy=policy)
        self.assertFalse(result.policy.passed)


if __name__ == "__main__":
    unittest.main()
