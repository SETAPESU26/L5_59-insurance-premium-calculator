"""Automated unit test suite for the insurance premium calculator module."""

import io
import os
import ssl
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import defusedxml.common

import premium_calculator as pc


class TestPremiumCalculatorQuality(unittest.TestCase):
    """Test suite covering code quality, calculation, and edge cases."""

    def test_identical_calculations_produce_identical_results(self):
        """Identical inputs must produce identical quotes across calls."""
        quote1 = pc.calculate_premium("health", 30, 500000, False, 0)
        quote2 = pc.calculate_premium("health", 30, 500000, False, 0)
        self.assertEqual(quote1, 6000.0)
        self.assertEqual(quote2, 6000.0)
        self.assertEqual(quote1, quote2)

    def test_discounts_do_not_leak_between_calls(self):
        """Discounts applied in one quote must not affect subsequent quotes."""
        discounted = pc.calculate_premium(
            "health", 30, 500000, False, 0, discounts=[500]
        )
        subsequent = pc.calculate_premium("health", 30, 500000, False, 0)
        self.assertEqual(discounted, 5500.0)
        self.assertEqual(subsequent, 6000.0)

    def test_premiums_must_not_become_negative(self):
        """Stacked discounts exceeding the premium must clamp to zero."""
        excessive_discounts = [3000, 3000, 3000]
        quote = pc.calculate_premium(
            "life", 25, 100000, False, 0, discounts=excessive_discounts
        )
        self.assertEqual(quote, 0.0)

    def test_negative_discounts_raise_error(self):
        """Negative discount values must be rejected."""
        with self.assertRaises(ValueError):
            pc.calculate_premium(
                "health", 30, 500000, False, 0, discounts=[-100]
            )

    def test_smoker_string_interpretation(self):
        """String indicators for smoker status must be properly interpreted."""
        quote_no = pc.calculate_premium("motor", 50, 800000, "no", 0)
        quote_yes = pc.calculate_premium("motor", 50, 800000, "yes", 0)
        self.assertEqual(quote_no, 6900.0)
        self.assertAlmostEqual(quote_yes, 8970.0, places=2)

    def test_age_calculation_accounts_for_birthdays(self):
        """Age calculation must consider whether birthday occurred yet."""
        age_dec = pc.age_from_dob("31-12-1990")
        self.assertEqual(age_dec, 35)
        age_jan = pc.age_from_dob("01-01-1990")
        self.assertEqual(age_jan, 36)

    def test_age_calculation_rejects_future_dates(self):
        """Dates of birth in the future must raise a ValueError."""
        with self.assertRaises(ValueError):
            pc.age_from_dob("01-01-2099")

    def test_monthly_instalment_valid_and_invalid_months(self):
        """Monthly instalment must validate month parameters properly."""
        self.assertEqual(pc.monthly_instalment(6000.0, 12), 500)
        with self.assertRaises(ValueError):
            pc.monthly_instalment(6000.0, 0)
        with self.assertRaises(ValueError):
            pc.monthly_instalment(6000.0, -6)
        with self.assertRaises(ValueError):
            pc.monthly_instalment(6000.0, "12")
        with self.assertRaises(ValueError):
            pc.monthly_instalment(-500.0, 12)

    def test_leap_year_renewal_dates(self):
        """Renewal date must handle Feb 29th across leap/non-leap years."""
        self.assertEqual(pc.renewal_due("2024-02-29", 1), "2025-02-28")
        self.assertEqual(pc.renewal_due("2024-02-29", 4), "2028-02-29")
        self.assertEqual(pc.renewal_due("2025-03-15", 1), "2026-03-15")

    def test_policy_number_format(self):
        """Policy numbers must start with POL- followed by 6 digits."""
        pol_num = pc.policy_number()
        self.assertTrue(pol_num.startswith("POL-"))
        self.assertEqual(len(pol_num), 10)
        self.assertTrue(pol_num[4:].isdigit())

    def test_save_quote_stores_record(self):
        """Saving a quote must populate the in-memory quote registry."""
        quote_id = pc.save_quote("Asha", 7500.0)
        self.assertIn(quote_id, pc.quotes)
        self.assertEqual(pc.quotes[quote_id]["name"], "Asha")
        self.assertEqual(pc.quotes[quote_id]["premium"], 7500.0)

    def test_backward_compatibility_aliases(self):
        """Legacy camelCase function names must remain accessible."""
        p_calc = pc.calculatePremium("health", 30, 500000, False, 0)
        self.assertEqual(p_calc, 6000.0)
        self.assertEqual(pc.ageFromDob("01-01-1990"), 36)
        self.assertEqual(pc.monthlyInstalment(6000.0, 12), 500)
        self.assertEqual(pc.renewalDue("2025-03-15", 1), "2026-03-15")


class TestPremiumCalculatorSecurity(unittest.TestCase):
    """Test suite covering Bandit security vulnerabilities and defenses."""

    def test_invalid_xml_records_handled_safely(self):
        """XML with invalid records must extract valid entries safely."""
        xml_data = (
            "<policies>"
            "<policy type='health' age='40' sum='300000'/>"
            "<policy type='motor' age='abc' sum='1'/>"
            "</policies>"
        )
        policies = pc.import_policies(xml_data)
        self.assertEqual(policies, [("health", 40, 300000)])

    def test_malicious_xml_rejected(self):
        """DefusedXML must reject XML entity expansions and XXE attacks."""
        malicious_xml = (
            "<?xml version='1.0'?>\n"
            "<!DOCTYPE lolz [\n"
            " <!ENTITY lol 'lol'>\n"
            " <!ELEMENT lolz (#PCDATA)>\n"
            " <!ENTITY lol1 '&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;'>\n"
            "]>\n"
            "<policies>"
            "<policy type='health' age='30' sum='100000'/>"
            "</policies>"
        )
        with self.assertRaises(defusedxml.common.DefusedXmlException):
            pc.import_policies(malicious_xml)

    def test_url_validation_rejects_unsupported_schemes(self):
        """Non-HTTPS schemes must be rejected to prevent SSRF/leakage."""
        unsupported_urls = [
            "http://example.com/rates",
            "file:///etc/passwd",
            "ftp://example.com/rates.csv",
            "gopher://example.com",
            "data:text/plain;base64,SGVsbG8=",
        ]
        for url in unsupported_urls:
            with self.assertRaises(ValueError):
                pc.fetch_rates(url)

    def test_tls_certificate_verification_remains_enabled(self):
        """HTTPS fetching must use a verified TLS context."""
        with patch("http.client.HTTPSConnection") as mock_conn:
            mock_inst = MagicMock()
            mock_conn.return_value = mock_inst
            mock_inst.getresponse.return_value.read.return_value = b"rates"
            result = pc.fetch_rates("https://rates.internal.example/tables")
            self.assertEqual(result, b"rates")
            mock_conn.assert_called_once()
            _, kwargs = mock_conn.call_args
            self.assertIn("context", kwargs)
            ctx = kwargs["context"]
            self.assertIsInstance(ctx, ssl.SSLContext)
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(ctx.check_hostname)

    def test_tar_extraction_rejects_path_traversal(self):
        """Tar archive extraction must reject path traversal attempts."""
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w") as tar:
            tar_info = tarfile.TarInfo(name="../evil.txt")
            payload = b"malicious payload"
            tar_info.size = len(payload)
            tar.addfile(tar_info, io.BytesIO(payload))

        archive_buffer.seek(0)
        with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as f:
            f.write(archive_buffer.getvalue())
            tar_filename = f.name

        try:
            with tempfile.TemporaryDirectory() as target_extract_dir:
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    pc.import_claim_documents(
                        tar_filename, target_extract_dir
                    )
        finally:
            if os.path.exists(tar_filename):
                os.remove(tar_filename)

    def test_authorization_does_not_depend_on_hardcoded_secret(self):
        """Token authorization must verify against environment variable."""
        with patch.dict(
            os.environ, {"UNDERWRITER_TOKEN": "dynamic-prod-token"}, clear=True
        ):
            self.assertTrue(pc.is_authorised("dynamic-prod-token"))
            self.assertFalse(pc.is_authorised("wrong-token"))
            # Hardcoded token from original source must not work
            self.assertFalse(pc.is_authorised("uw-7f3a9c2e1b"))

        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(pc.is_authorised("dynamic-prod-token"))

    def test_safe_host_binding(self):
        """Server host binding must default to localhost, not 0.0.0.0."""
        self.assertEqual(pc.HOST, "127.0.0.1")

    def test_safe_temporary_directory(self):
        """Log file path must use system tempdir without hardcoded /tmp."""
        expected_dir = tempfile.gettempdir()
        self.assertTrue(pc.LOG_FILE.startswith(expected_dir))


if __name__ == "__main__":
    unittest.main()
