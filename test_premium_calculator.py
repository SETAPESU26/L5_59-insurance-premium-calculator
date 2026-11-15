"""Automated unit test suite for the insurance premium calculator module."""

import unittest
from premium_calculator import (
    calculate_premium,
    age_from_dob,
    policy_number,
    save_quote,
    monthly_instalment,
    renewal_due,
    quotes,
    calculatePremium,
    ageFromDob,
    monthlyInstalment,
    renewalDue,
)


class TestPremiumCalculatorQuality(unittest.TestCase):
    """Test suite covering code quality, calculation accuracy, and edge cases."""

    def test_identical_calculations_produce_identical_results(self):
        """Identical inputs must produce identical quotes across calls."""
        quote1 = calculate_premium("health", 30, 500000, False, 0)
        quote2 = calculate_premium("health", 30, 500000, False, 0)
        self.assertEqual(quote1, 6000.0)
        self.assertEqual(quote2, 6000.0)
        self.assertEqual(quote1, quote2)

    def test_discounts_do_not_leak_between_calls(self):
        """Discounts applied in one quote must not affect subsequent quotes."""
        discounted = calculate_premium(
            "health", 30, 500000, False, 0, discounts=[500]
        )
        subsequent = calculate_premium("health", 30, 500000, False, 0)
        self.assertEqual(discounted, 5500.0)
        self.assertEqual(subsequent, 6000.0)

    def test_premiums_must_not_become_negative(self):
        """Stacked discounts exceeding the premium must clamp to zero."""
        excessive_discounts = [3000, 3000, 3000]
        quote = calculate_premium(
            "life", 25, 100000, False, 0, discounts=excessive_discounts
        )
        self.assertEqual(quote, 0.0)

    def test_age_calculation_accounts_for_birthdays(self):
        """Age calculation must consider whether the birthday occurred yet."""
        # Applicants born on Dec 31 have not reached that age earlier in the year
        age_dec = age_from_dob("31-12-1990")
        self.assertEqual(age_dec, 35)

        # Applicants born Jan 1 have already reached that age
        age_jan = age_from_dob("01-01-1990")
        self.assertEqual(age_jan, 36)

    def test_age_calculation_rejects_future_dates(self):
        """Dates of birth in the future must raise a ValueError."""
        with self.assertRaises(ValueError):
            age_from_dob("01-01-2099")

    def test_monthly_instalment_valid_and_invalid_months(self):
        """Monthly instalment must validate month parameters properly."""
        # Valid calculation: 6000 / 12 = 500
        self.assertEqual(monthly_instalment(6000.0, 12), 500)

        # Zero or negative months must raise ValueError
        with self.assertRaises(ValueError):
            monthly_instalment(6000.0, 0)
        with self.assertRaises(ValueError):
            monthly_instalment(6000.0, -6)
        with self.assertRaises(ValueError):
            monthly_instalment(6000.0, "12")  # Non-integer

    def test_leap_year_renewal_dates(self):
        """Renewal date must handle February 29th across leap and non-leap years."""
        # Leap year 2024 to non-leap 2025 -> Feb 28
        self.assertEqual(renewal_due("2024-02-29", 1), "2025-02-28")
        # Leap year 2024 to leap year 2028 -> Feb 29
        self.assertEqual(renewal_due("2024-02-29", 4), "2028-02-29")
        # Regular date -> exact same day next year
        self.assertEqual(renewal_due("2025-03-15", 1), "2026-03-15")

    def test_policy_number_format(self):
        """Policy numbers must start with POL- prefix followed by 6 digits."""
        pol_num = policy_number()
        self.assertTrue(pol_num.startswith("POL-"))
        self.assertEqual(len(pol_num), 10)
        self.assertTrue(pol_num[4:].isdigit())

    def test_save_quote_stores_record(self):
        """Saving a quote must populate the in-memory quote registry."""
        quote_id = save_quote("Asha", 7500.0)
        self.assertIn(quote_id, quotes)
        self.assertEqual(quotes[quote_id]["name"], "Asha")
        self.assertEqual(quotes[quote_id]["premium"], 7500.0)

    def test_backward_compatibility_aliases(self):
        """Legacy camelCase function names must remain accessible."""
        p_calc = calculatePremium("health", 30, 500000, False, 0)
        self.assertEqual(p_calc, 6000.0)
        self.assertEqual(ageFromDob("01-01-1990"), 36)
        self.assertEqual(monthlyInstalment(6000.0, 12), 500)
        self.assertEqual(renewalDue("2025-03-15", 1), "2026-03-15")


if __name__ == "__main__":
    unittest.main()
