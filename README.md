# Lab 5: Static Code Analysis — Insurance Premium Calculator

**Repository:** `L5_59-insurance-premium-calculator`  
**Working branch:** `lab5/static-analysis-fixes`

## About the Program

An insurance premium calculator that computes quotes for health, motor, and life policies, calculates applicant ages from date of birth, logs quotes to persistent storage, imports policies from external partner XML, downloads rate tables, extracts claim document archives, calculates monthly instalment schedules, and handles leap-year policy renewals.

## Environment & Tooling

- **Python Version:** 3.12
- **Virtual Environment:** `.venv`
- **Analysis Tools:** Pylint, Bandit, Flake8, defusedxml

## Execution Instructions

Run the premium calculator demonstration:
```bash
python premium_calculator.py
```

Run the automated test suite:
```bash
python -m unittest test_premium_calculator.py
```

Run the static code analysis tools:
```bash
# 1. Pylint (Code quality, design, and style)
python -m pylint premium_calculator.py

# 2. Bandit (Security vulnerability scanning)
python -m bandit -r premium_calculator.py

# 3. Flake8 (PEP 8 compliance and formatting)
python -m flake8 premium_calculator.py
```

## Static Analysis Results Summary

| Metric / Tool | Original Baseline | Final Result | Target | Status |
|---------------|-------------------|--------------|--------|--------|
| **Pylint** | 5.73 / 10 | **10.00 / 10** | > 9.5 / 10 | Exceeded |
| **Bandit** | 10 findings (1 High, 5 Med, 4 Low) | **0 findings** | 0 unresolved | Clean |
| **Flake8** | 19 violations | **0 violations** | 0 violations | Clean |
| **Automated Tests** | N/A | **20 passed (100%)** | All passing | Verified |

## Deliverables

1. `premium_calculator.py`: Fully refactored, hardened, and PEP 8 compliant source code.
2. `test_premium_calculator.py`: Comprehensive test suite verifying calculation logic, edge cases, and security controls.
3. `issues.md`: Detailed remediation table documenting High, Medium, and Low severity findings and fix approaches.
4. `reflection.md`: Comprehensive reflection covering tool comparisons, critical vulnerabilities, false positives, and dynamic testing.
5. Baseline reports: `pylint_before.txt`, `bandit_before.txt`, `flake8_before.txt`.
6. Final reports: `pylint_after.txt`, `bandit_after.txt`, `flake8_after.txt`.
