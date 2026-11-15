"""Insurance premium calculator module.

Provides policy rate calculations, underwriting validation, XML ingestion,
document extraction, and instalment schedules with robust security controls.
"""

from datetime import datetime
import http.client
import logging
import math
import os
import secrets
import ssl
import stat
import tarfile
import tempfile
import urllib.parse
import defusedxml.ElementTree as defused_ET

logger = logging.getLogger(__name__)

# Global quote book
quotes = {}
HOST = "127.0.0.1"
UNDERWRITER_TOKEN = os.environ.get("UNDERWRITER_TOKEN", "")
LOG_FILE = os.path.join(tempfile.gettempdir(), "premium_quotes.log")
BASE_RATES = {"health": 5000, "motor": 3000, "life": 8000}


def _validate_risk_inputs(
    policy_type: str, age: int, sum_insured: float
) -> str:
    """Validate core policy inputs and return normalized policy type."""
    pol_type = policy_type.lower()
    if pol_type not in BASE_RATES:
        raise ValueError(f"Invalid policy type: '{policy_type}'")
    if not isinstance(age, int) or age < 0:
        raise ValueError("Age must be a non-negative integer")
    if not isinstance(sum_insured, (int, float)) or sum_insured < 0:
        raise ValueError("Sum insured must be a non-negative number")
    return pol_type


def _extract_optional_factors(extra_args, discounts, kwargs):
    """Extract smoker status, claims count, and validated discount list."""
    raw_smoker = extra_args[0] if extra_args else kwargs.get("smoker", False)
    if isinstance(raw_smoker, str):
        is_smoker = raw_smoker.strip().lower() in ("true", "yes", "1", "y")
    else:
        is_smoker = bool(raw_smoker)

    claims_val = (
        extra_args[1] if len(extra_args) > 1 else kwargs.get("claims", 0)
    )
    if not isinstance(claims_val, int) or claims_val < 0:
        raise ValueError("Claims count must be a non-negative integer")

    if len(extra_args) > 2:
        raw_disc = extra_args[2]
    elif discounts is not None:
        raw_disc = discounts
    else:
        raw_disc = kwargs.get("discounts", None)

    disc_list = [float(d) for d in (raw_disc or [])]
    if any(d < 0 for d in disc_list):
        raise ValueError("Discounts cannot be negative")

    return is_smoker, claims_val, disc_list


def calculate_premium(
    policy_type: str,
    age: int,
    sum_insured: float,
    *extra_args,
    discounts=None,
    **kwargs,
) -> float:
    """Calculate insurance premium based on risk factors and discounts."""
    pol_type = _validate_risk_inputs(policy_type, age, sum_insured)
    is_smoker, claims_val, disc_list = _extract_optional_factors(
        extra_args, discounts, kwargs
    )

    base = BASE_RATES[pol_type]
    premium = float(base + sum_insured * 0.002)
    if age > 45:
        premium *= 1.5
    if is_smoker:
        premium *= 1.3
    premium += claims_val * 1000

    for disc in disc_list:
        premium -= disc

    return max(0.0, round(premium, 2))


def age_from_dob(dob: str) -> int:
    """Calculate age in full years from date of birth (DD-MM-YYYY)."""
    try:
        born = datetime.strptime(dob, "%d-%m-%Y").date()
    except (ValueError, TypeError) as err:
        raise ValueError(
            f"Invalid date format, expected DD-MM-YYYY: {dob}"
        ) from err

    today = datetime.now().date()
    if born > today:
        raise ValueError("Date of birth cannot be in the future")

    age = today.year - born.year - (
        (today.month, today.day) < (born.month, born.day)
    )
    return age


def policy_number() -> str:
    """Generate a cryptographically secure unique policy identifier."""
    num = secrets.SystemRandom().randint(100000, 999999)
    return f"POL-{num}"


def save_quote(name: str, premium: float) -> str:
    """Save quote details safely preventing symlink attacks."""
    number = policy_number()
    quotes[number] = {"name": name, "premium": float(premium)}
    flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(LOG_FILE, flags, 0o600)
    try:
        fstat = os.fstat(fd)
        if hasattr(os, "getuid") and fstat.st_uid != os.getuid():
            raise PermissionError("Log file ownership mismatch")
        if not stat.S_ISREG(fstat.st_mode):
            raise OSError("Log target is not a regular file")
        with open(fd, "a", encoding="utf-8", closefd=True) as file_handle:
            file_handle.write(f"{number},{name},{premium:.2f}\n")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return number


def import_policies(xml_text: str) -> list:
    """Safely parse XML policy data, rejecting malicious external entities."""
    root = defused_ET.fromstring(xml_text)
    result = []
    for policy in root.findall("policy"):
        try:
            pol_type = policy.get("type")
            age_str = policy.get("age")
            sum_str = policy.get("sum")
            if pol_type and age_str is not None and sum_str is not None:
                result.append((pol_type, int(age_str), int(sum_str)))
        except (ValueError, TypeError) as err:
            logger.warning("Skipping invalid policy record: %s", err)
    return result


def fetch_rates(url: str) -> bytes:
    """Fetch rate tables over HTTPS with verified TLS certificates."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError(
            f"Unsupported or insecure URL scheme: '{parsed.scheme}'. "
            "Only HTTPS is allowed."
        )
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(
        parsed.netloc, context=context, timeout=10
    )
    try:
        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path += f"?{parsed.query}"
        conn.request("GET", path)
        response = conn.getresponse()
        return response.read()
    finally:
        conn.close()


def import_claim_documents(
    archive_path: str, target_dir: str = "claims_docs"
) -> None:
    """Extract scanned claim documents safely, preventing path traversal."""
    target_path = os.path.abspath(target_dir)
    os.makedirs(target_path, exist_ok=True)
    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            dest_path = os.path.abspath(os.path.join(target_path, member.name))
            if not (
                dest_path == target_path
                or dest_path.startswith(target_path + os.sep)
            ):
                raise ValueError(
                    f"Path traversal detected in archive: {member.name}"
                )
        tar.extractall(target_path, filter="data")


def monthly_instalment(premium: float, months: int = 12) -> int:
    """Calculate the monthly instalment amount for a given total premium."""
    if not isinstance(months, int) or months <= 0:
        raise ValueError(
            f"Instalment months must be a positive integer, got: {months}"
        )
    if premium < 0:
        raise ValueError("Premium cannot be negative")
    return math.floor(premium / months)


def is_authorised(token: str) -> bool:
    """Verify underwriter authorization token against environment variable."""
    expected_token = os.environ.get("UNDERWRITER_TOKEN")
    if not expected_token or not token:
        return False
    return secrets.compare_digest(token, expected_token)


def renewal_due(start: str, years: int = 1) -> str:
    """Calculate policy renewal date, handling leap-year edge cases safely."""
    date = datetime.strptime(start, "%Y-%m-%d").date()
    target_year = date.year + years
    try:
        renewed = date.replace(year=target_year)
    except ValueError:
        renewed = date.replace(year=target_year, day=28)
    return renewed.strftime("%Y-%m-%d")


def print_quotes() -> None:
    """Print all currently stored insurance quotes in formatted output."""
    print("===== Quote Book =====")
    for idx, (key, quote_info) in enumerate(quotes.items(), start=1):
        print(
            f"{idx} {key} {quote_info['name']} Rs. {quote_info['premium']}"
        )


def main() -> None:
    """Demonstrate insurance premium calculation workflows."""
    p1 = calculate_premium("health", 30, 500000, False, 0)
    p2 = calculate_premium("health", 30, 500000, False, 0)
    p3 = calculate_premium("motor", 50, 800000, "no", 0)
    p4 = calculate_premium("life", 25, 100000, False, 0, [3000, 3000, 3000])
    print("Quote 1:", p1)
    print("Quote 2 (same customer details):", p2)
    print("Non-smoker aged 50:", p3)
    print("Life with stacked discounts:", p4)
    print("Age from DOB 31-12-1990:", age_from_dob("31-12-1990"))
    print("Monthly instalment:", monthly_instalment(p3))
    print("Renewal due:", renewal_due("2025-03-15"))
    sample_xml = (
        "<policies>"
        "<policy type='health' age='40' sum='300000'/>"
        "<policy type='motor' age='abc' sum='1'/>"
        "</policies>"
    )
    print("Imported:", import_policies(sample_xml))
    print("Saved as:", save_quote("Kiran", p1))
    auth_token = os.environ.get("UNDERWRITER_TOKEN", "")
    print("Authorised:", is_authorised(auth_token))
    print("Server would listen on", HOST)
    print_quotes()


def __getattr__(name: str):
    """Provide backward compatibility for legacy camelCase function names."""
    legacy_names = {
        "calculatePremium": calculate_premium,
        "ageFromDob": age_from_dob,
        "policyNumber": policy_number,
        "saveQuote": save_quote,
        "importPolicies": import_policies,
        "fetchRates": fetch_rates,
        "importClaimDocuments": import_claim_documents,
        "monthlyInstalment": monthly_instalment,
        "isAuthorised": is_authorised,
        "renewalDue": renewal_due,
        "printQuotes": print_quotes,
    }
    if name in legacy_names:
        return legacy_names[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


if __name__ == "__main__":
    main()
