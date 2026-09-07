from urllib.parse import urlparse
import ipaddress


# ============================================================
# MACHINE LEARNING FEATURES
# ============================================================

FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS"
]


# ============================================================
# PREPARE URL
# ============================================================

def prepare_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


# ============================================================
# EXTRACT ML FEATURES
# ============================================================

def extract_features(url):

    url = prepare_url(url)

    parsed = urlparse(url)

    domain = parsed.netloc.split("@")[-1].split(":")[0]

    # --------------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------------

    url_length = len(url)

    # --------------------------------------------------------
    # DOMAIN LENGTH
    # --------------------------------------------------------

    domain_length = len(domain)

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(domain)

        is_domain_ip = 1

    except ValueError:

        is_domain_ip = 0

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    parts = domain.split(".")

    no_subdomain = max(len(parts) - 2, 0)

    # --------------------------------------------------------
    # OBFUSCATION
    # --------------------------------------------------------

    obfuscated_chars = sum(
        url.count(c)
        for c in ["@", "%"]
    )

    has_obfuscation = (
        1 if obfuscated_chars > 0 else 0
    )

    # --------------------------------------------------------
    # LETTERS
    # --------------------------------------------------------

    letters = sum(
        c.isalpha()
        for c in url
    )

    # --------------------------------------------------------
    # DIGITS
    # --------------------------------------------------------

    digits = sum(
        c.isdigit()
        for c in url
    )

    # --------------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------------

    equals_count = url.count("=")

    question_count = url.count("?")

    ampersand_count = url.count("&")

    other_special = sum(
        not c.isalnum()
        for c in url
    )

    # --------------------------------------------------------
    # RATIOS
    # --------------------------------------------------------

    total_length = max(len(url), 1)

    obfuscation_ratio = (
        obfuscated_chars / total_length
    )

    letter_ratio = (
        letters / total_length
    )

    digit_ratio = (
        digits / total_length
    )

    special_ratio = (
        other_special / total_length
    )

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    is_https = (
        1
        if parsed.scheme.lower() == "https"
        else 0
    )

    # --------------------------------------------------------
    # RETURN FEATURES
    # --------------------------------------------------------

    return [

        url_length,

        domain_length,

        is_domain_ip,

        no_subdomain,

        has_obfuscation,

        obfuscated_chars,

        obfuscation_ratio,

        letters,

        letter_ratio,

        digits,

        digit_ratio,

        equals_count,

        question_count,

        ampersand_count,

        other_special,

        special_ratio,

        is_https

    ]


# ============================================================
# ADVANCED URL SECURITY ANALYSIS
# ============================================================

def analyze_url(url):

    url = prepare_url(url)

    parsed = urlparse(url)

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    domain = (
        parsed.netloc
        .split("@")[-1]
        .split(":")[0]
    )

    lower_url = url.lower()

    indicators = []

    reasons = []

    security_checks = []


    # ========================================================
    # 1. SUSPICIOUS KEYWORDS
    # ========================================================

    suspicious_keywords = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "update",
        "secure",
        "security",
        "confirm",
        "billing",
        "payment",
        "wallet",
        "bank",
        "credential",
        "authenticate",
        "authentication"

    ]


    found_keywords = []


    for keyword in suspicious_keywords:

        if keyword in lower_url:

            found_keywords.append(keyword)


    if found_keywords:

        indicators.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

        reasons.append(
            "The URL contains words commonly "
            "associated with login, verification, "
            "payment or account-related pages."
        )

        security_checks.append({

            "name": "Suspicious Keywords",

            "status": "WARNING",

            "message":
                "Suspicious keywords found"

        })

    else:

        security_checks.append({

            "name": "Suspicious Keywords",

            "status": "SAFE",

            "message":
                "No obvious suspicious keywords"

        })


    # ========================================================
    # 2. IP ADDRESS CHECK
    # ========================================================

    is_ip_address = False


    try:

        ipaddress.ip_address(domain)

        is_ip_address = True

        indicators.append(
            "URL uses an IP address instead of a domain name"
        )

        reasons.append(
            "The website is accessed using an IP address "
            "instead of a normal domain name."
        )

        security_checks.append({

            "name": "IP Address",

            "status": "WARNING",

            "message":
                "IP address used instead of domain"

        })

    except ValueError:

        security_checks.append({

            "name": "IP Address",

            "status": "SAFE",

            "message":
                "Normal domain detected"

        })


    # ========================================================
    # 3. SUBDOMAIN CHECK
    # ========================================================

    parts = domain.split(".")

    subdomains = max(
        len(parts) - 2,
        0
    )


    if subdomains >= 3:

        indicators.append(
            "Multiple subdomains detected"
        )

        reasons.append(
            "The URL contains multiple subdomains, "
            "which can sometimes be used to make "
            "a suspicious domain look legitimate."
        )

        security_checks.append({

            "name": "Subdomain Structure",

            "status": "WARNING",

            "message":
                f"{subdomains} subdomains detected"

        })

    else:

        security_checks.append({

            "name": "Subdomain Structure",

            "status": "SAFE",

            "message":
                f"{subdomains} subdomain(s) detected"

        })


    # ========================================================
    # 4. URL LENGTH
    # ========================================================

    if len(url) > 100:

        indicators.append(
            "Unusually long URL"
        )

        reasons.append(
            "The URL is unusually long and may contain "
            "additional tracking, redirection or "
            "encoded information."
        )

        security_checks.append({

            "name": "URL Length",

            "status": "WARNING",

            "message":
                f"Long URL ({len(url)} characters)"

        })

    else:

        security_checks.append({

            "name": "URL Length",

            "status": "SAFE",

            "message":
                f"URL length: {len(url)} characters"

        })


    # ========================================================
    # 5. DIGIT CHECK
    # ========================================================

    digits = sum(
        c.isdigit()
        for c in url
    )


    if digits >= 8:

        indicators.append(
            "High number of digits in URL"
        )

        reasons.append(
            "The URL contains an unusually high number "
            "of numeric characters."
        )

        security_checks.append({

            "name": "Digit Pattern",

            "status": "WARNING",

            "message":
                f"{digits} digits detected"

        })

    else:

        security_checks.append({

            "name": "Digit Pattern",

            "status": "SAFE",

            "message":
                f"{digits} digits detected"

        })


    # ========================================================
    # 6. OBFUSCATION CHECK
    # ========================================================

    obfuscated = sum(
        url.count(c)
        for c in ["@", "%"]
    )


    if obfuscated > 0:

        indicators.append(
            "Possible URL obfuscation detected"
        )

        reasons.append(
            "Special encoding characters such as @ or % "
            "were detected in the URL."
        )

        security_checks.append({

            "name": "URL Obfuscation",

            "status": "WARNING",

            "message":
                "Possible encoding/obfuscation detected"

        })

    else:

        security_checks.append({

            "name": "URL Obfuscation",

            "status": "SAFE",

            "message":
                "No obvious obfuscation detected"

        })


    # ========================================================
    # 7. SPECIAL CHARACTER CHECK
    # ========================================================

    special_chars = sum(
        not c.isalnum()
        for c in url
    )


    if special_chars >= 15:

        indicators.append(
            "Large number of special characters"
        )

        reasons.append(
            "The URL contains many special characters, "
            "which may indicate complex or suspicious URL structure."
        )

        security_checks.append({

            "name": "Special Characters",

            "status": "WARNING",

            "message":
                f"{special_chars} special characters"

        })

    else:

        security_checks.append({

            "name": "Special Characters",

            "status": "SAFE",

            "message":
                f"{special_chars} special characters"

        })


    # ========================================================
    # 8. HTTPS CHECK
    # ========================================================

    uses_https = (
        parsed.scheme.lower() == "https"
    )


    if not uses_https:

        indicators.append(
            "Connection is not using HTTPS"
        )

        reasons.append(
            "The URL does not use HTTPS. "
            "This does not automatically mean phishing, "
            "but HTTPS is recommended for secure websites."
        )

        security_checks.append({

            "name": "HTTPS",

            "status": "WARNING",

            "message":
                "HTTPS is not enabled"

        })

    else:

        security_checks.append({

            "name": "HTTPS",

            "status": "SAFE",

            "message":
                "HTTPS connection detected"

        })


    # ========================================================
    # 9. BRAND IMPERSONATION CHECK
    # ========================================================

    brands = [

        "paypal",
        "google",
        "microsoft",
        "apple",
        "amazon",
        "facebook",
        "instagram",
        "netflix",
        "linkedin",
        "bank"

    ]


    brand_found = []


    for brand in brands:

        if brand in lower_url:

            brand_found.append(brand)


    suspicious_context = [

        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "signin"

    ]


    brand_impersonation = False


    if brand_found:

        if any(
            word in lower_url
            for word in suspicious_context
        ):

            brand_impersonation = True

            indicators.append(

                "Possible brand impersonation detected: "
                + ", ".join(brand_found)

            )

            reasons.append(

                "A known brand name appears together with "
                "login, verification or account-related "
                "language. This pattern can be associated "
                "with impersonation attempts."

            )

            security_checks.append({

                "name": "Brand Impersonation",

                "status": "WARNING",

                "message":
                    "Possible brand impersonation"

            })

        else:

            security_checks.append({

                "name": "Brand Reference",

                "status": "INFO",

                "message":
                    "Brand name detected"

            })

    else:

        security_checks.append({

            "name": "Brand Impersonation",

            "status": "SAFE",

            "message":
                "No obvious brand impersonation pattern"

        })


    # ========================================================
    # 10. DOMAIN STRUCTURE CHECK
    # ========================================================

    domain_structure_warning = False


    if "-" in domain:

        domain_structure_warning = True

        indicators.append(
            "Hyphen detected in domain name"
        )

        reasons.append(
            "The domain contains a hyphen. "
            "Hyphens are legitimate in many domains, "
            "but can also appear in deceptive domain names."
        )

        security_checks.append({

            "name": "Domain Structure",

            "status": "INFO",

            "message":
                "Hyphen found in domain"

        })

    else:

        security_checks.append({

            "name": "Domain Structure",

            "status": "SAFE",

            "message":
                "Normal domain structure"

        })


    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_score = 0


    # Suspicious keywords

    if found_keywords:

        risk_score += min(
            len(found_keywords) * 5,
            20
        )


    # IP

    if is_ip_address:

        risk_score += 20


    # Subdomains

    if subdomains >= 3:

        risk_score += 15


    # URL length

    if len(url) > 100:

        risk_score += 15


    # Digits

    if digits >= 8:

        risk_score += 10


    # Obfuscation

    if obfuscated > 0:

        risk_score += 15


    # Special characters

    if special_chars >= 15:

        risk_score += 10


    # HTTP

    if not uses_https:

        risk_score += 10


    # Brand impersonation

    if brand_impersonation:

        risk_score += 20


    # Limit score

    risk_score = min(
        risk_score,
        100
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    if risk_score <= 30:

        risk_level = "LOW"

    elif risk_score <= 60:

        risk_level = "MEDIUM"

    else:

        risk_level = "HIGH"


    # ========================================================
    # EXPLANATION
    # ========================================================

    if risk_score >= 70:

        explanation = (
            "This URL shows several characteristics "
            "commonly associated with suspicious or "
            "potentially phishing URLs."
        )

    elif risk_score >= 40:

        explanation = (
            "This URL contains some suspicious patterns "
            "that require additional caution."
        )

    else:

        explanation = (
            "This URL does not show many obvious "
            "suspicious patterns based on the current checks."
        )


    # ========================================================
    # RETURN COMPLETE ANALYSIS
    # ========================================================

    return {

        "url": url,

        "domain": domain,

        "url_length": len(url),

        "domain_length": len(domain),

        "subdomains": subdomains,

        "digits": digits,

        "special_chars": special_chars,

        "https": uses_https,

        "ip_address": is_ip_address,

        "obfuscation": obfuscated > 0,

        "found_keywords": found_keywords,

        "brands_found": brand_found,

        "brand_impersonation":
            brand_impersonation,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "indicators": indicators,

        "reasons": reasons,

        "security_checks": security_checks,

        "explanation": explanation

    }