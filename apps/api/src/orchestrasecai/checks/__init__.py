from orchestrasecai.checks.clickjacking_check import ClickjackingCheck
from orchestrasecai.checks.cookie_check import CookieCheck
from orchestrasecai.checks.cors_check import CorsCheck
from orchestrasecai.checks.csp_quality_check import CspQualityCheck
from orchestrasecai.checks.disclosure_check import DisclosureCheck
from orchestrasecai.checks.header_check import HeaderCheck
from orchestrasecai.checks.jwt_check import JWTCheck
from orchestrasecai.checks.open_redirect_check import OpenRedirectCheck
from orchestrasecai.checks.s3_exposure_check import S3ExposureCheck
from orchestrasecai.checks.subdomain_enum_check import SubdomainEnumCheck
from orchestrasecai.checks.tech_fingerprint_check import TechFingerprintCheck
from orchestrasecai.checks.tls_check import TLSCheck

BUILTIN_CHECKS = [
    HeaderCheck,
    CookieCheck,
    TLSCheck,
    DisclosureCheck,
    CorsCheck,
    TechFingerprintCheck,
    CspQualityCheck,
    OpenRedirectCheck,
    JWTCheck,
    SubdomainEnumCheck,
    S3ExposureCheck,
    ClickjackingCheck,
]
