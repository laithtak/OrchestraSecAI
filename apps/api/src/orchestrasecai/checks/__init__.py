from orchestrasecai.checks.cookie_check import CookieCheck
from orchestrasecai.checks.disclosure_check import DisclosureCheck
from orchestrasecai.checks.header_check import HeaderCheck
from orchestrasecai.checks.tls_check import TLSCheck

BUILTIN_CHECKS = [HeaderCheck, CookieCheck, TLSCheck, DisclosureCheck]
