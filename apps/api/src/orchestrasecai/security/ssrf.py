import ipaddress

import socket

from urllib.parse import urlparse



BLOCKED_NETWORKS = [

    ipaddress.ip_network("10.0.0.0/8"),

    ipaddress.ip_network("172.16.0.0/12"),

    ipaddress.ip_network("192.168.0.0/16"),

    ipaddress.ip_network("127.0.0.0/8"),

    ipaddress.ip_network("169.254.0.0/16"),

    ipaddress.ip_network("::1/128"),

    ipaddress.ip_network("fc00::/7"),

    ipaddress.ip_network("fe80::/10"),

]





class SSRFError(ValueError):

    """Target URL failed SSRF safety checks."""





def _is_blocked_ip(ip_str: str) -> bool:

    try:

        addr = ipaddress.ip_address(ip_str)

    except ValueError:

        return True

    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:

        return True

    return any(addr in net for net in BLOCKED_NETWORKS)





def validate_target_url(url: str) -> None:

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):

        raise SSRFError("Only http/https URLs allowed")

    if not parsed.hostname:

        raise SSRFError("Invalid URL hostname")

    try:

        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))

    except socket.gaierror as exc:

        raise SSRFError("Cannot resolve hostname") from exc

    for info in infos:

        ip = info[4][0]

        if _is_blocked_ip(ip):

            raise SSRFError("Target resolves to a blocked private or reserved IP range")


