"""Domain verification via DNS TXT records."""



from urllib.parse import urlparse



import dns.resolver





def target_hostname(base_url: str) -> str | None:

    return urlparse(base_url).hostname





def verification_instructions(target_id: str, domain: str) -> dict:

    return {

        "method": "dns_txt",

        "record_name": f"_orchestrasec.{domain}",

        "record_value": f"verify-{target_id}",

        "message": "Add the TXT record below, then call POST /targets/{id}/verify.",

    }





def expected_txt_value(target_id: str) -> str:

    return f"verify-{target_id}"





def check_dns_txt_verification(domain: str, target_id: str) -> bool:

    record_name = f"_orchestrasec.{domain}"

    expected = expected_txt_value(target_id)

    try:

        answers = dns.resolver.resolve(record_name, "TXT")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):

        return False

    except Exception:

        return False



    for rdata in answers:

        for txt_string in rdata.strings:

            value = txt_string.decode("utf-8") if isinstance(txt_string, bytes) else str(txt_string)

            if value.strip('"') == expected or value == expected:

                return True

    return False





def can_scan_unverified_target() -> bool:

    return False


