from urllib.parse import urlparse
import ipaddress


def validar_url_segura(url: str) -> bool:
    parsed = urlparse(url)

    if parsed.scheme not in ["https"]:
        raise ValueError("SSRF bloqueado: solo se permite HTTPS.")

    host = parsed.hostname

    if not host:
        raise ValueError("SSRF bloqueado: URL sin host válido.")

    hosts_bloqueados = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254"
    ]

    if host in hosts_bloqueados:
        raise ValueError("SSRF bloqueado: host interno o sensible.")

    try:
        ip = ipaddress.ip_address(host)

        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("SSRF bloqueado: IP privada o interna.")

    except ValueError:
        pass

    return True
