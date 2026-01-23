from urllib.parse import urlparse
import re

def normalize_item(item: str) -> str:
    """
    Normalizes a URL or Domain into a clean domain or IP address.
    - Removes protocol (http, https)
    - Removes paths, query parameters
    - Converts to lowercase
    - Removes trailing slashes
    """
    if not item:
        return ""

    item = item.strip().lower()

    # If it doesn't start with http/https, urlparse might treat it as path
    # prepend http:// to parse it correctly if scheme is missing
    if not item.startswith(('http://', 'https://')):
        # Check if it's just an IP or domain
        # If it contains '/', it might be path, e.g. "example.com/bad"
        if '/' in item:
            item = 'http://' + item

    try:
        parsed = urlparse(item)
        domain = parsed.netloc or parsed.path  # if scheme was missing and we didn't add it

        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]

        return domain.strip()
    except Exception:
        return ""

def is_valid_domain_or_ip(item: str) -> bool:
    """
    Basic validation to ensure the item looks like a domain or IP.
    """
    if not item or len(item) > 253:
        return False

    # Regex for basic domain/IP validation
    # Allow dots, hyphens, alphanumeric
    # Simple check: no spaces, at least one dot (unless localhost which we filter anyway)
    if ' ' in item or '.' not in item:
        return False

    return True
