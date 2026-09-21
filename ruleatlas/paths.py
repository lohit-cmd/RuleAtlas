"""Portable local names; original publisher paths remain the provenance authority."""
import hashlib
import re
from pathlib import PurePosixPath


def portable_relative_path(relative):
    parts = PurePosixPath(relative).parts
    if not parts or relative.startswith('/') or '..' in parts or '\\' in relative:
        raise ValueError('Unsafe repository-relative path')
    result = []
    for part in parts:
        encoded = ''.join(f'%{ord(c):02X}' if c in '<>:"\\|?*%' or ord(c)<32 else c for c in part)
        if encoded.endswith(('.', ' ')):
            encoded = encoded[:-1] + f'%{ord(encoded[-1]):02X}'
        if re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', encoded):
            encoded = f'%{ord(encoded[0]):02X}' + encoded[1:]
        if len(encoded) > 220:
            encoded = hashlib.sha256(part.encode()).hexdigest() + PurePosixPath(encoded).suffix[:16]
        result.append(encoded)
    return '/'.join(result)
