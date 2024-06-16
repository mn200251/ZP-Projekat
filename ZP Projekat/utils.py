import base64
import re
import gzip
import io


def encode_radix64(data):
    return base64.b64encode(data).decode('ascii')


def radix64_decode(s):
    return base64.b64decode(s)


def is_radix64(s):
    # Check if the string length is a multiple of 4
    if len(s) % 4 != 0:
        return False

    # Check if the string contains only valid Base64 characters
    base64_pattern = re.compile('^[A-Za-z0-9+/]*={0,2}$')
    if not base64_pattern.match(s):
        return False

    try:
        # Try to decode the string
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def zip_data(data):
    return gzip.compress(data)


def unzip_data(data):
    return gzip.decompress(data)


def is_gzipped(data):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            f.read()
        return True
    except gzip.BadGzipFile:
        return False
    except OSError:
        return False
    