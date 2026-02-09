import hashlib


def sha256(data: bytes) -> bytes:
    """
    Compute SHA256 hash of data.

    Args:
        data: Bytes to hash

    Returns:
        SHA256 digest as bytes
    """
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()


def double_sha256(data: bytes) -> bytes:
    """
    Compute double SHA256 hash of data.

    Args:
        data: Bytes to hash.

    Returns:
        SHA256(SHA256(data)) digest.
    """
    return sha256(sha256(data))


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """
    Compute BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).

    Args:
        tag: Tag string for the hash
        msg: Message bytes to hash

    Returns:
        Tagged hash digest as bytes
    """
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + msg)
