import hashlib
import os
from pathlib import Path
from typing import Callable, Dict, Optional

import gnupg


def __default_gpg_home() -> Optional[Path]:
    """
    __defaultGpgHome tries to load the variable 'GPG_HOME' or to guess it
    """
    manual = os.getenv("GPG_HOME")
    if manual:
        return Path(manual)
    home = os.getenv("HOME")
    if home:
        return Path(home) / ".gnupg"
    return None


def gpg_sha256sums(
    hash_file: Path, gpg_home: Optional[Path] = __default_gpg_home()
) -> Dict[str, str]:
    """
    gpg_sha256sums verifies given hash_file with a asc file

    This functions assumes that the asc file is in the same directory as the
    hashfile and has the same name but with the suffix '.asc'
    """
    if not gpg_home:
        raise Exception("no gpg_home set")
    gpg = gnupg.GPG(gnupghome=f"{gpg_home.absolute()}")
    if not hash_file.is_file():
        raise Exception(f"{hash_file.absolute()} is not a file")
    asc_path = hash_file.parent / f"{hash_file.name}.asc"
    if not asc_path.is_file():
        raise Exception(f"{asc_path.absolute()} is not a file")
    with asc_path.open(mode="rb") as f:
        verified = gpg.verify_file(f, f"{hash_file.absolute()}")
        if not verified:
            raise Exception(f"verification of {hash_file.absolute()} failed")
        result = {}
        with hash_file.open() as f:
            hsum, fname = tuple(f.readline().split("  "))
            # the second part can contain a newline
            result[hsum] = fname.strip()
        return result


def create_verify(sha256sums: Dict[str, str]) -> Callable[[Path], bool]:
    """
    create_verify is returning a closure based on the sha256sums.

    This allows to load sha256sums and verify there instead of verifying and
    loading on each verification request.
    """

    def verify(advisory_path: Path) -> bool:
        s256h = hashlib.sha256()
        if not advisory_path.is_file():
            return False

        with advisory_path.open(mode="rb") as f:
            for hash_file_bytes in iter(lambda: f.read(1024), b""):
                s256h.update(hash_file_bytes)
        hash_sum = s256h.hexdigest()
        assumed_name = sha256sums.get(hash_sum)
        if not assumed_name:
            return False
        return assumed_name == advisory_path.name

    return verify
