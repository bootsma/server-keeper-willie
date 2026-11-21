#!/usr/bin/env python3
"""
luks_backup.py - LUKS header + key backup and verification.

Python 3.8+, standard library only. Must run as root.
External tools: cryptsetup, lsblk (util-linux)
Optional:       mount.cifs (cifs-utils), systemd-cryptenroll, gpg (gnupg2), runuser

Layout (UI-callable core, thin CLI on top)
    Config / CifsConfig / DeviceOverride   JSON-backed settings
    Prompter                               interaction interface (ConsolePrompter for CLI;
                                           base class = non-interactive; subclass for a GUI)
    reporter callable(level, message)      progress/log callback
    GpgKeyring                             thin gpg wrapper (dedicated keyring or a user's keyring)
    LuksBackupService                      discover() / verify() / backup() / configure() /
                                           configure_cifs() / test_cifs() / configure_gpg() / gpg_status()
    main()                                 argparse CLI

Commands
    run         (default) full backup: headers, dumps, keyfiles, crypttab -> dated dir (+ CIFS)
    verify      validate keyfiles / passphrases only, write nothing
    discover    list LUKS devices, keyslots, tokens, crypttab matches
    configure   interactive setup wizard; saves JSON config
    cifs-setup  interactive CIFS-only setup; tests mount + write, retries until OK; saves config
    cifs-test   test the configured CIFS share (mount, write/delete test file, unmount)
    gpg-setup   interactive archive-encryption setup (generate key / use your key / import / none)
    gpg-status  show encryption key status and any private-key export still waiting to be moved

Saved passphrases ("escrow")
    When a passphrase/recovery key is verified interactively, it can be saved (root-only, 0400,
    no trailing newline) to /etc/luks-backup/escrow/<uuid>.passphrase. It is then treated like a
    keyfile: re-validated against the device and header backup on every run (detects a changed
    passphrase) and copied into each dated backup (inside the .tar.gpg when encryption is on).

Exit codes: 0 ok, 1 error, 2 completed with warnings, 130 interrupted
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fcntl
import getpass
import glob
import hashlib
import json
import logging
import os
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

__version__ = "1.3.1"

DEFAULT_CONFIG = Path("/etc/luks-backup/config.json")
DEFAULT_CRED = "/etc/luks-backup/cifs.cred"
DEFAULT_GPG_HOME = "/etc/luks-backup/gnupg"
LOCK_PATH = "/run/luks-backup.lock"
CRYPTTAB_FILES = ("/etc/crypttab", "/etc/crypttab.initramfs")
KEYS_D_DIRS = ("/etc/cryptsetup-keys.d", "/run/cryptsetup-keys.d")
DEFAULT_KEY_GLOBS = [
    "/root/*.key", "/root/.*key*", "/root/*keyfile*",
    "/etc/luks-keys/*", "/etc/keys/*", "/etc/cryptsetup-keys.d/*",
]
MAX_KEYFILE_BYTES = 8 * 1024 * 1024
TS_FMT = "%Y%m%d-%H%M%S"
TS_RE = re.compile(r"^(\d{8}-\d{6})")
EXIT_OK, EXIT_ERROR, EXIT_WARN = 0, 1, 2
PASS_SLOT = "passphrase/keyfile"
TOKEN_LABELS = {
    "systemd-tpm2": "tpm2",
    "systemd-recovery": "recovery-key",
    "systemd-fido2": "fido2",
    "systemd-pkcs11": "pkcs11",
    "clevis": "clevis",
}
CIFS_HINTS = [
    (r"error\(13\)|Permission denied", "bad username/password/domain, or no access to the share/subfolder; "
     "try adding domain=<DOMAIN> to the credentials file"),
    (r"error\(95\)|not supported", "server rejected an option: remove 'seal' or try vers=3.1.1 / vers=2.1"),
    (r"error\(2\)|No such file", "share or subfolder path does not exist on the server"),
    (r"error\(112\)|Host is down|error\(115\)|error\(110\)|timed out",
     "server unreachable: check VPN/network, hostname/IP, and that port 445 is open"),
    (r"error\(22\)|Invalid argument", "malformed mount option or unsupported vers=; check mount_options"),
    (r"mount.cifs not found", "sudo apt install cifs-utils"),
    (r"Read-only|error\(30\)", "mounted but not writable: check share/folder write permission"),
    (r"credentials file not found", "create it (username=/password=) or rerun cifs-setup"),
]

log = logging.getLogger("luks_backup")
log.addHandler(logging.NullHandler())
Reporter = Callable[[str, str], None]


class BackupError(Exception):
    """Fatal error for the current operation."""


class PromptUnavailable(BackupError):
    """Raised when input is needed but the prompter is non-interactive."""


# --------------------------------------------------------------------------- config
def _from_dict(cls, d):
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in (d or {}).items() if k in names})


@dataclass
class CifsConfig:
    enabled: bool = False
    share: str = ""                       # //server/share[/subfolder]
    subdir: str = "luks-backups"          # <subdir>/<hostname>/<timestamp> on the share
    credentials_file: str = DEFAULT_CRED  # username=/password=/domain= (mode 0600)
    mount_options: str = "vers=3"         # add ,seal for SMB3 encryption if the server supports it


@dataclass
class DeviceOverride:
    keyfiles: List[str] = field(default_factory=list)  # extra keyfiles to test for this UUID
    no_keyfile_ok: bool = False   # passphrase/TPM-only device: don't prompt or warn
    skip: bool = False
    note: str = ""


@dataclass
class Config:
    local_dir: str = "/var/backups/luks"
    keep_local: bool = True
    retention: int = 8                    # backups kept per destination (0 = keep all)
    keyfile_globs: List[str] = field(default_factory=lambda: list(DEFAULT_KEY_GLOBS))
    gpg_recipient: str = ""               # key fingerprint; if set, only an encrypted .tar.gpg goes to CIFS
    gpg_home: str = DEFAULT_GPG_HOME      # dedicated keyring holding the recipient's PUBLIC key
    log_file: str = "/var/log/luks-backup.log"
    cifs: CifsConfig = field(default_factory=CifsConfig)
    devices: Dict[str, DeviceOverride] = field(default_factory=dict)  # keyed by LUKS UUID

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        d = dict(d or {})
        cifs = _from_dict(CifsConfig, d.pop("cifs", {}))
        devs = {k.lower(): _from_dict(DeviceOverride, v) for k, v in (d.pop("devices", {}) or {}).items()}
        cfg = _from_dict(cls, d)
        cfg.cifs, cfg.devices = cifs, devs
        return cfg

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def load(cls, path) -> "Config":
        with open(path) as f:
            return cls.from_dict(json.load(f))

    def save(self, path) -> None:
        path = Path(path)
        _mkdir_private(path.parent)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        os.chmod(path, 0o600)

    def override(self, uuid: str) -> DeviceOverride:
        return self.devices.get(uuid.lower()) or DeviceOverride()

    def override_rw(self, uuid: str) -> DeviceOverride:
        return self.devices.setdefault(uuid.lower(), DeviceOverride())

    @property
    def gpg_export_dir(self) -> Path:
        return Path(self.gpg_home).parent / "key-export"

    @property
    def escrow_dir(self) -> Path:
        return Path(self.gpg_home).parent / "escrow"


# --------------------------------------------------------------------------- UI interfaces
class Prompter:
    """Base = non-interactive. Subclass and set interactive=True for CLI/GUI."""
    interactive = False

    def text(self, message: str, default: Optional[str] = None) -> str:
        raise PromptUnavailable(message)

    def secret(self, message: str) -> str:
        raise PromptUnavailable(message)

    def confirm(self, message: str, default: bool = False) -> bool:
        raise PromptUnavailable(message)

    def choose(self, message: str, options: List[Tuple[str, str]], default: Optional[str] = None) -> str:
        raise PromptUnavailable(message)


class ConsolePrompter(Prompter):
    """Prompts on stderr so stdout stays clean for --json."""
    interactive = True

    @staticmethod
    def _ask(msg: str) -> str:
        sys.stderr.write(msg)
        sys.stderr.flush()
        return input().strip()

    def text(self, message, default=None):
        sfx = f" [{default}]" if default not in (None, "") else ""
        return self._ask(f"{message}{sfx}: ") or (default or "")

    def secret(self, message):
        return getpass.getpass(f"{message}: ", stream=sys.stderr)

    def confirm(self, message, default=False):
        ans = self._ask(f"{message} [{'Y/n' if default else 'y/N'}]: ").lower()
        return default if not ans else ans in ("y", "yes")

    def choose(self, message, options, default=None):
        keys = [k for k, _ in options]
        sys.stderr.write(message + "\n")
        for k, label in options:
            sys.stderr.write(f"  [{k}] {label}\n")
        while True:
            ans = self._ask(f"Choice{f' [{default}]' if default else ''}: ").lower() or (default or "")
            if ans in keys:
                return ans


def console_reporter(verbose: bool = False) -> Reporter:
    def _r(level: str, msg: str) -> None:
        if level == "debug" and not verbose:
            return
        prefix = {"warning": "WARNING: ", "error": "ERROR: ", "debug": "debug: "}.get(level, "")
        sys.stderr.write(f"{prefix}{msg}\n")
    return _r


# --------------------------------------------------------------------------- results
@dataclass
class CrypttabEntry:
    source: str
    name: str
    device: str
    keyfile: Optional[str]
    options: Dict[str, Optional[str]] = field(default_factory=dict)

    def _int_opt(self, *names) -> Optional[int]:
        for n in names:
            v = self.options.get(n)
            if v and v.isdigit():
                return int(v)
        return None

    @property
    def keyfile_offset(self):
        return self._int_opt("keyfile-offset")

    @property
    def keyfile_size(self):
        return self._int_opt("keyfile-size")


@dataclass
class LuksDevice:
    path: str
    uuid: str
    size: str = ""
    mapped_name: Optional[str] = None
    luks_version: Optional[int] = None
    keyslots: List[int] = field(default_factory=list)
    tokens: List[dict] = field(default_factory=list)
    slot_types: Dict[int, str] = field(default_factory=dict)
    crypttab: Optional[CrypttabEntry] = None

    @property
    def base_name(self) -> str:
        return f"{_safe(os.path.basename(self.path))}_{self.uuid}"


@dataclass
class KeyCandidate:
    path: str
    source: str
    offset: Optional[int] = None
    size: Optional[int] = None


@dataclass
class KeyResult:
    path: str
    source: str
    ok: bool = False
    slot: Optional[int] = None
    header_ok: Optional[bool] = None
    sha256: str = ""
    size: int = 0
    keyfile_offset: Optional[int] = None
    keyfile_size: Optional[int] = None
    backup_file: str = ""
    message: str = ""


@dataclass
class DeviceResult:
    device: str
    uuid: str
    size: str = ""
    mapped_name: Optional[str] = None
    crypttab_name: Optional[str] = None
    luks_version: Optional[int] = None
    slot_types: Dict[str, str] = field(default_factory=dict)
    header_file: str = ""
    header_sha256: str = ""
    header_verified: bool = False
    keys: List[KeyResult] = field(default_factory=list)
    passphrase_checks: List[dict] = field(default_factory=list)
    verified_slots: List[int] = field(default_factory=list)
    unverified_slots: List[int] = field(default_factory=list)
    status: str = "ok"
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class BackupOptions:
    devices: List[str] = field(default_factory=list)  # filter: path, UUID or mapper name
    check_passphrases: bool = False                    # interactively test a passphrase per device
    write: bool = True                                 # False = verify only


@dataclass
class BackupReport:
    tool_version: str = __version__
    host: str = ""
    timestamp: str = ""
    started: str = ""
    finished: str = ""
    mode: str = "backup"
    staging_dir: str = ""
    destinations: List[dict] = field(default_factory=list)
    devices: List[DeviceResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    status: str = "ok"
    exit_code: int = EXIT_OK

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GpgKeyInfo:
    fingerprint: str
    uid: str
    created: str = ""
    expires: str = ""
    can_encrypt: bool = False
    has_secret: bool = False


@dataclass
class GpgStatus:
    enabled: bool
    recipient: str = ""
    key: Optional[GpgKeyInfo] = None
    key_present: bool = False
    encrypt_test_ok: bool = False
    secret_on_machine: bool = False        # private key still inside the dedicated keyring
    pending_exports: List[str] = field(default_factory=list)  # *.SECRET.asc waiting to be moved
    public_key_file: str = ""
    message: str = ""


# --------------------------------------------------------------------------- helpers
def _run(cmd: List[str], input_bytes: Optional[bytes] = None, timeout: int = 300) -> Tuple[int, str, str]:
    log.debug("exec: %s", " ".join(cmd))
    kw = {"input": input_bytes} if input_bytes is not None else {"stdin": subprocess.DEVNULL}
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **kw)
    except FileNotFoundError:
        raise BackupError(f"required command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def _run_bytes(cmd: List[str], input_bytes: Optional[bytes] = None, timeout: int = 300) -> Tuple[int, bytes, str]:
    log.debug("exec: %s", " ".join(cmd))
    kw = {"input": input_bytes} if input_bytes is not None else {"stdin": subprocess.DEVNULL}
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **kw)
    except FileNotFoundError:
        raise BackupError(f"required command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return 124, b"", f"timed out after {timeout}s"
    return p.returncode, p.stdout, p.stderr.decode(errors="replace")


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "x"


def _mkdir_private(path) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _write_private(path, data) -> None:
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_cifs_credentials(path: str, username: str, password: str, domain: str = "") -> None:
    if "\n" in username + password + domain:
        raise BackupError("credentials may not contain newlines")
    _mkdir_private(Path(path).parent)
    body = f"username={username}\npassword={password}\n" + (f"domain={domain}\n" if domain else "")
    _write_private(path, body)


def read_cifs_username(path: str) -> str:
    try:
        for line in Path(path).read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip().lower() in ("username", "user"):
                return v.strip()
    except OSError:
        pass
    return ""


def parse_crypttab(path: str) -> List[CrypttabEntry]:
    try:
        text = Path(path).read_text()
    except (FileNotFoundError, PermissionError):
        return []
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        kf = parts[2] if len(parts) > 2 else None
        if kf in ("none", "-", ""):
            kf = None
        opts: Dict[str, Optional[str]] = {}
        if len(parts) > 3:
            for o in parts[3].split(","):
                k, sep, v = o.partition("=")
                opts[k] = v if sep else None
        out.append(CrypttabEntry(path, parts[0], parts[1], kf, opts))
    return out


def resolve_dev_spec(spec: str) -> Optional[str]:
    s = spec.strip().strip('"')
    for prefix, d in (("UUID=", "by-uuid"), ("PARTUUID=", "by-partuuid"),
                      ("LABEL=", "by-label"), ("PARTLABEL=", "by-partlabel")):
        if s.upper().startswith(prefix):
            p = f"/dev/disk/{d}/{s[len(prefix):].strip(chr(34))}"
            return os.path.realpath(p) if os.path.exists(p) else None
    return os.path.realpath(s) if s.startswith("/dev/") else None


def parse_luks_dump_text(txt: str) -> dict:
    """Fallback parser for `cryptsetup luksDump` text (LUKS1 and LUKS2)."""
    info = {"version": None, "keyslots": [], "tokens": []}
    m = re.search(r"^Version:\s*(\d+)", txt, re.M)
    if m:
        info["version"] = int(m.group(1))
    for m in re.finditer(r"^Key Slot (\d+): ENABLED", txt, re.M):  # LUKS1
        info["keyslots"].append(int(m.group(1)))
    section, tok = None, None
    for line in txt.splitlines():
        if line and not line[0].isspace():
            section, tok = line.strip().rstrip(":"), None
            continue
        if section == "Keyslots":
            m = re.match(r"^ {2}(\d+): ", line)
            if m:
                info["keyslots"].append(int(m.group(1)))
        elif section == "Tokens":
            m = re.match(r"^ {2}(\d+): (\S+)", line)
            if m:
                tok = {"id": int(m.group(1)), "type": m.group(2), "keyslots": []}
                info["tokens"].append(tok)
                continue
            m = re.match(r"^\s+Keyslot:\s+(\d+)", line)
            if m and tok is not None:
                tok["keyslots"].append(int(m.group(1)))
    info["keyslots"] = sorted(set(info["keyslots"]))
    return info


def on_encrypted_storage(path: str) -> Optional[bool]:
    """True if the filesystem holding `path` sits on a dm-crypt device; None if unknown."""
    try:
        rc, out, _ = _run(["findmnt", "-n", "-o", "SOURCE", "--target", path])
        src = out.strip().split("[")[0]
        if rc or not src.startswith("/dev/"):
            return None
        rc, out, _ = _run(["lsblk", "-s", "-n", "-o", "TYPE", src])
        return None if rc else ("crypt" in out.split())
    except BackupError:
        return None


class _RunLock:
    def __enter__(self):
        self.f = open(LOCK_PATH, "w")
        try:
            fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.f.close()
            raise BackupError("another luks_backup run is in progress")
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


class CifsMount:
    """Context manager: mounts the share on a private temp dir, always unmounts."""

    def __init__(self, cfg: CifsConfig, emit: Reporter):
        self.cfg, self.emit, self.mnt = cfg, emit, None

    def __enter__(self) -> Path:
        if not shutil.which("mount.cifs"):
            raise BackupError("mount.cifs not found (install cifs-utils)")
        if not self.cfg.share:
            raise BackupError("CIFS enabled but no share configured")
        cred = Path(self.cfg.credentials_file)
        if not cred.is_file():
            raise BackupError(f"CIFS credentials file not found: {cred}")
        if cred.stat().st_mode & 0o077:
            self.emit("warning", f"{cred} is group/world accessible; chmod 600 recommended")
        self.mnt = tempfile.mkdtemp(prefix="luks-backup-cifs-")
        # fixed root-only ownership first; user options appended (do not add uid/gid/*_mode there)
        opts = f"credentials={cred},uid=0,gid=0,file_mode=0600,dir_mode=0700"
        if self.cfg.mount_options:
            opts += "," + self.cfg.mount_options.strip(",")
        self.emit("debug", f"mount -t cifs {self.cfg.share} {self.mnt} -o {opts}")
        rc, _, err = _run(["mount", "-t", "cifs", self.cfg.share, self.mnt, "-o", opts], timeout=90)
        if rc:
            os.rmdir(self.mnt)
            self.mnt = None
            raise BackupError(f"CIFS mount of {self.cfg.share} failed: {err.strip()}")
        return Path(self.mnt)

    def __exit__(self, *exc):
        if not self.mnt:
            return
        rc, _, err = _run(["umount", self.mnt], timeout=60)
        if rc:
            self.emit("warning", f"umount failed ({err.strip()}); lazy unmounting")
            _run(["umount", "-l", self.mnt], timeout=60)
        try:
            os.rmdir(self.mnt)
        except OSError:
            pass


# --------------------------------------------------------------------------- GPG
class GpgKeyring:
    """
    Minimal gpg wrapper.
      GpgKeyring(home)                    dedicated root-owned keyring (default /etc/luks-backup/gnupg)
      GpgKeyring(home, run_as="greg")     a user's own keyring, accessed AS that user (read-only use)
    """

    def __init__(self, home: str, run_as: Optional[str] = None):
        self.home, self.run_as = home, run_as

    @classmethod
    def for_user(cls, user: str) -> "GpgKeyring":
        return cls(os.path.join(pwd.getpwnam(user).pw_dir, ".gnupg"), run_as=user)

    def _cmd(self, args: List[str], passphrase: bool = False) -> List[str]:
        if not shutil.which("gpg"):
            raise BackupError("gpg not found (sudo apt install gnupg)")
        cmd = ["gpg", "--homedir", self.home, "--batch", "--no-tty", "--quiet"]
        if passphrase:
            cmd += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
        cmd += args
        if self.run_as:
            cmd = ["runuser", "-u", self.run_as, "--"] + cmd
        return cmd

    def run(self, args: List[str], passphrase: Optional[str] = None,
            input_bytes: Optional[bytes] = None) -> Tuple[int, bytes, str]:
        if passphrase is not None:
            input_bytes = passphrase.encode() + b"\n" + (input_bytes or b"")
        return _run_bytes(self._cmd(args, passphrase is not None), input_bytes=input_bytes)

    def ensure_home(self) -> None:
        if not self.run_as:
            _mkdir_private(self.home)

    def list_keys(self, secret: bool = False) -> List[GpgKeyInfo]:
        if not os.path.isdir(self.home):
            return []
        rc, out, _ = self.run(["--with-colons", "--fixed-list-mode",
                               "--list-secret-keys" if secret else "--list-keys"])
        if rc:
            return []
        keys, cur, want_fpr = [], None, False
        for line in out.decode(errors="replace").splitlines():
            f = line.split(":")
            if f[0] in ("pub", "sec"):
                cur = GpgKeyInfo("", "", created=_ts(f[5]), expires=_ts(f[6]),
                                 can_encrypt="E" in f[11] and f[1] not in ("r", "e", "i", "d"))
                keys.append(cur)
                want_fpr = True
            elif f[0] == "fpr" and cur is not None and want_fpr:
                cur.fingerprint, want_fpr = f[9], False
            elif f[0] == "uid" and cur is not None and not cur.uid:
                cur.uid = f[9]
        if not secret:
            sec = {k.fingerprint for k in self.list_keys(secret=True)}
            for k in keys:
                k.has_secret = k.fingerprint in sec
        return keys

    def get(self, fpr: str) -> Optional[GpgKeyInfo]:
        fpr = fpr.upper()
        return next((k for k in self.list_keys() if k.fingerprint.upper() == fpr), None)

    def generate(self, uid: str, passphrase: str) -> str:
        self.ensure_home()
        rc, _, err = self.run(["--quick-gen-key", uid, "default", "default", "never"], passphrase=passphrase)
        if rc:
            raise BackupError(f"gpg key generation failed: {err.strip()}")
        k = next((k for k in self.list_keys() if k.uid == uid), None)
        if not k:
            raise BackupError("generated key not found in keyring")
        return k.fingerprint

    def export_public(self, fpr: str) -> bytes:
        rc, out, err = self.run(["--armor", "--export", fpr])
        if rc or not out.strip():
            raise BackupError(f"public key export failed: {err.strip()}")
        return out

    def export_secret(self, fpr: str, passphrase: str) -> bytes:
        rc, out, err = self.run(["--armor", "--export-secret-keys", fpr], passphrase=passphrase)
        if rc or b"PRIVATE KEY" not in out:
            raise BackupError(f"private key export failed: {err.strip()}")
        return out

    def import_public(self, data: bytes) -> List[str]:
        if b"PRIVATE KEY BLOCK" in data:
            raise BackupError("that file contains a PRIVATE key - import the public key (.pub.asc) only")
        self.ensure_home()
        before = {k.fingerprint for k in self.list_keys()}
        rc, _, err = self.run(["--import"], input_bytes=data)
        if rc:
            raise BackupError(f"gpg import failed: {err.strip()}")
        new = [k.fingerprint for k in self.list_keys() if k.fingerprint not in before]
        return new or [k.fingerprint for k in self.list_keys()]

    def delete_secret(self, fpr: str) -> None:
        rc, _, err = self.run(["--yes", "--delete-secret-keys", fpr])
        if rc:
            raise BackupError(f"could not remove private key from keyring: {err.strip()}")

    def delete_key(self, fpr: str) -> None:
        self.run(["--yes", "--delete-secret-and-public-key", fpr])

    def encrypt_file(self, recipient: str, src: str, dst: str) -> None:
        rc, _, err = self.run(["--yes", "--trust-model", "always", "--encrypt",
                               "--recipient", recipient, "--output", dst, src])
        if rc:
            raise BackupError(f"gpg encryption failed: {err.strip()}")

    def test_encrypt(self, recipient: str) -> Tuple[bool, str]:
        rc, out, err = self.run(["--trust-model", "always", "--encrypt", "--recipient", recipient,
                                 "--output", "-"], input_bytes=b"luks-backup test")
        return rc == 0 and len(out) > 0, err.strip()

    def roundtrip(self, recipient: str, passphrase: str) -> bool:
        """Encrypt then decrypt with the passphrase: proves key + passphrase work."""
        self.ensure_home()
        ct = os.path.join(self.home, f".rt-{os.getpid()}.gpg")
        try:
            rc, out, _ = self.run(["--trust-model", "always", "--encrypt", "--recipient", recipient,
                                   "--output", "-"], input_bytes=b"roundtrip-ok")
            if rc:
                return False
            _write_private(ct, out)
            rc, pt, _ = self.run(["--decrypt", ct], passphrase=passphrase)
            return rc == 0 and pt == b"roundtrip-ok"
        finally:
            if os.path.exists(ct):
                os.unlink(ct)

    def kill_agent(self) -> None:
        if shutil.which("gpgconf") and not self.run_as:
            _run(["gpgconf", "--homedir", self.home, "--kill", "gpg-agent"])


def _ts(epoch: str) -> str:
    try:
        return dt.datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d") if epoch else ""
    except ValueError:
        return epoch


# --------------------------------------------------------------------------- service
class LuksBackupService:
    def __init__(self, cfg: Config, prompter: Optional[Prompter] = None,
                 reporter: Optional[Reporter] = None, config_path: Optional[Path] = None):
        self.cfg = cfg
        self.prompter = prompter or Prompter()
        self.reporter = reporter or (lambda lvl, msg: None)
        self.config_path = Path(config_path) if config_path else None
        self.config_dirty = False
        self._glob_cache: Optional[List[str]] = None
        self._staging: Optional[Path] = None

    # ---- plumbing
    def emit(self, level: str, msg: str) -> None:
        log.log(getattr(logging, level.upper(), logging.INFO), msg)
        self.reporter(level, msg)

    def save_config(self) -> None:
        if self.config_path:
            self.cfg.save(self.config_path)
            self.config_dirty = False
            self.emit("info", f"Configuration saved to {self.config_path}")

    @staticmethod
    def require_root() -> None:
        if os.geteuid() != 0:
            raise BackupError("must be run as root (sudo)")

    # ---- discovery
    def discover(self) -> List[LuksDevice]:
        rc, out, err = _run(["lsblk", "-J", "-p", "-o", "NAME,TYPE,FSTYPE,UUID,SIZE"])
        if rc:
            raise BackupError(f"lsblk failed: {err.strip()}")
        found: Dict[str, LuksDevice] = {}

        def walk(nodes):
            for n in nodes or []:
                if (n.get("fstype") or "") == "crypto_LUKS":
                    rp = os.path.realpath(n["name"])
                    if rp not in found:
                        mapped = next((c["name"] for c in n.get("children") or []
                                       if c.get("type") == "crypt"), None)
                        found[rp] = LuksDevice(path=n["name"], uuid=(n.get("uuid") or "").lower(),
                                               size=n.get("size") or "",
                                               mapped_name=os.path.basename(mapped) if mapped else None)
                walk(n.get("children"))

        walk(json.loads(out).get("blockdevices"))
        entries = [e for f in CRYPTTAB_FILES for e in parse_crypttab(f)]
        for dev in found.values():
            if not dev.uuid:
                _, o, _ = _run(["cryptsetup", "luksUUID", dev.path])
                dev.uuid = o.strip().lower()
            self._inspect_header(dev)
            dev.crypttab = self._match_crypttab(dev, entries)
        return sorted(found.values(), key=lambda d: d.path)

    def _inspect_header(self, dev: LuksDevice) -> None:
        meta = None
        rc, out, _ = _run(["cryptsetup", "luksDump", "--dump-json-metadata", dev.path])
        if rc == 0:
            try:
                meta = json.loads(out)
            except ValueError:
                meta = None
        if meta:
            dev.luks_version = 2
            dev.keyslots = sorted(int(k) for k in meta.get("keyslots", {}))
            dev.tokens = [{"id": int(k), "type": v.get("type", "?"),
                           "keyslots": [int(s) for s in v.get("keyslots", [])]}
                          for k, v in (meta.get("tokens") or {}).items()]
        else:
            rc, out, err = _run(["cryptsetup", "luksDump", dev.path])
            if rc:
                raise BackupError(f"luksDump {dev.path} failed: {err.strip()}")
            p = parse_luks_dump_text(out)
            dev.luks_version, dev.keyslots, dev.tokens = p["version"], p["keyslots"], p["tokens"]
        dev.slot_types = {s: PASS_SLOT for s in dev.keyslots}
        for t in dev.tokens:
            for s in t["keyslots"]:
                dev.slot_types[s] = TOKEN_LABELS.get(t["type"], t["type"])

    @staticmethod
    def _match_crypttab(dev: LuksDevice, entries: List[CrypttabEntry]) -> Optional[CrypttabEntry]:
        rp = os.path.realpath(dev.path)
        for e in entries:
            spec = e.device.strip('"')
            if spec.upper().startswith("UUID=") and spec[5:].strip('"').lower() == dev.uuid:
                return e
            if resolve_dev_spec(spec) == rp:
                return e
        for e in entries:
            if dev.mapped_name and e.name == dev.mapped_name:
                return e
        return None

    # ---- key handling
    def test_key(self, device: str, keyfile: Optional[str] = None, passphrase: Optional[bytes] = None,
                 header: Optional[str] = None, offset: Optional[int] = None,
                 size: Optional[int] = None) -> Tuple[bool, Optional[int], str]:
        """Non-destructive: cryptsetup open --test-passphrase (no mapping created)."""
        cmd = ["cryptsetup", "open", "--test-passphrase", "--verbose"]
        if header:
            cmd += ["--header", header]
        if offset:
            cmd += ["--keyfile-offset", str(offset)]
        if size:
            cmd += ["--keyfile-size", str(size)]
        cmd += ["--key-file", keyfile if keyfile else "-", device]
        rc, out, err = _run(cmd, input_bytes=passphrase if keyfile is None else None)
        m = re.search(r"Key slot (\d+) unlocked", out + err)
        return rc == 0, (int(m.group(1)) if m else None), (err.strip() or out.strip())[-300:]

    def _candidates(self, dev: LuksDevice, r: DeviceResult) -> List[KeyCandidate]:
        esc = str(self.cfg.escrow_dir) + os.sep
        c: List[KeyCandidate] = [KeyCandidate(p, "escrow" if p.startswith(esc) else "config")
                                 for p in self.cfg.override(dev.uuid).keyfiles]
        ct = dev.crypttab
        if ct and ct.keyfile:
            m = re.match(r"^(.*?):((?:UUID|PARTUUID|LABEL|PARTLABEL)=.*|/dev/.*)$", ct.keyfile)
            if m:
                r.notes.append(f"crypttab keyfile {m.group(1)} lives on external device {m.group(2)}; not checked")
            else:
                c.append(KeyCandidate(ct.keyfile, f"crypttab:{ct.source}", ct.keyfile_offset, ct.keyfile_size))
            if "keyscript" in ct.options:
                r.notes.append(f"crypttab uses keyscript={ct.options['keyscript']}; key may be derived at boot")
        for n in {x for x in (dev.mapped_name, ct.name if ct else None) if x}:
            for d in KEYS_D_DIRS:
                p = os.path.join(d, f"{n}.key")
                if os.path.isfile(p):
                    c.append(KeyCandidate(p, "cryptsetup-keys.d"))
        seen, uniq = set(), []
        for k in c:
            rp = os.path.realpath(k.path)
            if rp not in seen:
                seen.add(rp)
                uniq.append(k)
        return uniq

    def _glob_candidates(self) -> List[str]:
        if self._glob_cache is None:
            excl = [os.path.realpath(self.cfg.local_dir), os.path.realpath(self.cfg.gpg_home),
                    os.path.realpath(self.cfg.gpg_export_dir), os.path.realpath(self.cfg.escrow_dir)]
            if self.config_path:
                excl.append(os.path.realpath(self.config_path.parent))
            res = set()
            for g in self.cfg.keyfile_globs:
                for p in glob.glob(g):
                    rp = os.path.realpath(p)
                    try:
                        st = os.stat(rp)
                    except OSError:
                        continue
                    if (os.path.isfile(rp) and 0 < st.st_size <= MAX_KEYFILE_BYTES
                            and not any(rp.startswith(e + os.sep) for e in excl)):
                        res.add(rp)
            self._glob_cache = sorted(res)
        return self._glob_cache

    def _check_keyfile(self, dev: LuksDevice, cand: KeyCandidate, header: Optional[str],
                       r: DeviceResult) -> KeyResult:
        kr = KeyResult(path=cand.path, source=cand.source,
                       keyfile_offset=cand.offset, keyfile_size=cand.size)
        p = Path(cand.path)
        if not p.is_file():
            kr.message = "file not found"
            return kr
        st = p.stat()
        kr.size = st.st_size
        if st.st_size == 0 or st.st_size > MAX_KEYFILE_BYTES:
            kr.message = f"unexpected size {st.st_size} bytes"
            return kr
        if st.st_mode & 0o077:
            r.warnings.append(f"keyfile {cand.path} is group/world accessible (chmod 400 recommended)")
        kr.ok, kr.slot, msg = self.test_key(dev.path, keyfile=cand.path, offset=cand.offset, size=cand.size)
        kr.message = "unlocks device" if kr.ok else f"rejected: {msg}"
        if kr.ok and header:
            kr.header_ok, _, _ = self.test_key(dev.path, keyfile=cand.path, header=header,
                                               offset=cand.offset, size=cand.size)
            if not kr.header_ok:
                r.warnings.append(f"keyfile {cand.path} unlocks device but NOT the backup header")
        kr.sha256 = sha256_file(p)
        return kr

    def _store_keyfile(self, dev: LuksDevice, kr: KeyResult, r: DeviceResult) -> None:
        if not self._staging:
            return
        for prev in r.keys:  # same content already stored for this device
            if prev is not kr and prev.backup_file and prev.sha256 == kr.sha256:
                kr.backup_file = prev.backup_file
                return
        kdir = self._staging / "keys" / dev.base_name
        _mkdir_private(kdir)
        name = _safe(os.path.basename(kr.path))
        if kr.source == "escrow":
            name = f"passphrase-slot{kr.slot}.txt" if kr.slot is not None else "passphrase.txt"
        dest, i = kdir / name, 1
        while dest.exists():
            dest, i = kdir / f"{name}.{i}", i + 1
        data = Path(kr.path).read_bytes()
        _write_private(dest, data)
        if hashlib.sha256(data).hexdigest() != kr.sha256:
            r.errors.append(f"keyfile {kr.path} changed during backup")
        kr.backup_file = str(dest.relative_to(self._staging))

    def _accept_key(self, dev, kr, r, verified: set) -> None:
        r.keys.append(kr)
        if kr.ok:
            if kr.slot is not None:
                verified.add(kr.slot)
            self._store_keyfile(dev, kr, r)
        elif kr.source.startswith("crypttab"):
            r.warnings.append(f"crypttab keyfile {kr.path} does NOT unlock {dev.path} ({kr.message}) "
                              "- automatic unlock at boot may be broken")
        elif kr.source == "config":
            r.warnings.append(f"configured keyfile {kr.path}: {kr.message}")
        elif kr.source == "escrow":
            r.warnings.append(f"saved passphrase {kr.path} no longer unlocks {dev.path} (passphrase changed or "
                              "slot removed?) - run interactively to save the current one")

    def _prompt_passphrase(self, dev, r, header, verified: set, offer_save: bool = True) -> bool:
        pw = self.prompter.secret(f"Passphrase or recovery key for {dev.path} (input hidden)")
        if not pw:
            return False
        b = pw.encode()
        del pw
        ok, slot, msg = self.test_key(dev.path, passphrase=b)
        hok = self.test_key(dev.path, passphrase=b, header=header)[0] if ok and header else None
        r.passphrase_checks.append({"ok": ok, "slot": slot, "header_ok": hok})
        if ok:
            if slot is not None:
                verified.add(slot)
            self.emit("info", f"  passphrase OK (keyslot {slot})" + ("" if hok in (None, True) else
                                                                    " but NOT valid for backup header"))
            if offer_save:
                self._offer_escrow(dev, r, header, verified, b)
        else:
            self.emit("warning", f"  passphrase rejected: {msg}")
        del b
        return ok

    def _offer_escrow(self, dev, r, header, verified: set, secret_bytes: bytes) -> bool:
        """Optionally save a verified passphrase so every backup includes (and re-checks) it."""
        p, c = self.prompter, self.cfg
        dest = c.escrow_dir / f"{dev.uuid}.passphrase"
        enc = on_encrypted_storage(str(c.escrow_dir.parent))
        where = {True: "on encrypted storage", False: "on UNENCRYPTED storage",
                 None: "on storage of unknown encryption status"}[enc]
        self.emit("info", f"  Saving lets scheduled backups include and re-verify this passphrase.\n"
                          f"  It would be stored root-only (0400) at {dest} ({where})"
                          + (" and only leaves this machine inside the encrypted .tar.gpg."
                             if c.gpg_recipient else
                             ".\n  NOTE: archive encryption is OFF - backups (and the share) will contain it "
                             "in plain text; consider gpg-setup."))
        if enc is False:
            self.emit("warning", "  anyone with physical access to this disk could read the saved passphrase")
        if not p.confirm("Save this passphrase for backups?", enc is not False):
            return False
        _mkdir_private(c.escrow_dir)
        _write_private(dest, secret_bytes)  # no trailing newline: --key-file uses the exact bytes
        os.chmod(dest, 0o400)
        kr = self._check_keyfile(dev, KeyCandidate(str(dest), "escrow"), header, r)
        if not kr.ok:  # should not happen; don't keep a file that doesn't work
            dest.unlink()
            self.emit("error", f"  saved passphrase failed re-check ({kr.message}); not kept")
            return False
        self._accept_key(dev, kr, r, verified)
        ov = c.override_rw(dev.uuid)
        if str(dest) not in ov.keyfiles:
            ov.keyfiles.append(str(dest))
        ov.no_keyfile_ok = False
        self.config_dirty = True
        self.emit("info", f"  passphrase saved and verified (slot {kr.slot}); future runs need no prompt")
        return True

    def _prompt_for_key(self, dev, r, header, verified: set) -> None:
        p = self.prompter
        slots = ", ".join(f"{s}={t}" for s, t in sorted(dev.slot_types.items()))
        resolved = False
        for _ in range(5):
            ch = p.choose(f"\n{dev.path} (UUID {dev.uuid}) - no valid keyfile found. Keyslots: {slots}",
                          [("k", "Enter path to a keyfile"),
                           ("p", "Enter a passphrase / recovery key (verified; you can then save it "
                                 "so backups include it)"),
                           ("s", "Skip key check for this device")], default="s")
            if ch == "k":
                path = p.text("Keyfile path").strip()
                if not path:
                    continue
                kr = self._check_keyfile(dev, KeyCandidate(path, "user"), header, r)
                self._accept_key(dev, kr, r, verified)
                if kr.ok:
                    ov = self.cfg.override_rw(dev.uuid)
                    if path not in ov.keyfiles:
                        ov.keyfiles.append(path)
                        self.config_dirty = True
                    self.emit("info", f"  keyfile OK (keyslot {kr.slot}); remembered in config")
                    return
                self.emit("warning", f"  keyfile {path}: {kr.message}")
            elif ch == "p":
                if self._prompt_passphrase(dev, r, header, verified):
                    if any(k.ok and k.source == "escrow" for k in r.keys):
                        return
                    resolved = True
                    break
            else:
                break
        if p.confirm("Treat this device as passphrase/TPM-only and stop asking for a keyfile?", resolved):
            self.cfg.override_rw(dev.uuid).no_keyfile_ok = True
            self.config_dirty = True

    # ---- per device
    def _process_device(self, dev: LuksDevice, opts: BackupOptions) -> DeviceResult:
        r = DeviceResult(device=dev.path, uuid=dev.uuid, size=dev.size, mapped_name=dev.mapped_name,
                         crypttab_name=dev.crypttab.name if dev.crypttab else None,
                         luks_version=dev.luks_version,
                         slot_types={str(k): v for k, v in sorted(dev.slot_types.items())})
        ov = self.cfg.override(dev.uuid)
        if ov.skip:
            r.status = "skipped"
            r.notes.append("skipped by config")
            return r
        self.emit("info", f"{dev.path}  UUID={dev.uuid}  LUKS{dev.luks_version}  slots: "
                          + (", ".join(f"{k}={v}" for k, v in r.slot_types.items()) or "none"))
        header = None
        if opts.write and self._staging:
            header = self._backup_header(dev, r)

        verified: set = set()
        for cand in self._candidates(dev, r):
            self._accept_key(dev, self._check_keyfile(dev, cand, header, r), r, verified)

        if not any(k.ok for k in r.keys):
            tried = {os.path.realpath(k.path) for k in r.keys}
            for path in self._glob_candidates():
                if path in tried:
                    continue
                kr = self._check_keyfile(dev, KeyCandidate(path, "search"), header, r)
                if kr.ok:
                    self._accept_key(dev, kr, r, verified)
                    self.cfg.override_rw(dev.uuid).keyfiles.append(path)
                    self.config_dirty = True
                    r.notes.append(f"found keyfile by search: {path} (added to config)")
                    break

        if not any(k.ok for k in r.keys):
            if self.prompter.interactive and not ov.no_keyfile_ok:
                self._prompt_for_key(dev, r, header, verified)
            ov = self.cfg.override(dev.uuid)
            if not any(k.ok for k in r.keys):
                if ov.no_keyfile_ok:
                    r.notes.append("no keyfile expected (no_keyfile_ok)")
                elif not r.passphrase_checks or not any(c["ok"] for c in r.passphrase_checks):
                    r.warnings.append("no valid keyfile found and no passphrase verified "
                                      "(run interactively or set devices.<uuid>.no_keyfile_ok)")

        if opts.check_passphrases and self.prompter.interactive and not r.passphrase_checks:
            self._prompt_passphrase(dev, r, header, verified)

        r.verified_slots = sorted(verified)
        r.unverified_slots = [s for s, t in sorted(dev.slot_types.items())
                              if t == PASS_SLOT and s not in verified]
        if dev.keyslots and not any(t in (PASS_SLOT, "recovery-key") for t in dev.slot_types.values()):
            r.warnings.append("no passphrase/keyfile/recovery keyslot: device depends solely on "
                              + "/".join(sorted(set(dev.slot_types.values()))) + " - add a recovery key")
        r.status = "error" if r.errors else ("warning" if r.warnings else "ok")
        for w in r.warnings:
            self.emit("warning", f"  {w}")
        for e in r.errors:
            self.emit("error", f"  {e}")
        return r

    def _backup_header(self, dev: LuksDevice, r: DeviceResult) -> Optional[str]:
        hdr = self._staging / "headers" / f"{dev.base_name}.luksheader.img"
        rc, _, err = _run(["cryptsetup", "luksHeaderBackup", dev.path, "--header-backup-file", str(hdr)])
        if rc:
            r.errors.append(f"luksHeaderBackup failed: {err.strip()}")
            return None
        os.chmod(hdr, 0o600)
        r.header_file = str(hdr.relative_to(self._staging))
        r.header_sha256 = sha256_file(hdr)
        rc, out, err = _run(["cryptsetup", "luksDump", str(hdr)])
        m = re.search(r"^UUID:\s*(\S+)", out, re.M)
        r.header_verified = rc == 0 and bool(m) and m.group(1).lower() == dev.uuid
        if not r.header_verified:
            r.errors.append(f"header backup verification failed: {err.strip() or 'UUID mismatch'}")
        dump = f"# cryptsetup luksDump {dev.path}\n{out}"
        if shutil.which("systemd-cryptenroll"):
            rc2, o2, _ = _run(["systemd-cryptenroll", dev.path])
            if rc2 == 0:
                dump += f"\n# systemd-cryptenroll {dev.path}\n{o2}"
        _write_private(self._staging / "dumps" / f"{dev.base_name}.luksDump.txt", dump)
        self.emit("info", f"  header backup {'verified' if r.header_verified else 'FAILED VERIFY'}")
        return str(hdr) if r.header_verified else None

    # ---- public operations
    def verify(self, opts: Optional[BackupOptions] = None) -> BackupReport:
        opts = dataclasses.replace(opts or BackupOptions(), write=False)
        return self._execute(opts)

    def backup(self, opts: Optional[BackupOptions] = None) -> BackupReport:
        return self._execute(opts or BackupOptions())

    def _select(self, devs: List[LuksDevice], flt: List[str]) -> List[LuksDevice]:
        if not flt:
            return devs
        want = {f.lower() for f in flt} | {os.path.realpath(f) for f in flt if f.startswith("/")}
        return [d for d in devs if {d.path, os.path.realpath(d.path), d.uuid,
                                    d.mapped_name or ""} & want]

    def _execute(self, opts: BackupOptions) -> BackupReport:
        self.require_root()
        now = dt.datetime.now()
        host = _safe(socket.gethostname())
        rep = BackupReport(host=host, timestamp=now.strftime(TS_FMT), started=now.isoformat(timespec="seconds"),
                           mode="backup" if opts.write else "verify")
        with _RunLock():
            for f in self.pending_key_exports():
                rep.warnings.append(f"private key export {f} is still on this machine: copy it to secure "
                                    "storage (e.g. Vaultwarden) and delete it (see gpg-status)")
            if opts.write and self.cfg.gpg_recipient:
                st = self.gpg_status()
                if not st.encrypt_test_ok:
                    rep.errors.append(f"GPG encryption not usable ({st.message}); backup kept local only, "
                                      "nothing copied to CIFS - run gpg-setup")
            if opts.write:
                self._staging = Path(self.cfg.local_dir) / host / rep.timestamp
                for d in (Path(self.cfg.local_dir), Path(self.cfg.local_dir) / host, self._staging):
                    _mkdir_private(d)
                for sub in ("headers", "dumps", "keys", "system"):
                    _mkdir_private(self._staging / sub)
                rep.staging_dir = str(self._staging)
            try:
                devs = self._select(self.discover(), opts.devices)
                if not devs:
                    rep.warnings.append("no LUKS devices found" + (" matching filter" if opts.devices else ""))
                for dev in devs:
                    rep.devices.append(self._process_device(dev, opts))
                if opts.write:
                    self._finalize_staging(rep)
                    self._distribute(rep)
            finally:
                self._staging = None
                if self.config_dirty:
                    self.save_config()
        return self._finish(rep)

    def _finalize_staging(self, rep: BackupReport) -> None:
        s = self._staging
        for f in CRYPTTAB_FILES:
            if os.path.isfile(f):
                _write_private(s / "system" / os.path.basename(f), Path(f).read_bytes())
        _, out, _ = _run(["lsblk", "-J", "-p", "-o", "NAME,TYPE,FSTYPE,UUID,PARTUUID,SIZE,MOUNTPOINT"])
        _write_private(s / "system" / "lsblk.json", out)
        _, ver, _ = _run(["cryptsetup", "--version"])
        _write_private(s / "README.txt", README_TEMPLATE.format(host=rep.host, ts=rep.timestamp,
                                                                 cs=ver.strip(), tool=__version__))
        _write_private(s / "manifest.json", json.dumps(rep.to_dict(), indent=2))
        lines = [f"{sha256_file(p)}  {p.relative_to(s)}" for p in sorted(s.rglob("*"))
                 if p.is_file() and p.name != "SHA256SUMS"]
        _write_private(s / "SHA256SUMS", "\n".join(lines) + "\n")

    def _encrypt(self, staging: Path) -> Path:
        kr = GpgKeyring(self.cfg.gpg_home)
        tar_path = staging.parent / f"{staging.name}.tar"
        out = staging.parent / f"{staging.name}.tar.gpg"
        fd = os.open(tar_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w") as tf:
                tf.add(str(staging), arcname=staging.name)
            kr.encrypt_file(self.cfg.gpg_recipient, str(tar_path), str(out))
        finally:
            if tar_path.exists():
                tar_path.unlink()
        os.chmod(out, 0o600)
        return out

    @staticmethod
    def _copy_verify(src: Path, dest_parent: Path) -> Path:
        dest = dest_parent / src.name
        if src.is_dir():
            shutil.copytree(src, dest, copy_function=shutil.copyfile)
            pairs = [(p, dest / p.relative_to(src)) for p in src.rglob("*") if p.is_file()]
        else:
            shutil.copyfile(src, dest)
            pairs = [(src, dest)]
        for a, b in pairs:
            if sha256_file(a) != sha256_file(b):
                raise BackupError(f"checksum mismatch after copy: {b}")
        for p in [dest, *dest.rglob("*")] if dest.is_dir() else [dest]:
            try:
                os.chmod(p, 0o700 if p.is_dir() else 0o600)
            except OSError:
                pass  # CIFS: permissions come from mount options
        return dest

    def _apply_retention(self, host_dir: Path) -> List[str]:
        keep = self.cfg.retention
        if keep <= 0 or not host_dir.is_dir():
            return []
        stamps = sorted({m.group(1) for p in host_dir.iterdir() if (m := TS_RE.match(p.name))})
        old = set(stamps[:-keep])
        removed = []
        for p in host_dir.iterdir():
            m = TS_RE.match(p.name)
            if m and m.group(1) in old:
                shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
                removed.append(p.name)
        return removed

    def _distribute(self, rep: BackupReport) -> None:
        staging = self._staging
        local_host = staging.parent
        artifact: Optional[Path] = staging
        if self.cfg.gpg_recipient:
            try:
                artifact = self._encrypt(staging)
                self.emit("info", f"Encrypted archive: {artifact}")
            except BackupError as e:
                artifact = None  # never fall back to sending plaintext to the share
                if not any("GPG" in x for x in rep.errors):
                    rep.errors.append(f"{e}; nothing copied to CIFS")
        cifs_ok = False
        if self.cfg.cifs.enabled and artifact is not None:
            dest = {"type": "cifs", "share": self.cfg.cifs.share, "ok": False}
            try:
                with CifsMount(self.cfg.cifs, self.emit) as mnt:
                    host_dir = mnt / self.cfg.cifs.subdir.strip("/") / rep.host
                    host_dir.mkdir(parents=True, exist_ok=True)
                    out = self._copy_verify(artifact, host_dir)
                    dest["path"] = f"{self.cfg.cifs.share.rstrip('/')}/{out.relative_to(mnt)}"
                    dest["pruned"] = self._apply_retention(host_dir)
                    dest["ok"] = cifs_ok = True
                    self.emit("info", f"Copied to {dest['path']} (verified)")
            except (BackupError, OSError) as e:
                dest["error"] = str(e)
                rep.errors.append(f"CIFS copy failed: {e}")
                self._emit_cifs_hints(str(e))
            rep.destinations.append(dest)
        if self.cfg.keep_local or not cifs_ok:
            rep.destinations.append({"type": "local", "path": str(artifact or staging), "ok": True,
                                     "pruned": self._apply_retention(local_host)})
            if not self.cfg.keep_local:
                rep.warnings.append("keep_local=false but CIFS copy failed; local copy retained")
        else:
            shutil.rmtree(staging)
            if artifact != staging:
                artifact.unlink()
            rep.staging_dir = ""

    def _finish(self, rep: BackupReport) -> BackupReport:
        rep.finished = dt.datetime.now().isoformat(timespec="seconds")
        if rep.errors or any(d.status == "error" for d in rep.devices):
            rep.status, rep.exit_code = "error", EXIT_ERROR
        elif rep.warnings or any(d.status == "warning" for d in rep.devices):
            rep.status, rep.exit_code = "warning", EXIT_WARN
        if self.config_path:
            try:
                _write_private(self.config_path.parent / "last_run.json", json.dumps(rep.to_dict(), indent=2))
            except OSError:
                pass
        return rep

    # ---- CIFS setup / test
    def _emit_cifs_hints(self, msg: str) -> None:
        for pat, hint in CIFS_HINTS:
            if re.search(pat, msg, re.I):
                self.emit("info", f"  hint: {hint}")

    def test_cifs(self) -> bool:
        """Mount, write+read+delete a test file under subdir, unmount. Safe to call any time."""
        self.require_root()
        c = self.cfg.cifs
        user = read_cifs_username(c.credentials_file)
        self.emit("info", f"Testing {c.share} as '{user or '?'}' (options: {c.mount_options or 'none'})")
        try:
            with CifsMount(c, self.emit) as mnt:
                self.emit("info", "  mount OK")
                d = mnt / c.subdir.strip("/") if c.subdir.strip("/") else mnt
                d.mkdir(parents=True, exist_ok=True)
                t = d / f".luks-backup-write-test-{os.getpid()}"
                t.write_bytes(b"luks-backup write test\n")
                if t.read_bytes() != b"luks-backup write test\n":
                    raise BackupError("write test read-back mismatch")
                t.unlink()
                self.emit("info", f"  write/read/delete OK in '{c.subdir or '/'}'")
            self.emit("info", "  unmount OK - CIFS test PASSED")
            return True
        except (BackupError, OSError) as e:
            self.emit("error", f"CIFS test FAILED: {e}")
            self._emit_cifs_hints(str(e))
            return False

    def configure_cifs(self) -> bool:
        """Interactive CIFS-only setup; retests until it passes or the user stops. Returns test result."""
        p, c = self.prompter, self.cfg.cifs
        if not p.interactive:
            raise PromptUnavailable("CIFS setup requires an interactive prompter")
        c.enabled = True
        while True:
            c.share = p.text("Share (//server/share[/subfolder])", c.share)
            c.subdir = p.text("Directory for backups on the share", c.subdir)
            c.mount_options = p.text("Mount options (vers=3 works for most; vers=3,seal to encrypt "
                                     "traffic; '-' for none)", c.mount_options)
            if c.mount_options.strip() == "-":
                c.mount_options = ""
            c.credentials_file = p.text("Credentials file (username=/password=[/domain=])", c.credentials_file)
            cred = Path(c.credentials_file)
            if cred.is_file():
                self.emit("info", f"  existing credentials for user '{read_cifs_username(str(cred)) or '?'}'")
            if not cred.is_file() or p.confirm(f"Overwrite {cred} with new credentials?", False):
                user = p.text("CIFS username", read_cifs_username(str(cred)) or None)
                domain = p.text("Domain (blank for none)", "")
                write_cifs_credentials(c.credentials_file, user, p.secret("CIFS password"), domain)
            self.config_dirty = True
            ok = self.test_cifs()
            if ok or not p.confirm("Edit settings and retry?", True):
                return ok

    # ---- GPG setup / status
    def pending_key_exports(self) -> List[str]:
        return sorted(str(p) for p in self.cfg.gpg_export_dir.glob("*.SECRET.asc"))

    def gpg_status(self) -> GpgStatus:
        c = self.cfg
        st = GpgStatus(enabled=bool(c.gpg_recipient), recipient=c.gpg_recipient,
                       pending_exports=self.pending_key_exports())
        pubs = sorted(c.gpg_export_dir.glob("*.pub.asc"))
        st.public_key_file = str(pubs[-1]) if pubs else ""
        if not c.gpg_recipient:
            st.message = "encryption disabled"
            return st
        try:
            kr = GpgKeyring(c.gpg_home)
            st.key = kr.get(c.gpg_recipient)
            st.key_present = st.key is not None
            if not st.key_present:
                st.message = f"key {c.gpg_recipient} not found in {c.gpg_home}"
                return st
            st.secret_on_machine = st.key.has_secret
            st.encrypt_test_ok, err = kr.test_encrypt(c.gpg_recipient)
            st.message = "ready" if st.encrypt_test_ok else f"test encryption failed: {err}"
        except BackupError as e:
            st.message = str(e)
        return st

    def _report_gpg_status(self, st: GpgStatus) -> None:
        if not st.enabled:
            self.emit("info", "Archive encryption: OFF")
        else:
            uid = st.key.uid if st.key else "?"
            self.emit("info", f"Archive encryption: {'READY' if st.encrypt_test_ok else 'NOT WORKING'} "
                              f"- {uid} [{st.recipient}]")
            if not st.encrypt_test_ok:
                self.emit("warning", f"  {st.message}")
            if st.secret_on_machine:
                self.emit("warning", "  the private key is stored on this machine; backups are only "
                                     "recoverable while this machine works")
        if st.public_key_file:
            self.emit("info", f"  public key (for other machines): {st.public_key_file}")
        for f in st.pending_exports:
            self.emit("warning", f"  PRIVATE KEY WAITING TO BE MOVED: {f}")
            self.emit("info", f"    1) sudo cat {f}   -> paste into a Vaultwarden secure note (with the passphrase)")
            self.emit("info", f"    2) sudo rm {f}")

    def _passphrase_for_new_key(self) -> str:
        p = self.prompter
        self.emit("info", "Choose a passphrase that protects the private key (needed only to RESTORE).\n"
                          "  Leave blank to generate a strong random one.")
        for _ in range(3):
            pw = p.secret("Passphrase (input hidden)")
            if not pw:
                pw = "-".join(secrets.token_urlsafe(6) for _ in range(4))
                self.emit("info", f"\n  Generated passphrase:  {pw}\n"
                                  "  Save it in Vaultwarden NOW, together with the key file below.\n")
                if p.confirm("Saved it?", True):
                    return pw
                continue
            if len(pw) < 10:
                self.emit("warning", "  use at least 10 characters")
                continue
            if p.secret("Repeat passphrase") != pw:
                self.emit("warning", "  passphrases do not match")
                continue
            return pw
        raise BackupError("no passphrase set")

    def _gpg_generate(self) -> str:
        c, host = self.cfg, _safe(socket.gethostname())
        kr = GpgKeyring(c.gpg_home)
        pw = self._passphrase_for_new_key()
        uid = f"LUKS backup key ({host} {dt.datetime.now():%Y-%m-%d %H%M%S}) <luks-backup@{host}>"
        self.emit("info", "Generating key...")
        fpr, done = None, False
        try:
            fpr = kr.generate(uid, pw)
            if not kr.roundtrip(fpr, pw):
                raise BackupError("encrypt/decrypt self-test failed")
            short = fpr[-8:]
            _mkdir_private(c.gpg_export_dir)
            sec = c.gpg_export_dir / f"luks-backup-key-{short}.SECRET.asc"
            pub = c.gpg_export_dir / f"luks-backup-key-{short}.pub.asc"
            _write_private(sec, kr.export_secret(fpr, pw))
            _write_private(pub, kr.export_public(fpr))
            kr.delete_secret(fpr)  # this machine only needs the public key to encrypt
            done = True
        finally:
            if fpr and not done:  # failed part-way: remove the half-made key and its exports
                kr.delete_key(fpr)
                for f in c.gpg_export_dir.glob(f"luks-backup-key-{fpr[-8:]}.*"):
                    f.unlink()
                self.emit("warning", "  key generation did not complete; partial key removed")
            kr.kill_agent()
            del pw
        self.emit("info", f"Key created and self-tested: {fpr}")
        self.emit("info", "The private key was removed from the keyring; the only copy is the export file.")
        return fpr

    def _gpg_use_user_key(self, user: str) -> Optional[str]:
        p = self.prompter
        ukr = GpgKeyring.for_user(user)
        keys = [k for k in ukr.list_keys() if k.can_encrypt and k.has_secret]
        if not keys:
            self.emit("warning", f"No usable GPG keys with a private key found for {user}.")
            return None
        opts = [(str(i + 1), f"{k.uid}  [{k.fingerprint[-16:]}]"
                 + (f" expires {k.expires}" if k.expires else "")) for i, k in enumerate(keys)]
        ch = p.choose(f"Keys belonging to {user}:", opts, default="1")
        k = keys[int(ch) - 1]
        GpgKeyring(self.cfg.gpg_home).import_public(ukr.export_public(k.fingerprint))
        _mkdir_private(self.cfg.gpg_export_dir)
        _write_private(self.cfg.gpg_export_dir / f"luks-backup-key-{k.fingerprint[-8:]}.pub.asc",
                       ukr.export_public(k.fingerprint))
        if k.expires:
            self.emit("warning", f"  this key expires {k.expires}; backups will fail after that until renewed")
        self.emit("info", f"Using {user}'s key {k.fingerprint}. Your private key stays in {user}'s keyring - "
                          "make sure it is backed up (e.g. Vaultwarden).")
        return k.fingerprint

    def _gpg_import(self) -> Optional[str]:
        p = self.prompter
        path = p.text("Path to public key file (.asc), e.g. the luks-backup-key-*.pub.asc from another machine")
        if not path or not os.path.isfile(path):
            self.emit("warning", "  file not found")
            return None
        fprs = GpgKeyring(self.cfg.gpg_home).import_public(Path(path).read_bytes())
        if len(fprs) > 1:
            ch = p.choose("Multiple keys imported; which one?", [(str(i + 1), f) for i, f in enumerate(fprs)], "1")
            return fprs[int(ch) - 1]
        return fprs[0] if fprs else None

    def _gpg_existing(self) -> Optional[str]:
        p, c = self.prompter, self.cfg
        kr = GpgKeyring(c.gpg_home)
        keys = kr.list_keys()
        if not keys:
            self.emit("warning", "  backup keyring is empty")
            return None
        exports = {f.name for f in c.gpg_export_dir.glob("*.SECRET.asc")}
        opts = []
        for i, k in enumerate(keys):
            tag = []
            if f"luks-backup-key-{k.fingerprint[-8:]}.SECRET.asc" in exports:
                tag.append("private-key export still on disk")
            elif k.has_secret:
                tag.append("PRIVATE KEY IN KEYRING (unfinished setup?)")
            else:
                tag.append("public only")
            opts.append((str(i + 1), f"{k.uid}  [{k.fingerprint[-16:]}]  ({'; '.join(tag)})"))
        opts.append(("d", "Delete one of these keys"))
        opts.append(("b", "Back"))
        ch = p.choose("Keys in the backup keyring (" + c.gpg_home + "):", opts, default="b")
        if ch == "b":
            return None
        if ch == "d":
            n = p.choose("Delete which key?", opts[:-2] + [("b", "Back")], default="b")
            if n != "b":
                k = keys[int(n) - 1]
                if p.confirm(f"Delete {k.uid}? Backups already encrypted to it stay decryptable only "
                             "with its exported private key", False):
                    kr.delete_key(k.fingerprint)
                    for f in c.gpg_export_dir.glob(f"luks-backup-key-{k.fingerprint[-8:]}.*"):
                        f.unlink()
                    if c.gpg_recipient.upper() == k.fingerprint.upper():
                        c.gpg_recipient = ""
                    self.emit("info", "  deleted")
            return None
        k = keys[int(ch) - 1]
        if k.has_secret:
            self.emit("warning", "  this key's private half is still in the keyring; you must know its passphrase "
                                 "and keep a copy elsewhere, otherwise delete it and generate a new key")
            if not p.confirm("Use it anyway?", False):
                return None
        return k.fingerprint

    def configure_gpg(self) -> bool:
        """Interactive encryption setup. Returns True if encryption is enabled and tested."""
        p, c = self.prompter, self.cfg
        if not p.interactive:
            raise PromptUnavailable("GPG setup requires an interactive prompter")
        self.require_root()
        self._report_gpg_status(self.gpg_status())
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user == "root":
            sudo_user = ""
        self.emit("info", "\nEncrypting the archive means people with access to the share cannot read your "
                          "LUKS headers/keys.\nThis machine only stores a PUBLIC key; you need the private key "
                          "+ passphrase only to restore.")
        options = [("g", "Generate a new backup key (recommended; one key can be reused on all machines)")]
        if GpgKeyring(c.gpg_home).list_keys():
            options.append(("e", f"Use or delete a key already in the backup keyring ({c.gpg_home})"))
        if sudo_user:
            options.append(("u", f"Use one of {sudo_user}'s existing GPG keys"))
        options += [("i", "Import a public key file (e.g. from your first machine)"),
                    ("n", "No encryption")]
        if c.gpg_recipient:
            options.insert(0, ("k", "Keep current setting"))
        default = "k" if c.gpg_recipient else ("g" if c.cifs.enabled else "n")
        while True:
            ch = p.choose("Archive encryption:", options, default=default)
            try:
                if ch == "k":
                    break
                if ch == "n":
                    c.gpg_recipient = ""
                    break
                fpr = {"g": self._gpg_generate,
                       "u": lambda: self._gpg_use_user_key(sudo_user),
                       "e": self._gpg_existing,
                       "i": self._gpg_import}[ch]()
                if fpr:
                    c.gpg_recipient = fpr
                    break
            except BackupError as e:
                self.emit("error", str(e))
        self.config_dirty = True
        st = self.gpg_status()
        self._report_gpg_status(st)
        return st.enabled and st.encrypt_test_ok

    def configure(self) -> Config:
        p, c = self.prompter, self.cfg
        if not p.interactive:
            raise PromptUnavailable("configure requires an interactive prompter")

        def ask_int(msg, cur):
            while True:
                try:
                    return int(p.text(msg, str(cur)))
                except ValueError:
                    pass

        c.local_dir = p.text("Local backup directory", c.local_dir)
        c.retention = ask_int("Backups to keep per destination (0 = keep all)", c.retention)
        c.cifs.enabled = p.confirm("Copy backups to a CIFS/SMB share?", c.cifs.enabled)
        if c.cifs.enabled:
            self.configure_cifs()
            c.keep_local = p.confirm("Also keep the local copy?", c.keep_local)
        else:
            c.keep_local = True
        self.configure_gpg()
        globs = p.text("Keyfile search globs (comma-separated)", ",".join(c.keyfile_globs))
        c.keyfile_globs = [g.strip() for g in globs.split(",") if g.strip()]
        self.config_dirty = True
        return c


README_TEMPLATE = """LUKS header/key backup - host {host} - {ts}
Created by luks_backup.py {tool}; {cs}

Contents
  headers/   cryptsetup luksHeaderBackup images (<dev>_<uuid>.luksheader.img)
  dumps/     luksDump / systemd-cryptenroll listings at backup time
  keys/      keyfiles (and saved passphrases, passphrase-slotN.txt) verified to unlock the
             device and the header backup. Use with --key-file, or: cat the .txt to read it.
  system/    crypttab(s), lsblk.json
  manifest.json, SHA256SUMS  (verify: sha256sum -c SHA256SUMS)

If you received this as <timestamp>.tar.gpg (encrypted archive)
  gpg --import luks-backup-key-XXXXXXXX.SECRET.asc     # once, from Vaultwarden
  gpg -d <timestamp>.tar.gpg | tar x                   # asks for the key passphrase

Inspect / test (non-destructive)
  cryptsetup luksDump headers/<file>
  cryptsetup open --test-passphrase --header headers/<file> <device>

Unlock using the backup header without restoring it
  cryptsetup open --header headers/<file> [--key-file keys/<dir>/<key>] <device> <name>

Restore (DESTRUCTIVE - overwrites on-disk header; confirm the UUID matches first)
  cryptsetup luksHeaderRestore <device> --header-backup-file headers/<file>

SECURITY: a header backup preserves every keyslot that existed at backup time.
A passphrase/keyfile removed from the disk later can still unlock the data using
this header. Store and expire these backups accordingly. TPM2-bound slots
cannot be backed up; they are only usable on the original machine/PCR state.
"""


# --------------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Back up and verify LUKS headers and keyfiles.")
    ap.add_argument("command", nargs="?", default="run",
                    choices=["run", "verify", "discover", "configure", "cifs-setup", "cifs-test",
                             "gpg-setup", "gpg-status"],
                    help="cifs-setup/cifs-test: share only; gpg-setup/gpg-status: archive encryption only")
    ap.add_argument("-c", "--config", default=str(DEFAULT_CONFIG), help="JSON config path")
    ap.add_argument("-n", "--non-interactive", action="store_true", help="never prompt (scheduled jobs)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON on stdout")
    ap.add_argument("-v", "--verbose", action="store_true", help="also show the exact mount command")
    ap.add_argument("--save", action="store_true", help="persist the overrides below into the config")
    g = ap.add_argument_group("overrides")
    g.add_argument("--local-dir")
    g.add_argument("--retention", type=int)
    g.add_argument("--keep-local", choices=["yes", "no"])
    g.add_argument("--cifs-share", help="//server/share[/subfolder] (enables CIFS)")
    g.add_argument("--cifs-subdir")
    g.add_argument("--cifs-credentials", help="credentials file (username=/password=/domain=)")
    g.add_argument("--cifs-user", help="write a credentials file for this user (password prompted "
                                       "or taken from $LUKS_BACKUP_CIFS_PASSWORD)")
    g.add_argument("--cifs-domain", default="")
    g.add_argument("--cifs-options", help="mount options, e.g. vers=3 or vers=3,seal ('' for none)")
    g.add_argument("--no-cifs", action="store_true")
    g.add_argument("--gpg-recipient", help="fingerprint of a key already in gpg_home ('' disables)")
    g.add_argument("--device", action="append", default=[], help="limit to device path/UUID/mapper name")
    g.add_argument("--check-passphrases", action="store_true",
                   help="also prompt to test a passphrase/recovery key on each device")
    return ap


def apply_overrides(cfg: Config, a, prompter: Prompter) -> bool:
    changed = False

    def setv(obj, attr, val):
        nonlocal changed
        if val is not None and getattr(obj, attr) != val:
            setattr(obj, attr, val)
            changed = True

    setv(cfg, "local_dir", a.local_dir)
    setv(cfg, "retention", a.retention)
    setv(cfg, "keep_local", None if a.keep_local is None else a.keep_local == "yes")
    setv(cfg, "gpg_recipient", a.gpg_recipient)
    if a.cifs_share:
        setv(cfg.cifs, "share", a.cifs_share)
        setv(cfg.cifs, "enabled", True)
    setv(cfg.cifs, "subdir", a.cifs_subdir)
    setv(cfg.cifs, "credentials_file", a.cifs_credentials)
    setv(cfg.cifs, "mount_options", a.cifs_options)
    if a.no_cifs:
        setv(cfg.cifs, "enabled", False)
    if a.cifs_user:
        pw = os.environ.get("LUKS_BACKUP_CIFS_PASSWORD")
        if pw is None:
            pw = prompter.secret(f"CIFS password for {a.cifs_user}")
        write_cifs_credentials(cfg.cifs.credentials_file, a.cifs_user, pw, a.cifs_domain)
    return changed


def print_human(rep: BackupReport) -> None:
    out = sys.stdout
    out.write(f"\n{rep.mode.upper()} {rep.timestamp} on {rep.host}: {rep.status.upper()}\n")
    for d in rep.devices:
        keys = [k for k in d.keys if k.ok]
        kdesc = ", ".join(f"{os.path.basename(k.path)}(slot {k.slot})" for k in keys) or "none"
        pp = sum(1 for c in d.passphrase_checks if c["ok"])
        out.write(f"  {d.device:<16} {d.status.upper():<8} header={'OK' if d.header_verified else '-'}"
                  f"  keyfiles={kdesc}" + (f"  passphrases_ok={pp}" if d.passphrase_checks else "")
                  + f"  slots={','.join(f'{k}:{v}' for k, v in d.slot_types.items())}\n")
        for w in d.warnings:
            out.write(f"      ! {w}\n")
        for e in d.errors:
            out.write(f"      X {e}\n")
    for dst in rep.destinations:
        out.write(f"  -> {dst['type']}: {dst.get('path', dst.get('share'))} "
                  f"{'OK' if dst.get('ok') else 'FAILED ' + dst.get('error', '')}\n")
    for w in rep.warnings:
        out.write(f"  ! {w}\n")
    for e in rep.errors:
        out.write(f"  X {e}\n")


def setup_logging(path: str, verbose: bool) -> None:
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        h = logging.FileHandler(path)
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
        os.chmod(path, 0o600)
    except OSError:
        pass


def main(argv: Optional[List[str]] = None) -> int:
    os.umask(0o077)
    a = build_parser().parse_args(argv)
    interactive = not a.non_interactive and sys.stdin.isatty()
    prompter: Prompter = ConsolePrompter() if interactive else Prompter()
    reporter = console_reporter(a.verbose)
    try:
        LuksBackupService.require_root()
        cfg_path = Path(a.config)
        first_run = not cfg_path.exists()
        cfg = Config() if first_run else Config.load(cfg_path)
        changed = apply_overrides(cfg, a, prompter)
        setup_logging(cfg.log_file, a.verbose)
        svc = LuksBackupService(cfg, prompter, reporter, cfg_path)

        # ---- setup/test commands that do not perform a backup
        if a.command == "cifs-test":
            if not cfg.cifs.share:
                raise BackupError("no CIFS share configured (run cifs-setup or pass --cifs-share)")
            ok = svc.test_cifs()
            if ok and changed and a.save:
                svc.save_config()
            return EXIT_OK if ok else EXIT_ERROR
        if a.command == "cifs-setup":
            if not interactive:
                raise PromptUnavailable("cifs-setup is interactive; use cifs-test with --cifs-* options instead")
            ok = svc.configure_cifs()
            if ok or prompter.confirm("Test did not pass. Save these CIFS settings anyway?", False):
                svc.save_config()
            return EXIT_OK if ok else EXIT_ERROR
        if a.command == "gpg-status":
            st = svc.gpg_status()
            if a.json:
                print(json.dumps(asdict(st), indent=2))
            else:
                svc._report_gpg_status(st)
            bad = st.pending_exports or (st.enabled and not st.encrypt_test_ok)
            return EXIT_WARN if bad else EXIT_OK
        if a.command == "gpg-setup":
            if not interactive:
                raise PromptUnavailable("gpg-setup is interactive")
            svc.configure_gpg()
            svc.save_config()
            return EXIT_OK

        if a.command == "configure" or (first_run and interactive and a.command == "run"):
            if first_run:
                reporter("info", f"No config at {cfg_path}; starting first-run setup.")
            svc.configure()
            svc.save_config()
            if a.command == "configure":
                return EXIT_OK
        elif first_run or (changed and a.save):
            if first_run:
                reporter("warning", "No config found; using defaults + command-line options")
            svc.save_config()

        if a.command == "discover":
            devs = svc.discover()
            if a.json:
                print(json.dumps([asdict(d) for d in devs], indent=2))
            else:
                for d in devs:
                    ct = f"crypttab {d.crypttab.name} key={d.crypttab.keyfile}" if d.crypttab else "no crypttab entry"
                    print(f"{d.path:<16} {d.uuid}  LUKS{d.luks_version}  {d.size:>6}  "
                          f"open={d.mapped_name or '-'}  {ct}")
                    for s, t in sorted(d.slot_types.items()):
                        print(f"    slot {s}: {t}")
            return EXIT_OK

        opts = BackupOptions(devices=a.device, check_passphrases=a.check_passphrases)
        rep = svc.verify(opts) if a.command == "verify" else svc.backup(opts)
        if a.json:
            print(json.dumps(rep.to_dict(), indent=2))
        else:
            print_human(rep)
        return rep.exit_code
    except PromptUnavailable as e:
        reporter("error", f"input required but running non-interactively: {e}")
        return EXIT_ERROR
    except BackupError as e:
        reporter("error", str(e))
        return EXIT_ERROR
    except KeyboardInterrupt:
        reporter("error", "interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
