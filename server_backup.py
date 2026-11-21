#!/usr/bin/env python3
"""
server_backup.py - one-file backup utility for Proxmox hosts and Linux VMs/servers.

Evolved from luks_backup.py 1.3.1; the LUKS module keeps that tool's behaviour.
Python 3.8+, standard library only. Must run as root.

Recovery layers (independent modules; detection says what CAN run, config says what SHOULD run)
    luks          LUKS headers, keyfiles, saved passphrases + validation   (encryption recovery)
    files         Restic snapshots of explicitly configured paths          (file/history recovery)
    proxmox_vm    vzdump of explicitly configured VM IDs                   (complete VM disaster recovery)
    proxmox_host  /etc/pve, network, boot, storage config + inventory      (Proxmox host reconstruction)

External tools
    shared        lsblk, findmnt; optional mount.cifs (cifs-utils), gpg (gnupg2), runuser
    luks          cryptsetup; optional systemd-cryptenroll
    files         restic
    proxmox_*     qm, vzdump, pveversion; optional zstd (deep verify)

Layout (UI-callable core, thin CLI on top)
    Config (+ CifsConfig, DeviceOverride, *ModuleConfig)   JSON-backed settings
    Prompter / ConsolePrompter, reporter(level, message)   interaction and progress
    LockManager                                            global non-blocking run lock (re-entrant)
    CifsMount / Destination                                share mount + preflight, one mount per run
    GpgKeyring / GpgEncryption                             backup encryption key (LUKS + host-config archives)
    Manifest / RetentionManager / ArtifactPublisher        checksums, pruning, copy + verify
    Ledger                                                 tamper detection (record of backups made)
    EnvironmentDetector                                    capability detection
    LuksBackupService                                      LUKS module (from luks_backup.py)
    DirectoryBackupService                                 Restic module
    ProxmoxVmBackupService / ProxmoxHostBackupService      Proxmox modules
    ServerBackup                                           status / backup / verify / restore-test
    main()                                                 argparse CLI

Commands
    status           capabilities, modules, destination health, VMs, warnings (performs no backup)
    backup           --profile NAME | --luks --files --proxmox --proxmox-vm --proxmox-host
                     (no selector = every enabled module)
    verify           same selection; --deep = full checksums, restic data read, zstd -t
    restore-test     --files [--path P]  |  --proxmox-vm --vmid V --test-vmid N --storage S [--yes]
    ledger           show the tamper ledger; --accept re-baselines after intended deletions
    files-init       create the Restic repository (and its password file)
    files-snapshots  list this host's Restic snapshots
    gpg-test         backup key + passphrase (from Vaultwarden) decrypt the newest archive?
    discover         list LUKS devices, keyslots, tokens, crypttab matches
    configure        interactive setup (local dir, CIFS, GPG, LUKS keyfiles, modules)
    cifs-setup / cifs-test / gpg-setup / gpg-status      as in luks_backup.py
    run              legacy luks_backup.py full LUKS backup (same output/JSON report)
    example-config / systemd-units                       print a starting config / timer units

Remote layout
    <share>/<cifs.subdir>/<host>/luks/<ts>[.tar.gpg]        proxmox/host/<ts>[.tar.gpg]
                                 proxmox/vm/<vmid>/vzdump-*  restic/   last_run.json  RESTORE-*.txt

Exit codes: 0 ok, 1 error, 2 completed with warnings, 130 interrupted
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import dataclasses
import datetime as dt
import difflib
import fcntl
import fnmatch
import getpass
import glob
import hashlib
import io
import json
import logging
import os
import pwd
import re
import secrets
import shutil
import signal
import smtplib
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import asdict, dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

__version__ = "2.2.1"

DEFAULT_CONFIG = Path("/etc/server-backup/config.json")
LEGACY_CONFIG = Path("/etc/luks-backup/config.json")
DEFAULT_CRED = "/etc/server-backup/cifs.cred"
DEFAULT_GPG_HOME = "/etc/server-backup/gnupg"
DEFAULT_RESTIC_PASS = "/etc/server-backup/restic.pass"
LOCK_PATH = "/run/server-backup.lock"
LEGACY_LOCK_PATH = "/run/luks-backup.lock"   # also taken by the LUKS module: never overlap luks_backup.py
CRYPTTAB_FILES = ("/etc/crypttab", "/etc/crypttab.initramfs")
KEYS_D_DIRS = ("/etc/cryptsetup-keys.d", "/run/cryptsetup-keys.d")
DEFAULT_KEY_GLOBS = [
    "/root/*.key", "/root/.*key*", "/root/*keyfile*",
    "/etc/luks-keys/*", "/etc/keys/*", "/etc/cryptsetup-keys.d/*",
]
MAX_KEYFILE_BYTES = 8 * 1024 * 1024
KEY_PREFIX = "server-backup-key"          # export files of the backup encryption key
LEGACY_KEY_PREFIX = "luks-backup-key"     # same thing, as named by luks_backup.py / server_backup 2.0.0
GPG_SCOPE = "LUKS and Proxmox host-config archives"   # what the backup encryption key protects
TS_FMT = "%Y%m%d-%H%M%S"
TS_RE = re.compile(r"^(\d{8}-\d{6})")
EXIT_OK, EXIT_ERROR, EXIT_WARN, EXIT_INTERRUPTED = 0, 1, 2, 130
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

# module names; tuple order = run order (small/fast first, the big vzdump last)
MODULE_ORDER = ("luks", "proxmox_host", "files", "proxmox_vm")
MODULE_FLAGS = {"luks": "--luks", "files": "--files", "proxmox_vm": "--proxmox-vm", "proxmox_host": "--proxmox-host"}
DEFAULT_SCHEDULES = {                     # systemd OnCalendar per profile; "verify" = scheduled verify --deep
    "daily": "Mon..Sat *-*-* 01:30",
    "weekly": "Sun *-*-* 01:30",
    "recovery": "*-*-01 05:00",
    "verify": "Wed *-1/2-15..21 03:00",   # third Wednesday of every second month
}
DEFAULT_PROFILES = {
    "daily": ["files"],
    "weekly": ["files", "proxmox_vm", "proxmox_host"],
    "recovery": ["luks"],
}
RESTIC_TAG = "server-backup"
DEFAULT_PVE_HOST_PATHS = [
    "/etc/pve", "/etc/network", "/etc/hosts", "/etc/hostname", "/etc/fstab", "/etc/crypttab",
    "/etc/default/grub", "/etc/modules*", "/etc/modprobe.d", "/etc/systemd/system",
    "/etc/vzdump.conf", "/etc/kernel", "/etc/lvm/lvm.conf", "/etc/resolv.conf",
    "/etc/apt/sources.list", "/etc/apt/sources.list.d",
]
PVE_HOST_COMMANDS = [
    ("pveversion-v", ["pveversion", "-v"]),
    ("qm-list", ["qm", "list"]),
    ("pct-list", ["pct", "list"]),
    ("pvesm-status", ["pvesm", "status"]),
    ("pvecm-status", ["pvecm", "status"]),
    ("lsblk", ["lsblk", "-o", "NAME,TYPE,FSTYPE,UUID,PARTUUID,SIZE,MOUNTPOINT,MODEL,SERIAL"]),
    ("lsblk-json", ["lsblk", "-J", "-p", "-O"]),
    ("blkid", ["blkid"]),
    ("pvs", ["pvs", "-v"]),
    ("vgs", ["vgs", "-v"]),
    ("lvs", ["lvs", "-a", "-o", "+devices"]),
    ("zpool-status", ["zpool", "status"]),
    ("zfs-list", ["zfs", "list", "-o", "name,used,avail,refer,mountpoint"]),
    ("ip-addr", ["ip", "addr"]),
    ("ip-route", ["ip", "route"]),
    ("ip-link", ["ip", "-d", "link"]),
    ("uname", ["uname", "-a"]),
    ("proc-cmdline", ["cat", "/proc/cmdline"]),
    ("proxmox-boot-tool", ["proxmox-boot-tool", "status"]),
    ("efibootmgr", ["efibootmgr", "-v"]),
    ("findmnt", ["findmnt", "-l"]),
    ("df", ["df", "-hT"]),
    ("lspci", ["lspci", "-nnk"]),
    ("dpkg-packages", ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n"]),
    ("apt-manual", ["apt-mark", "showmanual"]),
    ("systemctl-enabled", ["systemctl", "list-unit-files", "--state=enabled", "--no-pager"]),
]
VZDUMP_RE = re.compile(r"^vzdump-qemu-(\d+)-(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})")
VZDUMP_ARCHIVE_RE = re.compile(r"^vzdump-qemu-(\d+)-(\d{4}_\d{2}_\d{2}-\d{2}_\d{2}_\d{2})\.vma(\.zst|\.lzo|\.gz)?$")
VM_META_SUFFIX = ".server-backup.json"
QM_DISK_RE = re.compile(r"^(scsi|sata|ide|virtio|efidisk|tpmstate)\d+$")
RESTIC_SIZE_RE = re.compile(r"^\d+[KMGT]?$", re.I)

log = logging.getLogger("server_backup")
log.addHandler(logging.NullHandler())
Reporter = Callable[[str, str], None]


class BackupError(Exception):
    """Fatal error for the current operation."""


class PromptUnavailable(BackupError):
    """Raised when input is needed but the prompter is non-interactive."""


class Interrupted(KeyboardInterrupt):
    """SIGTERM/SIGHUP (e.g. systemd stop); handled like Ctrl-C so cleanup runs."""


# --------------------------------------------------------------------------- config
def _from_dict(cls, d):
    names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in (d or {}).items() if k in names})


@dataclass
class CifsConfig:
    enabled: bool = False
    share: str = ""                       # //server/share[/subfolder]
    subdir: str = "serverBackup"          # <subdir>/<hostname>/<module>/... on the share
    credentials_file: str = DEFAULT_CRED  # username=/password=/domain= (mode 0600)
    mount_options: str = "vers=3"         # add ,seal for SMB3 encryption if the server supports it
    min_free_gb: float = 5.0              # preflight fails below this; VM backups add their own estimate
    marker_file: str = ""                 # optional file that must exist on the share (proves the right share)


@dataclass
class DeviceOverride:
    keyfiles: List[str] = field(default_factory=list)  # extra keyfiles to test for this UUID
    no_keyfile_ok: bool = False   # passphrase/TPM-only device: don't prompt or warn
    skip: bool = False
    note: str = ""


@dataclass
class LuksModuleConfig:
    enabled: bool = True                  # True so configs from luks_backup.py keep doing what they did
    stale_after_days: int = 35


@dataclass
class FilesModuleConfig:
    enabled: bool = False
    repository: str = ""                  # "" = on the CIFS share (<subdir>/<host>/restic); or any restic repo
    password_file: str = DEFAULT_RESTIC_PASS   # 0400; keep a copy OFF this machine
    env_file: str = ""                    # optional KEY=VALUE lines (e.g. AWS_*) for remote repos; 0600
    cache_dir: str = "/var/cache/server-backup/restic"
    paths: List[str] = field(default_factory=list)          # explicit; nothing is backed up by default
    excludes: List[str] = field(default_factory=list)       # restic --exclude; nothing excluded unless listed
    exclude_files: List[str] = field(default_factory=list)  # restic --exclude-file
    exclude_caches: bool = False          # explicit opt-in: skip dirs containing CACHEDIR.TAG
    one_file_system: bool = False
    allow_missing_paths: bool = False     # False: a missing configured path fails the module
    max_file_size: str = ""               # e.g. "100M": larger files are listed every run ("" = no limit)
    large_file_action: str = "warn"       # warn = back them up anyway; exclude = skip them (both list them)
    tags: List[str] = field(default_factory=list)
    keep_last: int = 0
    keep_daily: int = 7
    keep_weekly: int = 4
    keep_monthly: int = 6
    keep_yearly: int = 0
    prune: bool = True
    check_after_backup: bool = False
    check_read_data_subset: str = ""      # e.g. "5%"; used by verify (--deep defaults to 5%)
    extra_backup_args: List[str] = field(default_factory=list)
    timeout_hours: float = 0              # 0 = no limit
    stale_after_days: int = 2


@dataclass
class ProxmoxVmModuleConfig:
    enabled: bool = False
    vmids: List[int] = field(default_factory=list)  # explicit list; discovered VMs are never added
    excluded_disks_ok: Dict[str, List[str]] = field(default_factory=dict)  # {"101": ["scsi1"]}: planned
    # backup=0 disks (data disks backed up otherwise, or not at all): a note instead of a warning
    mode: str = "snapshot"                # snapshot | suspend | stop
    compress: str = "zstd"                # zstd | lzo | gzip | 0
    zstd_threads: int = 0                 # >0 passes --zstd N; 0 = vzdump default
    retention: int = 3                    # newest N valid backups kept per VM (0 = keep all)
    keep_daily: int = 0                   # optional, on top of retention: newest backup per day/week/month,
    keep_weekly: int = 0                  # e.g. retention 1 + keep_weekly 4 + keep_monthly 3
    keep_monthly: int = 0
    bwlimit_kbps: int = 0
    tmpdir: str = ""
    dumpdir: str = ""                     # alternative to CIFS; must be a separate filesystem (never /)
    required_free_ratio: float = 1.0      # free space needed = allocated disks x ratio + cifs.min_free_gb
    checksum: bool = True                 # sha256 of each archive (reads it back once)
    verify_zstd: bool = False             # zstd -t after each backup (reads it back again)
    timeout_hours: float = 0
    extra_args: List[str] = field(default_factory=list)
    stale_after_days: int = 8


@dataclass
class ProxmoxHostModuleConfig:
    enabled: bool = False
    paths: List[str] = field(default_factory=lambda: list(DEFAULT_PVE_HOST_PATHS))
    extra_paths: List[str] = field(default_factory=list)    # missing ones are warnings
    excludes: List[str] = field(default_factory=list)       # fnmatch patterns on absolute paths
    include_config_db: bool = True        # consistent copy of /var/lib/pve-cluster/config.db
    extra_commands: Dict[str, List[str]] = field(default_factory=dict)
    retention: int = 8                    # newest N backups kept
    keep_daily: int = 0                   # optional, on top of retention (see proxmox_vm)
    keep_weekly: int = 0
    keep_monthly: int = 0
    allow_unencrypted: bool = False       # True: no GPG is a note instead of a warning
    stale_after_days: int = 8


@dataclass
class NotifyConfig:
    email: List[str] = field(default_factory=list)   # recipients; empty = no email
    on: str = "warning"                   # error | warning | always: the least severe result that sends mail
    method: str = "smtp"                  # smtp (direct, no local mail server needed) | sendmail (local MTA)
    smtp_host: str = ""                   # your relay, e.g. smtp-relay.example.org
    smtp_port: int = 587
    security: str = "starttls"            # starttls | ssl | none
    credentials_file: str = ""            # username=/password= (0600); "" = relay without login
    sender: str = ""                      # From: address; "" = server-backup@<hostname>
    timeout: int = 30


def unknown_keys(cls, d, prefix: str) -> List[str]:
    """Keys the dataclass does not know (typos, misplaced settings), with a suggestion."""
    if not isinstance(d, dict):
        return [f"{prefix.rstrip('.') or 'config'} should be a JSON object"]
    names = [f.name for f in dataclasses.fields(cls)]
    out = []
    for k in d:
        if k.startswith("_") or k in names:
            continue
        hint = difflib.get_close_matches(k, names, n=1, cutoff=0.6)
        out.append(f"unknown key {prefix}{k} is ignored" + (f" (did you mean {prefix}{hint[0]}?)" if hint else ""))
    return out


@dataclass
class ModulesConfig:
    luks: LuksModuleConfig = field(default_factory=LuksModuleConfig)
    files: FilesModuleConfig = field(default_factory=FilesModuleConfig)
    proxmox_vm: ProxmoxVmModuleConfig = field(default_factory=ProxmoxVmModuleConfig)
    proxmox_host: ProxmoxHostModuleConfig = field(default_factory=ProxmoxHostModuleConfig)

    @classmethod
    def unknown(cls, d: dict) -> List[str]:
        out = unknown_keys(cls, d, "modules.")
        for f in dataclasses.fields(cls):
            if isinstance(d.get(f.name), dict):
                out += unknown_keys(type(getattr(cls(), f.name)), d[f.name], f"modules.{f.name}.")
        return out

    @classmethod
    def from_dict(cls, d: dict) -> "ModulesConfig":
        d = d or {}
        m = cls(luks=_from_dict(LuksModuleConfig, d.get("luks")),
                files=_from_dict(FilesModuleConfig, d.get("files")),
                proxmox_vm=_from_dict(ProxmoxVmModuleConfig, d.get("proxmox_vm")),
                proxmox_host=_from_dict(ProxmoxHostModuleConfig, d.get("proxmox_host")))
        try:
            m.proxmox_vm.vmids = [int(v) for v in m.proxmox_vm.vmids]
        except (TypeError, ValueError):
            raise BackupError(f"modules.proxmox_vm.vmids must be a list of numbers: {m.proxmox_vm.vmids!r}")
        m.proxmox_vm.excluded_disks_ok = {str(k): [str(d) for d in v]
                                          for k, v in (m.proxmox_vm.excluded_disks_ok or {}).items()}
        return m


@dataclass
class Config:
    hostname: str = ""                    # name of the <host> directories; "" = system hostname
    local_dir: str = "/var/backups/server-backup"
    keep_local: bool = True
    retention: int = 8                    # LUKS backups kept per destination (0 = keep all)
    keyfile_globs: List[str] = field(default_factory=lambda: list(DEFAULT_KEY_GLOBS))
    gpg_recipient: str = ""               # backup encryption key (fingerprint): encrypts the LUKS and Proxmox
                                          # host-config archives (.tar.gpg). VM images and Restic are not GPG-encrypted.
    gpg_home: str = DEFAULT_GPG_HOME      # dedicated keyring holding only the PUBLIC half of that key
    log_file: str = "/var/log/server-backup.log"
    state_dir: str = "/var/lib/server-backup"   # tamper ledger: record of the backups this machine made
    cifs: CifsConfig = field(default_factory=CifsConfig)
    devices: Dict[str, DeviceOverride] = field(default_factory=dict)  # keyed by LUKS UUID
    modules: ModulesConfig = field(default_factory=ModulesConfig)
    profiles: Dict[str, List[str]] = field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_PROFILES.items()})
    schedules: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SCHEDULES))
    disk_warn_percent: int = 90           # filesystems / thin pools / share fuller than this: warning
    disk_error_percent: int = 97          # ... and this: error
    disk_check_paths: List[str] = field(default_factory=list)   # extra mount points to watch
    notify: NotifyConfig = field(default_factory=NotifyConfig)

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        d = dict(d or {})
        problems = unknown_keys(cls, d, "")
        cifs_d = d.pop("cifs", {}) or {}
        problems += unknown_keys(CifsConfig, cifs_d, "cifs.")
        cifs = _from_dict(CifsConfig, cifs_d)
        notify_d = d.pop("notify", {}) or {}
        problems += unknown_keys(NotifyConfig, notify_d, "notify.")
        notify = _from_dict(NotifyConfig, notify_d)
        devs = {}
        for k, v in (d.pop("devices", {}) or {}).items():
            problems += unknown_keys(DeviceOverride, v, f"devices.{k}.")
            devs[k.lower()] = _from_dict(DeviceOverride, v)
        mods_d = d.pop("modules", {}) or {}
        problems += ModulesConfig.unknown(mods_d)
        mods = ModulesConfig.from_dict(mods_d)
        profiles = d.pop("profiles", None)
        schedules = d.pop("schedules", None)
        cfg = _from_dict(cls, d)
        cfg.cifs, cfg.devices, cfg.modules, cfg.notify = cifs, devs, mods, notify
        if profiles is not None:
            cfg.profiles = {str(k): [str(m) for m in v] for k, v in profiles.items()}
        if schedules is not None:
            cfg.schedules = {str(k): str(v) for k, v in schedules.items()}
        cfg.load_problems = problems
        return cfg

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def load(cls, path) -> "Config":
        dups: List[str] = []

        def pairs(items):
            seen: dict = {}
            for k, v in items:
                if k in seen:
                    dups.append(k)
                seen[k] = v
            return seen

        with open(path) as f:
            cfg = cls.from_dict(json.load(f, object_pairs_hook=pairs))
        cfg.load_problems = [f"key '{k}' appears more than once at the same level (only the last one counts)"
                             for k in dict.fromkeys(dups)] + cfg.load_problems
        return cfg

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

    def module(self, name: str):
        return getattr(self.modules, name)

    @property
    def gpg_export_dir(self) -> Path:
        return Path(self.gpg_home).parent / "key-export"

    @property
    def escrow_dir(self) -> Path:
        return Path(self.gpg_home).parent / "escrow"

    def cifs_problems(self) -> List[str]:
        c, out = self.cifs, []
        if not c.share:
            out.append("no share configured")
        elif not c.share.startswith("//"):
            out.append(f"share must look like //server/share[/subfolder], got {c.share!r}")
        if not Path(c.credentials_file).is_file():
            out.append(f"credentials file not found: {c.credentials_file}")
        return out

    def validate(self) -> List[Tuple[str, str, str]]:
        """(scope, level, message); scope is a module name, 'cifs', 'profiles' or 'global'."""
        out: List[Tuple[str, str, str]] = []

        def add(scope, level, msg):
            out.append((scope, level, msg))

        for msg in getattr(self, "load_problems", []):
            add("global", "warning", msg)
        n = self.notify
        if n.on not in ("error", "warning", "always"):
            add("global", "error", f"notify.on must be error/warning/always, got {n.on!r}")
        if n.method not in ("smtp", "sendmail"):
            add("global", "error", f"notify.method must be smtp or sendmail, got {n.method!r}")
        if n.security not in ("starttls", "ssl", "none"):
            add("global", "error", f"notify.security must be starttls/ssl/none, got {n.security!r}")
        if n.email and n.method == "smtp" and not n.smtp_host:
            add("global", "error", "notify.email is set but notify.smtp_host is empty")
        if not 0 < self.disk_warn_percent <= self.disk_error_percent <= 100:
            add("global", "error", "need 0 < disk_warn_percent <= disk_error_percent <= 100")

        for name, mods in self.profiles.items():
            for m in mods:
                if m not in MODULE_ORDER:
                    add("profiles", "error", f"profile '{name}' names unknown module '{m}' "
                                             f"(known: {', '.join(MODULE_ORDER)})")
        if self.cifs.enabled:
            for p in self.cifs_problems():
                add("cifs", "error", f"cifs: {p}")
        f = self.modules.files
        if f.enabled:
            if not f.paths:
                add("files", "error", "files: no paths configured (modules.files.paths)")
            for p in f.paths:
                if not p.startswith("/"):
                    add("files", "error", f"files: path must be absolute: {p}")
            if not f.password_file:
                add("files", "error", "files: password_file is empty")
            if not f.repository.strip() and not self.cifs.enabled:
                add("files", "error", "files: repository is empty (= on the CIFS share) but CIFS is disabled")
            if not any(getattr(f, f"keep_{k}") > 0 for k in ("last", "daily", "weekly", "monthly", "yearly")):
                add("files", "warning", "files: no keep_* retention set; snapshots are never forgotten")
            if f.max_file_size and not RESTIC_SIZE_RE.match(f.max_file_size):
                add("files", "error", f"files: max_file_size must look like 500K, 100M or 2G, got {f.max_file_size!r}")
            if f.large_file_action not in ("warn", "exclude"):
                add("files", "error", f"files: large_file_action must be warn or exclude, got {f.large_file_action!r}")
        v = self.modules.proxmox_vm
        if v.enabled:
            if not v.vmids:
                add("proxmox_vm", "error", "proxmox_vm: no vmids configured")
            if v.mode not in ("snapshot", "suspend", "stop"):
                add("proxmox_vm", "error", f"proxmox_vm: mode must be snapshot/suspend/stop, got {v.mode!r}")
            if str(v.compress) not in ("zstd", "lzo", "gzip", "0"):
                add("proxmox_vm", "error", f"proxmox_vm: compress must be zstd/lzo/gzip/0, got {v.compress!r}")
            if v.retention < 0:
                add("proxmox_vm", "error", "proxmox_vm: retention must be >= 0")
            if not self.cifs.enabled and not v.dumpdir:
                add("proxmox_vm", "error", "proxmox_vm: no destination (enable CIFS or set dumpdir)")
        h = self.modules.proxmox_host
        if h.enabled and not self.gpg_recipient:
            add("proxmox_host", "note" if h.allow_unencrypted else "warning",
                "proxmox_host: archive contains secrets (/etc/pve/priv, keys) and GPG encryption is off "
                "(run gpg-setup, or set allow_unencrypted)")
        return out


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

    def paste(self, message: str) -> str:
        """Multi-line input such as a key block copied from a password manager."""
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

    def paste(self, message):
        """Reads until an empty line after an -----END line, or Ctrl-D."""
        sys.stderr.write(message + "\n(paste, then press Enter on an empty line; Ctrl-D also ends)\n")
        sys.stderr.flush()
        lines: List[str] = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if not line.strip() and any(ln.startswith("-----END") for ln in lines):
                break
            lines.append(line)
        return "\n".join(lines) + "\n"


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


@dataclass
class ModuleResult:
    module: str
    action: str
    status: str = "ok"                     # ok | warning | error | skipped
    started: str = ""
    finished: str = ""
    summary: str = ""
    artifacts: List[dict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def finalize(self) -> "ModuleResult":
        if self.status != "skipped":
            self.status = "error" if self.errors else ("warning" if self.warnings else "ok")
        self.finished = _now()
        return self


@dataclass
class RunReport:
    tool_version: str = __version__
    host: str = ""
    action: str = "backup"
    profile: str = ""
    selected: List[str] = field(default_factory=list)
    started: str = ""
    finished: str = ""
    destination: dict = field(default_factory=dict)
    modules: List[ModuleResult] = field(default_factory=list)
    disk: List[dict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    status: str = "ok"
    exit_code: int = EXIT_OK

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- helpers
def _run(cmd: List[str], input_bytes: Optional[bytes] = None, timeout: int = 300,
         env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    log.debug("exec: %s", " ".join(cmd))
    kw = {"input": input_bytes} if input_bytes is not None else {"stdin": subprocess.DEVNULL}
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env, **kw)
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


def _run_long(cmd: List[str], env: Optional[Dict[str, str]] = None, timeout: Optional[float] = None,
              on_line: Optional[Callable[[str], Optional[bool]]] = None, tail: int = 40) -> Tuple[int, List[str]]:
    """
    Long-running command (vzdump, restic): stdout+stderr streamed line by line to the debug log
    and on_line (return True from on_line to stop early: rc 0). Returns (rc, last lines).
    The child is terminated if we are interrupted or time out.
    """
    log.debug("exec: %s", " ".join(cmd))
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=env)
    except FileNotFoundError:
        raise BackupError(f"required command not found: {cmd[0]}")
    last: collections.deque = collections.deque(maxlen=tail)
    deadline = time.monotonic() + timeout if timeout else None
    stopped = timed_out = False
    try:
        for raw in p.stdout:
            line = raw.decode(errors="replace").rstrip("\n")
            last.append(line)
            log.debug("  | %s", line)
            if on_line and on_line(line):
                stopped = True
                break
            if deadline and time.monotonic() > deadline:
                timed_out = True
                break
        if stopped or timed_out:
            p.terminate()
        rc = p.wait()
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(30)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        p.stdout.close()
    if timed_out:
        last.append(f"timed out after {timeout:.0f}s")
        return 124, list(last)
    return (0 if stopped else rc), list(last)


class Progress:
    """Progress of a long step at normal level, at most every `interval` seconds (the first update
    right away), so vzdump, qmrestore and restic are never silent for minutes."""

    def __init__(self, emit: Reporter, label: str, interval: float = 30.0):
        self.emit, self.label, self.interval, self.last = emit, label, interval, None

    def update(self, msg: str) -> None:
        now = time.monotonic()
        if self.last is None or now - self.last >= self.interval:
            self.last = now
            self.emit("info", f"  {self.label} {msg}")


def progress_lines(emit: Reporter, label: str, parse: Callable[[str], Optional[str]],
                   interval: float = 30.0) -> Callable[[str], None]:
    """on_line for _run_long: every raw line at debug level (-v), parsed progress throttled at info."""
    prog = Progress(emit, label, interval)

    def on_line(line: str) -> None:
        emit("debug", f"  {label}: {line}")
        msg = parse(line)
        if msg:
            prog.update(msg)
    return on_line


def parse_vzdump_progress(line: str) -> Optional[str]:
    """'INFO:  77% (198.3 GiB of 256.0 GiB) in 6m 37s, read: ...' -> '77% (198.3 GiB of 256.0 GiB, 6m 37s)'"""
    m = re.search(r"INFO:\s+(\d+)% \(([^)]*)\)(?: in ([^,]+))?", line)
    if not m:
        return None
    return f"{m.group(1)}% ({m.group(2)}" + (f", {m.group(3).strip()}" if m.group(3) else "") + ")"


def parse_qmrestore_progress(line: str) -> Optional[str]:
    """'progress 35% (read 96619904000 bytes, duration 120 sec)' -> '35% (90.0 GiB read, 120 s)'"""
    m = re.search(r"progress (\d+)% \(read (\d+) bytes, duration (\d+) sec\)", line)
    return f"{m.group(1)}% ({_fmt_bytes(int(m.group(2)))} read, {m.group(3)} s)" if m else None


def restic_status_text(msg: dict) -> str:
    pct = int(float(msg.get("percent_done") or 0) * 100)
    text = f"{pct}%"
    if msg.get("total_bytes"):
        text += f" ({_fmt_bytes(msg.get('bytes_done'))} of {_fmt_bytes(msg['total_bytes'])}"
        text += f", {msg.get('files_done', 0)} files)" if msg.get("files_done") is not None else ")"
    return text


def _hours(h: float) -> Optional[float]:
    return h * 3600 if h and h > 0 else None


def _tail_text(lines: List[str], n: int = 6) -> str:
    keep = [ln for ln in lines if ln.strip() and not ln.startswith('{"message_type":"status"')]
    return " | ".join(keep[-n:])[-800:] or "no output"


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "x"


def _now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def host_id(cfg: Config) -> str:
    return _safe(cfg.hostname or socket.gethostname())


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


def _write_atomic(path, data) -> None:
    """Write via temp file + rename; chmod failures ignored (CIFS: permissions come from mount options)."""
    path = Path(path)
    if isinstance(data, str):
        data = data.encode()
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def sha256_file(path, progress: Optional[Callable[[int], None]] = None) -> str:
    h, done = hashlib.sha256(), 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            if progress:
                done += len(chunk)
                progress(done)
    return h.hexdigest()


def sha256_with_progress(path: Path, emit: Optional[Reporter], why: str) -> str:
    """sha256 of a big file with a start message and progress every 30 s (no silent pauses)."""
    if emit is None:
        return sha256_file(path)
    size, last = path.stat().st_size, [time.monotonic()]
    emit("info", f"  computing sha256 of {path.name} ({_fmt_bytes(size)}, {why})...")

    def progress(done: int) -> None:
        if time.monotonic() - last[0] >= 30:
            last[0] = time.monotonic()
            emit("info", f"    sha256 {done * 100 // max(size, 1)}% ({_fmt_bytes(done)} of {_fmt_bytes(size)})")

    return sha256_file(path, progress)


def _fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def parse_size(s: str) -> int:
    """Proxmox-style size ('32G', '528K', '4M', '1.5T') -> bytes; 0 if unparseable."""
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([KMGTP]?)B?\s*$", s or "", re.I)
    if not m:
        return 0
    return int(float(m.group(1)) * 1024 ** (" KMGTP".index(m.group(2).upper() or " ")))


def parse_duration(s: str) -> int:
    """'90', '30s', '15m', '4h', '1d' -> seconds."""
    m = re.match(r"^\s*(\d+)\s*([smhd]?)\s*$", s or "", re.I)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid duration {s!r} (examples: 600, 30m, 4h)")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2).lower()]


def parse_stamp(stamp: str) -> Optional[dt.datetime]:
    for fmt, n in ((TS_FMT, 15), ("%Y_%m_%d-%H_%M_%S", 19)):
        try:
            return dt.datetime.strptime(stamp[:n], fmt)
        except ValueError:
            continue
    return None


def stamp_age_days(stamp: str) -> Optional[float]:
    for fmt, n in ((TS_FMT, 15), ("%Y_%m_%d-%H_%M_%S", 19)):
        try:
            return (dt.datetime.now() - dt.datetime.strptime(stamp[:n], fmt)).total_seconds() / 86400
        except ValueError:
            continue
    return None


def rfc3339_age_days(s: str) -> Optional[float]:
    try:
        s = re.sub(r"(\.\d{6})\d+", r"\1", s.strip()).replace("Z", "+00:00")
        t = dt.datetime.fromisoformat(s)
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        return (dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 86400
    except (ValueError, AttributeError):
        return None


def read_env_file(path: str) -> Dict[str, str]:
    """KEY=VALUE lines (export prefix and quotes allowed). Values are never logged."""
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        raise BackupError(f"env_file not found: {path}")
    out = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        k, sep, v = line.partition("=")
        if sep and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k.strip()):
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def emit_cifs_hints(emit: Reporter, msg: str) -> None:
    for pat, hint in CIFS_HINTS:
        if re.search(pat, msg, re.I):
            emit("info", f"  hint: {hint}")


def write_cifs_credentials(path: str, username: str, password: str, domain: str = "") -> None:
    if "\n" in username + password + domain:
        raise BackupError("credentials may not contain newlines")
    _mkdir_private(Path(path).parent)
    body = f"username={username}\npassword={password}\n" + (f"domain={domain}\n" if domain else "")
    _write_private(path, body)


def read_credentials(path: str) -> Tuple[str, str]:
    """username=/password= file (the CIFS credentials format)."""
    user = pw = ""
    for line in Path(path).read_text().splitlines():
        k, _, v = line.partition("=")
        k = k.strip().lower()
        if k in ("username", "user"):
            user = v.strip()
        elif k in ("password", "pass"):
            pw = v.strip()
    return user, pw


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


def _norm_unc(s: str) -> str:
    return s.replace("\\", "/").rstrip("/").lower()


# --------------------------------------------------------------------------- shared infrastructure
class LockManager:
    """
    Global non-blocking run lock (flock). Re-entrant within this process, so a module that takes
    the lock itself (LUKS) can run inside an orchestrated run. wait>0 polls instead of failing.
    """
    _held: Dict[str, list] = {}

    def __init__(self, path: Optional[str] = None, what: str = "server_backup", wait: int = 0):
        self.path, self.what, self.wait = path or LOCK_PATH, what, wait

    def __enter__(self):
        ent = LockManager._held.get(self.path)
        if ent:
            ent[1] += 1
            return self
        f = open(self.path, "w")
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    f.close()
                    raise BackupError(f"another {self.what} run is in progress ({self.path})")
                time.sleep(min(10.0, max(0.1, deadline - time.monotonic())))
        LockManager._held[self.path] = [f, 1]
        return self

    def __exit__(self, *exc):
        ent = LockManager._held[self.path]
        ent[1] -= 1
        if ent[1] <= 0:
            fcntl.flock(ent[0], fcntl.LOCK_UN)
            ent[0].close()
            del LockManager._held[self.path]

    @staticmethod
    def is_locked(path: Optional[str] = None) -> bool:
        """True if another process holds the lock (probe only)."""
        path = path or LOCK_PATH
        if path in LockManager._held:
            return False
        try:
            with open(path, "a") as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False
                except BlockingIOError:
                    return True
        except OSError:
            return False


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
        self.mnt = tempfile.mkdtemp(prefix="server-backup-cifs-")
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


class Destination:
    """
    The shared backup destination. With CIFS enabled the share is mounted on a fresh private temp
    dir (never a fixed path, so a failed mount can never be mistaken for the share), preflighted
    (fstype, optional marker file, write/read/delete test, free space), and kept mounted for the
    whole run while hold() is active. Large writers call assert_mounted() right before writing.
    """
    FSTYPES = ("cifs", "smb3")

    def __init__(self, cfg: Config, emit: Reporter):
        self.cfg, self.emit = cfg, emit
        self.host = host_id(cfg)
        self._cifs: Optional[CifsMount] = None
        self._mnt: Optional[Path] = None
        self._root: Optional[Path] = None
        self._depth = self._held = 0
        self._failure: Optional[str] = None
        self.preflight: dict = {}

    @property
    def remote(self) -> bool:
        return bool(self.cfg.cifs.enabled)

    @property
    def mounted(self) -> bool:
        return self._root is not None

    def local_dir(self, kind: str) -> Path:
        return Path(self.cfg.local_dir) / self.host / kind

    def display(self, p) -> str:
        try:
            return f"{self.cfg.cifs.share.rstrip('/')}/{Path(p).relative_to(self._mnt)}"
        except (ValueError, TypeError):
            return str(p)

    @contextlib.contextmanager
    def hold(self) -> Iterator["Destination"]:
        """Keep the share mounted (once first used) until the outermost hold() exits."""
        self._held += 1
        try:
            yield self
        finally:
            self._held -= 1
            if not self._held:
                self._failure = None
                if not self._depth:
                    self._close()

    @contextlib.contextmanager
    def session(self, test: bool = False) -> Iterator[Path]:
        """Yields <mnt>/<subdir>/<host> on the mounted, preflighted share."""
        if not (self.remote or test):
            raise BackupError("no CIFS destination enabled (cifs.enabled=false)")
        if self._failure:
            raise BackupError(self._failure)
        if self._root is None:
            try:
                self._open()
            except BackupError as e:
                self._close()
                if self._held:
                    self._failure = str(e)   # don't retry a 90 s mount timeout for every module
                raise
            except BaseException:
                self._close()
                raise
        self._depth += 1
        try:
            yield self._root
        finally:
            self._depth -= 1
            if not self._depth and not self._held:
                self._close()

    # overridable for tests
    def _mount_share(self) -> Path:
        self._cifs = CifsMount(self.cfg.cifs, self.emit)
        return self._cifs.__enter__()

    def _is_mount(self, path) -> bool:
        return os.path.ismount(path)

    def fstype(self, path) -> Tuple[str, str]:
        rc, out, _ = _run(["findmnt", "-n", "-o", "FSTYPE,SOURCE", "--mountpoint", str(path)])
        parts = out.strip().split(None, 1) if rc == 0 else []
        return (parts[0] if parts else ""), (parts[1].strip() if len(parts) > 1 else "")

    def _close(self) -> None:
        cm, self._cifs, self._mnt, self._root = self._cifs, None, None, None
        if cm:
            cm.__exit__(None, None, None)

    def assert_mounted(self) -> None:
        """Refuse to write unless the share is still mounted where we mounted it."""
        if self._mnt is None:
            raise BackupError("CIFS share is not mounted")
        fs, _ = self.fstype(self._mnt)
        if not self._is_mount(self._mnt) or fs not in self.FSTYPES:
            raise BackupError(f"CIFS share is no longer mounted at {self._mnt} (fstype '{fs or 'none'}'); "
                              "refusing to write to the local filesystem")

    def _open(self) -> None:
        c = self.cfg.cifs
        problems = self.cfg.cifs_problems()
        if problems:
            raise BackupError("CIFS configuration invalid: " + "; ".join(problems))
        self._mnt = mnt = self._mount_share()
        fs, src = self.fstype(mnt)
        if not self._is_mount(mnt) or fs not in self.FSTYPES:
            raise BackupError(f"mount reported success but {mnt} is not a CIFS mount (fstype '{fs or 'none'}')")
        if src and _norm_unc(src) != _norm_unc(c.share):
            self.emit("warning", f"mounted source {src} differs from configured share {c.share}")
        if c.marker_file and not (mnt / c.marker_file.lstrip("/")).is_file():
            raise BackupError(f"marker file '{c.marker_file}' not found on the share - wrong share mounted?")
        sub = c.subdir.strip("/")
        root = (mnt / sub / self.host) if sub else (mnt / self.host)
        root.mkdir(parents=True, exist_ok=True)
        t = root / f".server-backup-write-test-{os.getpid()}"
        payload = b"server-backup write test " + secrets.token_hex(16).encode() + b"\n"
        t.write_bytes(payload)
        try:
            if t.read_bytes() != payload:
                raise BackupError("write test read-back mismatch")
        finally:
            with contextlib.suppress(OSError):
                t.unlink()
        if t.exists():
            raise BackupError("write test file could not be deleted")
        free, need = self.free_bytes(root), int(c.min_free_gb * 1024 ** 3)
        if free < need:
            raise BackupError(f"only {_fmt_bytes(free)} free on the share (min_free_gb={c.min_free_gb})")
        self._root = root
        self.preflight = {"share": c.share, "mounted_at": str(mnt), "fstype": fs, "source": src,
                          "path": self.display(root), "free_bytes": free, "write_test": "ok"}
        self.emit("info", f"CIFS preflight OK: {self.display(root)} ({fs}), write/read/delete OK, "
                          f"{_fmt_bytes(free)} free")

    @staticmethod
    def free_bytes(path) -> int:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize


class Manifest:
    """sha256sum-compatible checksum files."""

    @staticmethod
    def write_sha256sums(d: Path) -> None:
        lines = [f"{sha256_file(p)}  {p.relative_to(d)}" for p in sorted(d.rglob("*"))
                 if p.is_file() and p.name != "SHA256SUMS"]
        _write_private(d / "SHA256SUMS", "\n".join(lines) + "\n")

    @staticmethod
    def verify_sha256sums(d: Path) -> List[str]:
        sums = d / "SHA256SUMS"
        if not sums.is_file():
            return [f"{d.name}: SHA256SUMS missing"]
        problems = []
        for line in sums.read_text().splitlines():
            h, _, rel = line.partition("  ")
            if not rel:
                continue
            p = d / rel
            if not p.is_file():
                problems.append(f"{d.name}/{rel}: missing")
            elif sha256_file(p) != h:
                problems.append(f"{d.name}/{rel}: checksum mismatch")
        return problems

    @staticmethod
    def write_sidecar(f: Path, emit: Optional[Reporter] = None, why: str = "") -> str:
        h = sha256_with_progress(f, emit, why)
        _write_atomic(f.with_name(f.name + ".sha256"), f"{h}  {f.name}\n")
        return h

    @staticmethod
    def check_sidecar(f: Path) -> Optional[bool]:
        """None = no sidecar; else whether the file matches it."""
        sc = f.with_name(f.name + ".sha256")
        if not sc.is_file():
            return None
        return sc.read_text().split()[0:1] == [sha256_file(f)]


class RetentionManager:
    @staticmethod
    def select(keys: List[str], last: int, daily: int = 0, weekly: int = 0, monthly: int = 0) -> set:
        """Which backups to keep: the newest `last`, plus the newest one in each of the last
        `daily` days / `weekly` ISO weeks / `monthly` months that have a backup. The newest is
        always kept. Keys are timestamps (20261120-191747 or 2026_11_20-19_17_47)."""
        order = sorted(keys, reverse=True)
        keep = set(order[:last]) if last > 0 else set()
        for n, fmt in ((daily, "%Y-%m-%d"), (weekly, "%G-W%V"), (monthly, "%Y-%m")):
            buckets: List[str] = []
            for k in order:
                if len(buckets) >= n:
                    break
                t = parse_stamp(k)
                if t is not None and t.strftime(fmt) not in buckets:
                    buckets.append(t.strftime(fmt))
                    keep.add(k)
        if order:
            keep.add(order[0])
        return keep

    @classmethod
    def prune_groups(cls, groups: Dict[str, List[Path]], valid, keep: int,
                     daily: int = 0, weekly: int = 0, monthly: int = 0) -> List[str]:
        """
        groups: timestamp -> files. Keeps the VALID groups chosen by select() and removes the other
        valid ones, plus failed/partial groups older than the oldest kept backup. Only valid groups
        count, so failed runs can never push out the last good backup. keep=0 and no keep_* = keep all.
        """
        if keep <= 0 and not (daily or weekly or monthly):
            return []
        good = sorted(k for k in groups if k in valid)
        kept = cls.select(good, keep, daily, weekly, monthly)
        if not good or len(kept) >= len(good):
            return []
        oldest = min(kept)
        removed = []
        for k in sorted(groups):
            if k in kept or (k not in valid and k > oldest):
                continue
            for p in groups[k]:
                shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
                removed.append(p.name)
        return removed

    @classmethod
    def prune_timestamped(cls, directory: Path, keep: int, daily: int = 0, weekly: int = 0,
                          monthly: int = 0) -> List[str]:
        """<ts>... entries (dirs, .tar.gpg, sidecars); every stamp counts (luks_backup.py rule).
        Callers only invoke this after a successful backup, so the newest stamp is always good."""
        if not directory.is_dir():
            return []
        groups: Dict[str, List[Path]] = {}
        for p in directory.iterdir():
            m = TS_RE.match(p.name)
            if m:
                groups.setdefault(m.group(1), []).append(p)
        return cls.prune_groups(groups, set(groups), keep, daily, weekly, monthly)


def _few(names: List[str], n: int = 5) -> str:
    return ", ".join(names[:n]) + (f" (+{len(names) - n} more)" if len(names) > n else "")


def ledger_label(kind: str, where) -> str:
    return f"{kind} @ {where}"


class Ledger:
    """
    Tamper detection: a local record of the backups this machine made, per destination
    ("collection"), as name -> fingerprint. Every run compares it with what is really there:
      gone or changed without this tool removing them -> error; retention pauses
      present but never made here                     -> warning
    Findings repeat on every run until `ledger --accept` re-baselines. The first run for a
    destination adopts whatever is there.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.was_missing = not self.path.exists()
        self.data: dict = {"version": 1, "collections": {}, "values": {}}
        self.dirty = False
        if not self.was_missing:
            try:
                self.data.update(json.loads(self.path.read_text()))
            except (OSError, ValueError) as e:
                raise BackupError(f"tamper ledger {self.path} is unreadable ({e}); move it aside to start "
                                  "a new baseline")

    @classmethod
    def for_config(cls, cfg: Config) -> "Ledger":
        return cls(Path(cfg.state_dir) / "ledger.json")

    def check(self, coll: str, current: Dict[str, str], ignore=()) -> Tuple[List[str], List[str]]:
        """(errors, warnings) for one destination; nothing if it has no baseline yet."""
        known = self.data["collections"].get(coll)
        if known is None:
            return [], []
        missing = sorted(n for n in known if n not in current)
        changed = sorted(n for n in known if n in current and known[n] != current[n])
        unknown = sorted(n for n in current if n not in known and n not in ignore)
        errs, warns = [], []
        if missing:
            errs.append(f"TAMPER CHECK {coll}: {len(missing)} backup(s) gone that this tool did not remove: "
                        f"{_few(missing)}")
        if changed:
            errs.append(f"TAMPER CHECK {coll}: {len(changed)} backup(s) changed since they were written: "
                        f"{_few(changed)}")
        if unknown:
            warns.append(f"TAMPER CHECK {coll}: {len(unknown)} backup(s) not made by this machine: {_few(unknown)}")
        return errs, warns

    def update(self, coll: str, current: Dict[str, str], added=(), removed=()) -> None:
        """After writing: add what we created, drop what we pruned; flagged entries stay flagged."""
        known = self.data["collections"].get(coll)
        if known is None:
            new = dict(current)
        else:
            new = {n: fp for n, fp in known.items() if n not in set(removed)}
            new.update({n: current[n] for n in added if n in current})
        self.data["collections"][coll] = new
        self.dirty = True

    def accept(self, coll: str, current: Dict[str, str]) -> None:
        self.data["collections"][coll] = dict(current)
        self.dirty = True

    def check_value(self, key: str, value: str) -> Optional[str]:
        old = self.data["values"].get(key)
        if old and value and old != value:
            return f"TAMPER CHECK {key}: was {old}, now {value}"
        return None

    def set_value(self, key: str, value: str, force: bool = False) -> None:
        if value and (force or not self.data["values"].get(key)):
            self.data["values"][key] = value
            self.dirty = True

    def save(self) -> None:
        if self.dirty:
            self.data["updated"] = _now()
            _mkdir_private(self.path.parent)
            _write_atomic(self.path, json.dumps(self.data, indent=2, sort_keys=True))
            self.dirty = False


def timestamped_entries(kind_dir: Path) -> Dict[str, str]:
    """Ledger fingerprints for <ts> backups: dir -> sha256(SHA256SUMS); .tar.gpg -> sidecar sha:size."""
    out: Dict[str, str] = {}
    if not kind_dir.is_dir():
        return out
    for p in kind_dir.iterdir():
        if not TS_RE.match(p.name) or p.name.endswith(".sha256"):
            continue
        if p.is_dir():
            s = p / "SHA256SUMS"
            out[p.name] = sha256_file(s) if s.is_file() else "no-SHA256SUMS"
        elif p.name.endswith(".tar.gpg"):
            sc = p.with_name(p.name + ".sha256")
            words = sc.read_text().split() if sc.is_file() else []
            out[p.name] = f"{words[0] if words else 'no-sidecar'}:{p.stat().st_size}"
    return out


def copy_verify(src: Path, dest_parent: Path) -> Path:
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


def latest_timestamped(kind_dir: Path) -> Optional[str]:
    if not kind_dir.is_dir():
        return None
    stamps = sorted({m.group(1) for p in kind_dir.iterdir() if (m := TS_RE.match(p.name))})
    return stamps[-1] if stamps else None


def verify_timestamped(kind_dir: Path) -> dict:
    """Latest <ts> backup in kind_dir: plain dir -> SHA256SUMS + tar readability; .tar.gpg -> sidecar."""
    out = {"dir": str(kind_dir), "latest": None, "age_days": None, "ok": False, "problems": []}
    s = latest_timestamped(kind_dir)
    if not s:
        out["problems"].append(f"no backups found in {kind_dir}")
        return out
    out["latest"], out["age_days"] = s, stamp_age_days(s)
    enc, d = kind_dir / f"{s}.tar.gpg", kind_dir / s
    if enc.is_file():
        sc = Manifest.check_sidecar(enc)
        out["artifact"] = enc.name
        if sc is False:
            out["problems"].append(f"{enc.name}: checksum mismatch")
        elif sc is None:
            out["notes"] = [f"{enc.name}: no .sha256 sidecar (made by luks_backup.py?); size {enc.stat().st_size}"]
            if enc.stat().st_size == 0:
                out["problems"].append(f"{enc.name}: empty")
    elif d.is_dir():
        out["artifact"] = d.name
        out["problems"] += Manifest.verify_sha256sums(d)
        for t in d.rglob("*.tar"):
            try:
                with tarfile.open(t) as tf:
                    tf.getmembers()
            except (tarfile.TarError, OSError) as e:
                out["problems"].append(f"{t.relative_to(d)}: unreadable tar ({e})")
    else:
        out["problems"].append(f"latest backup {s} has no directory or .tar.gpg")
    out["ok"] = not out["problems"]
    return out


class ArtifactPublisher:
    """
    Staged dir -> optional GPG .tar.gpg (+ .sha256) -> copy + verify on the share -> keep or drop
    the local copy. Retention only when prune_ok() (i.e. this backup succeeded). Shared by the
    LUKS and Proxmox host modules; logic from luks_backup.py _distribute().
    """

    def __init__(self, cfg: Config, emit: Reporter, dest: Destination, ledger: Optional["Ledger"] = None):
        self.cfg, self.emit, self.dest, self.ledger = cfg, emit, dest, ledger

    def _check(self, kind_dir: Path, label: str, errors: List[str], warnings: List[str], ignore=()) -> None:
        """Tamper findings go into errors, which also stops retention (prune_ok sees them)."""
        if self.ledger:
            e, w = self.ledger.check(label, timestamped_entries(kind_dir), ignore)
            errors += e
            warnings += w

    def _record(self, kind_dir: Path, label: str, added, removed) -> None:
        if self.ledger:
            self.ledger.update(label, timestamped_entries(kind_dir), added, removed)

    def publish(self, staging: Path, kind: str, retention: int, errors: List[str], warnings: List[str],
                prune_ok: Callable[[], bool], gfs: Tuple[int, int, int] = (0, 0, 0)) -> Tuple[List[dict], bool]:
        """Returns (destinations, local staging removed)."""
        local_kind = staging.parent
        local_label = ledger_label(kind, local_kind)
        if self.cfg.keep_local:
            self._check(local_kind, local_label, errors, warnings,
                        {staging.name, f"{staging.name}.tar.gpg"})
        artifact: Optional[Path] = staging
        if self.cfg.gpg_recipient:
            try:
                artifact = GpgEncryption(self.cfg).encrypt_dir(staging)
                self.emit("info", f"Encrypted archive: {artifact}")
            except BackupError as e:
                artifact = None  # never fall back to sending plaintext to the share
                if not any("GPG" in x for x in errors):
                    errors.append(f"{e}; nothing copied to CIFS")
        sidecar = artifact.with_name(artifact.name + ".sha256") if artifact and artifact.is_file() else None
        dests: List[dict] = []
        cifs_ok = False
        if self.cfg.cifs.enabled and artifact is not None:
            dest = {"type": "cifs", "share": self.cfg.cifs.share, "ok": False}
            try:
                with self.dest.session() as root:
                    kind_dir = root / kind
                    kind_dir.mkdir(parents=True, exist_ok=True)
                    label = ledger_label(kind, self.dest.display(kind_dir))
                    self._check(kind_dir, label, errors, warnings)
                    self.dest.assert_mounted()
                    out = copy_verify(artifact, kind_dir)
                    if sidecar and sidecar.is_file():
                        copy_verify(sidecar, kind_dir)
                    dest["path"] = self.dest.display(out)
                    dest["ok"] = cifs_ok = True
                    dest["pruned"] = RetentionManager.prune_timestamped(kind_dir, retention, *gfs) if prune_ok() else []
                    self._record(kind_dir, label, [out.name], dest["pruned"])
                    self.emit("info", f"Copied to {dest['path']} (verified)")
            except (BackupError, OSError) as e:
                dest["error"] = str(e)
                errors.append(f"CIFS copy failed: {e}")
                emit_cifs_hints(self.emit, str(e))
            dests.append(dest)
        if not prune_ok():
            self.emit("info", "Retention skipped: this backup had errors or tamper findings, older backups kept")
        if self.cfg.keep_local or not cifs_ok:
            pruned = RetentionManager.prune_timestamped(local_kind, retention, *gfs) if prune_ok() else []
            dests.append({"type": "local", "path": str(artifact or staging), "ok": True, "pruned": pruned})
            if self.cfg.keep_local:
                self._record(local_kind, local_label,
                             [p.name for p in (staging, artifact) if p is not None and p.exists()], pruned)
            else:
                warnings.append("keep_local=false but CIFS copy failed; local copy retained")
            return dests, False
        shutil.rmtree(staging)
        if artifact != staging:
            artifact.unlink()
            if sidecar and sidecar.exists():
                sidecar.unlink()
        return dests, True


# --------------------------------------------------------------------------- GPG
class GpgKeyring:
    """
    Minimal gpg wrapper.
      GpgKeyring(home)                    dedicated root-owned keyring (default /etc/server-backup/gnupg)
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
                                 "--output", "-"], input_bytes=b"server-backup test")
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


def _decrypt_and_check(kr: "GpgKeyring", passphrase: str, archive: Path, r: "ModuleResult") -> None:
    """Stream-decrypt a .tar.gpg and check its contents against the SHA256SUMS inside it.
    Nothing decrypted is written to disk."""
    p = subprocess.Popen(kr._cmd(["--decrypt", "--output", "-", str(archive)], passphrase=True),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    hashes: Dict[str, str] = {}
    sums, members = "", 0
    try:
        p.stdin.write(passphrase.encode() + b"\n")
        p.stdin.close()
        with tarfile.open(fileobj=p.stdout, mode="r|") as tf:
            for m in tf:
                members += 1
                if not m.isfile():
                    continue
                rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
                f = tf.extractfile(m)
                if rel == "SHA256SUMS":
                    data = f.read()
                    sums, hashes[rel] = data.decode(errors="replace"), hashlib.sha256(data).hexdigest()
                    continue
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
                hashes[rel] = h.hexdigest()
    except (tarfile.TarError, OSError) as e:
        p.kill()
        err = p.stderr.read().decode(errors="replace").strip()
        p.wait()
        raise BackupError(f"could not decrypt/read {archive.name}: {err or e}")
    finally:
        p.stdout.close()
        if p.returncode is not None:
            p.stderr.close()
    err = p.stderr.read().decode(errors="replace").strip()
    p.stderr.close()
    if p.wait():
        raise BackupError(f"gpg could not decrypt {archive.name}: {err}")
    bad = []
    for line in sums.splitlines():
        h, _, rel = line.partition("  ")
        if rel and hashes.get(rel) != h:
            bad.append(rel)
    if not sums:
        r.warnings.append(f"{archive.name}: decrypted ({members} entries) but it contains no SHA256SUMS")
    elif bad:
        r.errors.append(f"{archive.name}: decrypted, but {len(bad)} file(s) do not match SHA256SUMS: {_few(bad)}")
    else:
        r.notes.append(f"{archive.name}: decrypted and readable, {len(hashes)} files match SHA256SUMS "
                       "(nothing written to disk)")


def restore_key_test(key_data: bytes, passphrase: str, expect_fpr: str, archive: Optional[Path],
                     r: "ModuleResult") -> None:
    """Prove the backup key + passphrase work: temporary keyring, encrypt/decrypt round trip, then
    (optionally) decrypt a real archive. The keyring lives in /run (RAM) and is always deleted."""
    if b"PRIVATE KEY BLOCK" not in key_data:
        raise BackupError("that is not a private key; the test needs the PRIVATE key from Vaultwarden "
                          "(-----BEGIN PGP PRIVATE KEY BLOCK-----)")
    home = tempfile.mkdtemp(prefix="server-backup-gpgtest-", dir="/run" if os.access("/run", os.W_OK) else None)
    kr = GpgKeyring(home)
    try:
        rc, _, err = kr.run(["--import"], input_bytes=key_data)
        fprs = [k.fingerprint for k in kr.list_keys(secret=True)]
        if rc or not fprs:
            raise BackupError(f"could not import the private key: {err.strip() or 'no private key found'}")
        fpr = fprs[0]
        if expect_fpr:
            match = [f for f in fprs if f.upper() == expect_fpr.upper()]
            if match:
                fpr = match[0]
                r.notes.append(f"key {fpr[-16:]} is the backup key this machine encrypts to")
            else:
                r.errors.append(f"this private key ({', '.join(f[-16:] for f in fprs)}) is NOT the backup key "
                                f"configured here ({expect_fpr[-16:]}): archives from this machine cannot be "
                                "decrypted with it")
        if not kr.roundtrip(fpr, passphrase):
            raise BackupError("passphrase rejected: the test message could not be decrypted")
        r.notes.append("passphrase OK: a test message was encrypted and decrypted")
        if archive is not None:
            sc = Manifest.check_sidecar(archive)
            if sc is False:
                r.errors.append(f"{archive.name}: does not match its .sha256 file")
            _decrypt_and_check(kr, passphrase, archive, r)
    finally:
        kr.kill_agent()
        shutil.rmtree(home, ignore_errors=True)


def read_private_key(prompter: "Prompter", key_file: str = "") -> bytes:
    """The private backup key, from a file or pasted (e.g. the Vaultwarden note or attachment)."""
    if key_file:
        return Path(key_file).read_bytes()
    src = prompter.choose("Where is the private backup key?",
                          [("p", "Paste it - the Vaultwarden note (the whole note is fine)"),
                           ("f", "A file - e.g. the .SECRET.asc attachment downloaded from Vaultwarden")], default="p")
    if src == "f":
        path = prompter.text("Path to the .asc file")
        if not path or not os.path.isfile(path):
            raise BackupError(f"file not found: {path}")
        return Path(path).read_bytes()
    return prompter.paste("Paste the private key block (or the whole note):").encode()


def key_export_files(export_dir: Path, fpr: str) -> List[Path]:
    """Export files of one key, under the current or the legacy (luks-backup-key-*) name."""
    short = fpr[-8:]
    return sorted(p for prefix in (KEY_PREFIX, LEGACY_KEY_PREFIX) for p in export_dir.glob(f"{prefix}-{short}.*"))


PUBLIC_BLOCK_RE = re.compile(rb"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", re.S)


def public_key_material(data: bytes) -> Tuple[bytes, str]:
    """
    Public key(s) from what the user supplied: a public block, a whole password-manager note
    (passphrase + private + public block), or just the private block. In the last case the public
    half is extracted in a throw-away keyring that is deleted straight away; the private key is
    never stored. Returns (public key data, how it was obtained).
    """
    blocks = PUBLIC_BLOCK_RE.findall(data)
    if blocks:
        return b"\n".join(blocks) + b"\n", "public key block"
    if b"PRIVATE KEY BLOCK" not in data:
        raise BackupError("no PGP key block found (expected -----BEGIN PGP PUBLIC KEY BLOCK-----)")
    home = tempfile.mkdtemp(prefix="server-backup-gpg-", dir="/run" if os.access("/run", os.W_OK) else None)
    kr = GpgKeyring(home)
    try:
        rc, _, err = kr.run(["--import"], input_bytes=data)
        fprs = [k.fingerprint for k in kr.list_keys()]
        if rc or not fprs:
            raise BackupError(f"could not read the private key block: {err.strip() or 'no key found'}")
        return b"".join(kr.export_public(f) for f in fprs), "public half of the private key (private key not kept)"
    finally:
        kr.kill_agent()
        shutil.rmtree(home, ignore_errors=True)


class GpgEncryption:
    """Staged directory -> <name>.tar.gpg (+ <name>.tar.gpg.sha256) for the configured recipient."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def encrypt_dir(self, staging: Path) -> Path:
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
        Manifest.write_sidecar(out)
        return out


# --------------------------------------------------------------------------- detection
@dataclass
class Capabilities:
    hostname: str = ""
    host_type: str = ""                    # proxmox-host | virtual-machine | container | physical
    virtualization: str = ""
    os: str = ""
    is_root: bool = False
    tools: Dict[str, str] = field(default_factory=dict)
    luks_devices: List[str] = field(default_factory=list)
    modules: Dict[str, dict] = field(default_factory=dict)   # name -> {available, reason}
    cifs: dict = field(default_factory=dict)


class EnvironmentDetector:
    """What CAN run here. Never decides what SHOULD run - that is the config's job."""
    TOOLS = ("cryptsetup", "lsblk", "findmnt", "mount.cifs", "gpg", "restic", "qm", "vzdump",
             "qmrestore", "pveversion", "pct", "zstd", "systemd-cryptenroll")
    PVE_DIR = "/etc/pve"

    def __init__(self, cfg: Config, emit: Optional[Reporter] = None):
        self.cfg, self.emit = cfg, emit or (lambda lvl, msg: None)

    def detect(self, probe_luks: bool = True) -> Capabilities:
        c = Capabilities(hostname=host_id(self.cfg), is_root=os.geteuid() == 0)
        c.tools = {t: p for t in self.TOOLS if (p := shutil.which(t))}
        c.os = self._os_release()
        c.virtualization = self._virt()
        pve = os.path.isdir(self.PVE_DIR)
        if pve and "qm" in c.tools:
            c.host_type = "proxmox-host"
        elif c.virtualization in ("lxc", "lxc-libvirt", "openvz", "docker", "podman", "systemd-nspawn", "wsl"):
            c.host_type = "container"
        elif c.virtualization not in ("", "none"):
            c.host_type = "virtual-machine"
        else:
            c.host_type = "physical"
        if probe_luks and "lsblk" in c.tools:
            c.luks_devices = self._luks_devices()

        def mod(name, ok, reason):
            c.modules[name] = {"available": bool(ok), "reason": reason}

        if "cryptsetup" not in c.tools:
            mod("luks", False, "cryptsetup not installed")
        elif probe_luks and not c.luks_devices:
            mod("luks", False, "no LUKS volumes found")
        else:
            mod("luks", True, f"{len(c.luks_devices)} LUKS volume(s)" if probe_luks else "cryptsetup present")
        mod("files", "restic" in c.tools, "restic installed" if "restic" in c.tools else "restic not installed")
        missing = [t for t in ("qm", "vzdump") if t not in c.tools]
        mod("proxmox_vm", not missing, "qm + vzdump present" if not missing else f"{'/'.join(missing)} not found")
        mod("proxmox_host", pve, f"{self.PVE_DIR} present" if pve else f"{self.PVE_DIR} not found")
        cc = self.cfg.cifs
        c.cifs = {"configured": bool(cc.enabled and cc.share), "mount.cifs": "mount.cifs" in c.tools,
                  "available": bool(cc.enabled and cc.share and "mount.cifs" in c.tools)}
        return c

    @staticmethod
    def _os_release() -> str:
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return ""

    @staticmethod
    def _virt() -> str:
        if shutil.which("systemd-detect-virt"):
            try:
                _, out, _ = _run(["systemd-detect-virt"], timeout=20)
                return out.strip() or "none"
            except BackupError:
                pass
        return ""

    @staticmethod
    def _luks_devices() -> List[str]:
        try:
            rc, out, _ = _run(["lsblk", "-J", "-p", "-o", "NAME,FSTYPE"])
            if rc:
                return []
            found = []

            def walk(nodes):
                for n in nodes or []:
                    if (n.get("fstype") or "") == "crypto_LUKS" and n["name"] not in found:
                        found.append(n["name"])
                    walk(n.get("children"))
            walk(json.loads(out).get("blockdevices"))
            return found
        except (BackupError, ValueError):
            return []


def _existing(path: str) -> Optional[str]:
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    return str(p) if p.exists() else None


def disk_usage(cfg: Config, share_root: Optional[Path] = None, share_label: str = "") -> List[dict]:
    """
    How full everything the backups depend on is: the share, the local filesystems this tool writes
    to (/, local_dir, state_dir), the files module's source filesystems, extra disk_check_paths,
    LVM thin pools (data AND metadata - a full pool stalls every VM on it) and ZFS pools.
    Each entry: what, used_percent, free_bytes (None for pools), level (ok/warning/error).
    """
    out: List[dict] = []

    def add(what: str, pct: float, free: Optional[int]) -> None:
        level = ("error" if pct >= cfg.disk_error_percent else
                 "warning" if pct >= cfg.disk_warn_percent else "ok")
        out.append({"what": what, "used_percent": round(pct, 1), "free_bytes": free, "level": level})

    def fs(path: str, label: str, seen: set) -> None:
        try:
            st = os.statvfs(path)
            dev = os.stat(path).st_dev
        except OSError:
            return
        if dev in seen or st.f_blocks == 0:
            return
        seen.add(dev)
        used = st.f_blocks - st.f_bfree
        add(label, 100.0 * used / max(used + st.f_bavail, 1), st.f_bavail * st.f_frsize)

    if share_root is not None:
        fs(str(share_root), f"share {share_label or share_root}", set())
    seen: set = set()
    paths = [("/", "filesystem /"), (cfg.local_dir, "local_dir"), (cfg.state_dir, "state_dir")]
    if cfg.modules.files.enabled:
        paths += [(p, "backed-up path") for p in cfg.modules.files.paths]
    paths += [(p, "disk_check_paths") for p in cfg.disk_check_paths]
    for path, why in paths:
        real = _existing(path)
        if real:
            fs(real, f"filesystem {real}" + ("" if why.startswith("filesystem") else f" ({why})"), seen)
    if shutil.which("lvs"):
        with contextlib.suppress(BackupError, ValueError, KeyError, IndexError):
            rc, js, _ = _run(["lvs", "--reportformat", "json", "-o",
                              "vg_name,lv_name,lv_attr,data_percent,metadata_percent"], timeout=60)
            for lv in (json.loads(js)["report"][0]["lv"] if rc == 0 else []):
                if lv.get("lv_attr", "").startswith("t"):
                    for key, part in (("data_percent", "data"), ("metadata_percent", "metadata")):
                        if lv.get(key):
                            add(f"LVM thin pool {lv['vg_name']}/{lv['lv_name']} {part}", float(lv[key]), None)
    if shutil.which("zpool"):
        with contextlib.suppress(BackupError, ValueError):
            rc, txt, _ = _run(["zpool", "list", "-H", "-p", "-o", "name,capacity,free"], timeout=60)
            for line in txt.splitlines() if rc == 0 else []:
                name, cap, free = line.split("\t")[:3]
                add(f"ZFS pool {name}", float(cap.rstrip("%")), int(free))
    return out


def disk_messages(entries: List[dict]) -> Tuple[List[str], List[str]]:
    """(errors, warnings) for entries above the thresholds."""
    errs, warns = [], []
    for e in entries:
        if e["level"] == "ok":
            continue
        msg = f"disk: {e['what']} is {e['used_percent']:.0f}% full" + (
            f" ({_fmt_bytes(e['free_bytes'])} free)" if e["free_bytes"] is not None else "")
        if "metadata" in e["what"]:
            msg += " - a thin pool with full metadata can go read-only or be damaged; extend it (lvextend --poolmetadatasize)"
        elif "thin pool" in e["what"]:
            msg += " - VMs on a full thin pool stall with I/O errors"
        (errs if e["level"] == "error" else warns).append(msg)
    return errs, warns


@dataclass
class RunContext:
    cfg: Config
    emit: Reporter
    prompter: Prompter
    dest: Destination
    host: str
    config_path: Optional[Path] = None
    reporter: Optional[Reporter] = None
    profile: str = ""
    vmids: List[int] = field(default_factory=list)   # restricts proxmox_vm to these configured IDs
    deep: bool = False
    ledger: Optional[Ledger] = None


def ledger_findings(ctx: RunContext, label: str, current: Dict[str, str], r: ModuleResult,
                    prefix: str = "") -> bool:
    """Read-only tamper check into a result; True if something is gone or changed."""
    if not ctx.ledger:
        return False
    e, w = ctx.ledger.check(label, current)
    r.errors += [prefix + x for x in e]
    r.warnings += [prefix + x for x in w]
    return bool(e)


def verify_stored(ctx: RunContext, kind: str, stale_days: int, r: ModuleResult) -> None:
    """Check the latest timestamped backup (LUKS/host config) on the share and/or locally."""
    checked = []
    if ctx.cfg.cifs.enabled:
        try:
            with ctx.dest.session() as root:
                checked.append(("cifs", verify_timestamped(root / kind)))
                ledger_findings(ctx, ledger_label(kind, ctx.dest.display(root / kind)),
                                timestamped_entries(root / kind), r)
        except (BackupError, OSError) as e:
            r.errors.append(f"CIFS: {e}")
    local = ctx.dest.local_dir(kind)
    if ctx.cfg.keep_local or not ctx.cfg.cifs.enabled or local.is_dir():
        checked.append(("local", verify_timestamped(local)))
        ledger_findings(ctx, ledger_label(kind, local), timestamped_entries(local), r)
    for where, res in checked:
        res["location"] = where
        r.artifacts.append(res)
        for p in res["problems"]:
            r.errors.append(f"{where}: {p}")
        r.notes += [f"{where}: {n}" for n in res.get("notes", [])]
        age = res.get("age_days")
        if res["latest"]:
            r.notes.append(f"{where}: latest {res['latest']} ({age:.1f} days old)" if age is not None
                           else f"{where}: latest {res['latest']}")
        if age is not None and stale_days and age > stale_days:
            r.warnings.append(f"{where}: latest backup is {age:.0f} days old (stale_after_days={stale_days})")


# --------------------------------------------------------------------------- LUKS module
class LuksBackupService:
    def __init__(self, cfg: Config, prompter: Optional[Prompter] = None,
                 reporter: Optional[Reporter] = None, config_path: Optional[Path] = None,
                 dest: Optional[Destination] = None, ledger: Optional[Ledger] = None):
        self.cfg = cfg
        self.prompter = prompter or Prompter()
        self.reporter = reporter or (lambda lvl, msg: None)
        self.config_path = Path(config_path) if config_path else None
        self.config_dirty = False
        self.dest = dest or Destination(cfg, self.emit)
        self.ledger = ledger
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
                             ".\n  NOTE: backup encryption is OFF - backups (and the share) will contain it "
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
        host = host_id(self.cfg)
        rep = BackupReport(host=host, timestamp=now.strftime(TS_FMT), started=now.isoformat(timespec="seconds"),
                           mode="backup" if opts.write else "verify")
        with LockManager(), LockManager(LEGACY_LOCK_PATH, "luks_backup"):
            for f in self.pending_key_exports():
                rep.warnings.append(f"private key export {f} is still on this machine: copy it to secure "
                                    "storage (e.g. Vaultwarden) and delete it (see gpg-status)")
            if opts.write and self.cfg.gpg_recipient:
                st = self.gpg_status()
                if not st.encrypt_test_ok:
                    rep.errors.append(f"GPG encryption not usable ({st.message}); backup kept local only, "
                                      "nothing copied to CIFS - run gpg-setup")
            if opts.write:
                kind_dir = Path(self.cfg.local_dir) / host / "luks"
                self._staging = kind_dir / rep.timestamp
                for d in (Path(self.cfg.local_dir), kind_dir.parent, kind_dir, self._staging):
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
        Manifest.write_sha256sums(s)

    def _distribute(self, rep: BackupReport) -> None:
        def ok() -> bool:  # retention only after a good backup: never displace the last good one
            return not rep.errors and not any(d.status == "error" for d in rep.devices)

        dests, removed = ArtifactPublisher(self.cfg, self.emit, self.dest, self.ledger).publish(
            self._staging, "luks", self.cfg.retention, rep.errors, rep.warnings, ok)
        rep.destinations.extend(dests)
        if removed:
            rep.staging_dir = ""

    def _finish(self, rep: BackupReport) -> BackupReport:
        rep.finished = dt.datetime.now().isoformat(timespec="seconds")
        if rep.errors or any(d.status == "error" for d in rep.devices):
            rep.status, rep.exit_code = "error", EXIT_ERROR
        elif rep.warnings or any(d.status == "warning" for d in rep.devices):
            rep.status, rep.exit_code = "warning", EXIT_WARN
        if self.config_path:
            try:
                _write_private(self.config_path.parent / "last_luks_run.json", json.dumps(rep.to_dict(), indent=2))
            except OSError:
                pass
        return rep

    # ---- CIFS setup / test
    def test_cifs(self) -> bool:
        """Full destination preflight (mount, fstype, write/read/delete, free space), then unmount."""
        self.require_root()
        c = self.cfg.cifs
        user = read_cifs_username(c.credentials_file)
        self.emit("info", f"Testing {c.share} as '{user or '?'}' (options: {c.mount_options or 'none'})")
        try:
            with Destination(self.cfg, self.emit).session(test=True):
                self.emit("info", "  mount, fstype, write/read/delete and free-space checks OK")
            self.emit("info", "  unmount OK - CIFS test PASSED")
            return True
        except (BackupError, OSError) as e:
            self.emit("error", f"CIFS test FAILED: {e}")
            emit_cifs_hints(self.emit, str(e))
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
            self.emit("info", f"Backup encryption key ({GPG_SCOPE}): OFF")
        else:
            uid = st.key.uid if st.key else "?"
            self.emit("info", f"Backup encryption key ({GPG_SCOPE}): "
                              f"{'READY' if st.encrypt_test_ok else 'NOT WORKING'} - {uid} [{st.recipient}]")
            if not st.encrypt_test_ok:
                self.emit("warning", f"  {st.message}")
            if st.secret_on_machine:
                self.emit("warning", "  the private key is stored on this machine; backups are only "
                                     "recoverable while this machine works")
        if st.public_key_file:
            self.emit("info", f"  public key (to reuse the key on other machines): {st.public_key_file}")
        for f in st.pending_exports:
            self.emit("warning", f"  PRIVATE KEY WAITING TO BE MOVED: {f}")
            self.emit("info", f"    1) attach {f} to a Vaultwarden item (or cat it and paste it into a secure "
                              "note), and store the passphrase in the same item")
            self.emit("info", f"    2) test it: server_backup.py gpg-test --key-file {f}")
            self.emit("info", f"    3) rm {f}")
            self.emit("info", "    Without that private key + passphrase the encrypted archives cannot be restored.")

    def _passphrase_for_new_key(self) -> str:
        p = self.prompter
        self.emit("info", "Choose a passphrase that protects the private backup key (needed only to RESTORE).\n"
                          "  Leave blank to generate a strong random one.")
        for _ in range(3):
            pw = p.secret("Passphrase (input hidden)")
            if not pw:
                pw = "-".join(secrets.token_urlsafe(6) for _ in range(4))
                # straight to the terminal: secrets never go through emit() (that also writes the log file)
                sys.stderr.write(f"\n  Generated passphrase:  {pw}\n"
                                 "  Save it in Vaultwarden NOW; the key itself follows once it is created.\n\n")
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
        c, host = self.cfg, host_id(self.cfg)
        kr = GpgKeyring(c.gpg_home)
        pw = self._passphrase_for_new_key()
        uid = f"server-backup key ({host} {dt.datetime.now():%Y-%m-%d %H%M%S}) <server-backup@{host}>"
        self.emit("info", "Generating key...")
        fpr, done = None, False
        try:
            fpr = kr.generate(uid, pw)
            if not kr.roundtrip(fpr, pw):
                raise BackupError("encrypt/decrypt self-test failed")
            short = fpr[-8:]
            _mkdir_private(c.gpg_export_dir)
            sec = c.gpg_export_dir / f"{KEY_PREFIX}-{short}.SECRET.asc"
            pub = c.gpg_export_dir / f"{KEY_PREFIX}-{short}.pub.asc"
            _write_private(sec, kr.export_secret(fpr, pw))
            _write_private(pub, kr.export_public(fpr))
            kr.delete_secret(fpr)  # this machine only needs the public key to encrypt
            done = True
        finally:
            if fpr and not done:  # failed part-way: remove the half-made key and its exports
                kr.delete_key(fpr)
                for f in key_export_files(c.gpg_export_dir, fpr):
                    f.unlink()
                self.emit("warning", "  key generation did not complete; partial key removed")
            kr.kill_agent()
            del pw
        self.emit("info", f"Backup key created and self-tested: {fpr}")
        self.emit("info", "The private key was removed from the keyring; the only copy is the export file.")
        self._hand_over_key(sec, pub, fpr)
        return fpr

    def _hand_over_key(self, sec: Path, pub: Path, fpr: str) -> None:
        """Show the new key pair for the password manager, then delete the private-key export."""
        p = self.prompter
        sys.stderr.write(f"\n  Store the key in ONE Vaultwarden item, e.g. \"server-backup key {sec.name.split('-')[-1][:8]}\",\n"
                         "  together with the passphrase (password field). It decrypts the\n"
                         f"  {GPG_SCOPE} of every machine that uses this key. Either:\n"
                         f"    a) attach the files {sec}\n"
                         f"       and {pub} to the item (copy them off with scp), or\n"
                         "    b) paste the key blocks into a secure note (shown next if you choose).\n"
                         "  Then test the copy in Vaultwarden before this machine deletes its own.\n\n")
        if p.confirm("Show the key blocks now to paste into a note?", True):
            # straight to the terminal: never through emit(), which also writes the log file
            sys.stderr.write(sec.read_text() + "\n" + pub.read_text() + "\n")
        tested = False
        while p.confirm("Test the copy saved in Vaultwarden now (paste it or use the downloaded file)?", True):
            r = ModuleResult("gpg", "gpg-test")
            try:
                restore_key_test(read_private_key(p), p.secret("Passphrase (input hidden)"), fpr, None, r)
            except BackupError as e:
                r.errors.append(str(e))
            for n in r.notes:
                self.emit("info", f"  {n}")
            for e in r.errors:
                self.emit("error", f"  {e}")
            if not r.errors:
                tested = True
                break
        if p.confirm(f"Delete {sec.name} from this machine now?", tested):
            sec.unlink()
            self.emit("info", f"  deleted {sec}; the public key stays at {pub}")
        else:
            self.emit("warning", f"  private key still at {sec}: delete it once it is saved (see gpg-status)")

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
        _write_private(self.cfg.gpg_export_dir / f"{KEY_PREFIX}-{k.fingerprint[-8:]}.pub.asc",
                       ukr.export_public(k.fingerprint))
        if k.expires:
            self.emit("warning", f"  this key expires {k.expires}; backups will fail after that until renewed")
        self.emit("info", f"Using {user}'s key {k.fingerprint}. Your private key stays in {user}'s keyring - "
                          "make sure it is backed up (e.g. Vaultwarden).")
        return k.fingerprint

    def _gpg_import(self) -> Optional[str]:
        """Reuse an existing backup key: paste it (e.g. the Vaultwarden note) or read a file."""
        p = self.prompter
        src = p.choose("Where is the backup key?",
                       [("p", "Paste it - e.g. the whole Vaultwarden note; a public or private block both work"),
                        ("f", "A file - e.g. server-backup-key-*.pub.asc copied from another machine"),
                        ("b", "Back")], default="p")
        if src == "b":
            return None
        if src == "f":
            path = p.text("Path to the .asc file")
            if not path or not os.path.isfile(path):
                self.emit("warning", "  file not found")
                return None
            data = Path(path).read_bytes()
        else:
            data = p.paste("Paste the key block(s):").encode()
        data, how = public_key_material(data)
        self.emit("info", f"  using the {how}")
        fprs = GpgKeyring(self.cfg.gpg_home).import_public(data)
        if fprs:
            _mkdir_private(self.cfg.gpg_export_dir)
            _write_private(self.cfg.gpg_export_dir / f"{KEY_PREFIX}-{fprs[0][-8:]}.pub.asc",
                           GpgKeyring(self.cfg.gpg_home).export_public(fprs[0]))
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
            if any(f.name in exports for f in key_export_files(c.gpg_export_dir, k.fingerprint)):
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
                    for f in key_export_files(c.gpg_export_dir, k.fingerprint):
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
        self.emit("info", f"\nThe backup encryption key encrypts the {GPG_SCOPE}, so people with access to\n"
                          "the share cannot read LUKS headers/keys or host secrets (/etc/pve/priv). VM images and\n"
                          "Restic are not covered (Restic has its own password). This machine stores only the\n"
                          "PUBLIC key; the private key + passphrase (kept in Vaultwarden) are needed only to restore.")
        options = [("g", "Generate a new backup key (first machine; reuse it on the others)")]
        if GpgKeyring(c.gpg_home).list_keys():
            options.append(("e", f"Use or delete a key already in the backup keyring ({c.gpg_home})"))
        if sudo_user:
            options.append(("u", f"Use one of {sudo_user}'s existing GPG keys"))
        options += [("i", "Use the existing backup key: paste it from Vaultwarden, or a file"),
                    ("n", "No encryption")]
        if c.gpg_recipient:
            options.insert(0, ("k", "Keep current setting"))
        default = "k" if c.gpg_recipient else ("g" if c.cifs.enabled else "n")
        while True:
            ch = p.choose("Backup encryption key:", options, default=default)
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
        c.retention = ask_int("LUKS backups to keep per destination (0 = keep all)", c.retention)
        c.cifs.enabled = p.confirm("Copy backups to a CIFS/SMB share?", c.cifs.enabled)
        if c.cifs.enabled:
            self.configure_cifs()
            c.keep_local = p.confirm("Also keep the local copy (LUKS / host config)?", c.keep_local)
        else:
            c.keep_local = True
        self.configure_gpg()
        globs = p.text("Keyfile search globs (comma-separated)", ",".join(c.keyfile_globs))
        c.keyfile_globs = [g.strip() for g in globs.split(",") if g.strip()]
        self.config_dirty = True
        return c


README_TEMPLATE = """LUKS header/key backup - host {host} - {ts}
Created by server_backup.py {tool} (LUKS module); {cs}

Contents
  headers/   cryptsetup luksHeaderBackup images (<dev>_<uuid>.luksheader.img)
  dumps/     luksDump / systemd-cryptenroll listings at backup time
  keys/      keyfiles (and saved passphrases, passphrase-slotN.txt) verified to unlock the
             device and the header backup. Use with --key-file, or: cat the .txt to read it.
  system/    crypttab(s), lsblk.json
  manifest.json, SHA256SUMS  (verify: sha256sum -c SHA256SUMS)

If you received this as <timestamp>.tar.gpg (encrypted archive)
  sha256sum -c <timestamp>.tar.gpg.sha256              # integrity, no key needed
  gpg --import server-backup-key-XXXXXXXX.SECRET.asc   # once: the backup key from Vaultwarden
                                                       # (older keys are named luks-backup-key-*)
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


# --------------------------------------------------------------------------- Restic module
class DirectoryBackupService:
    """Restic orchestration: repository access, backup, forget/prune, check, snapshots, restore test."""
    name = "files"

    def __init__(self, ctx: RunContext):
        self.ctx, self.cfg, self.emit = ctx, ctx.cfg, ctx.emit
        self.repo_id = ""

    @property
    def mc(self) -> FilesModuleConfig:
        return self.cfg.modules.files

    @property
    def ledger_coll(self) -> str:
        return ledger_label("files", self.repo_display())

    @property
    def ledger_repo_key(self) -> str:
        return f"files repository id @ {self.repo_display()}"

    @property
    def uses_share(self) -> bool:
        return not self.mc.repository.strip()

    def repo_display(self) -> str:
        if not self.uses_share:
            return self.mc.repository.strip()
        c = self.cfg.cifs
        return "/".join(x for x in (c.share.rstrip("/"), c.subdir.strip("/"), self.ctx.host, "restic") if x)

    @contextlib.contextmanager
    def environment(self) -> Iterator[Tuple[Dict[str, str], Optional[Path]]]:
        """Yields (env for restic, share root or None). Holds the share mounted while in use."""
        if self.uses_share:
            if not self.cfg.cifs.enabled:
                raise BackupError("files.repository is empty (= on the CIFS share) but CIFS is not enabled")
            with self.ctx.dest.session() as root:
                yield self._env(str(root / "restic")), root
        else:
            yield self._env(self.mc.repository.strip()), None

    def _env(self, repo: str) -> Dict[str, str]:
        pw = Path(self.mc.password_file)
        if not pw.is_file():
            raise BackupError(f"Restic password file not found: {pw} (run files-init)")
        if pw.stat().st_mode & 0o077:
            self.emit("warning", f"{pw} is group/world accessible; chmod 400 recommended")
        env = {k: v for k, v in os.environ.items() if not k.startswith("RESTIC_")}
        env.update(read_env_file(self.mc.env_file))
        env.update({"RESTIC_REPOSITORY": repo, "RESTIC_PASSWORD_FILE": str(pw),
                    "RESTIC_CACHE_DIR": self.mc.cache_dir})
        env.setdefault("RESTIC_PROGRESS_FPS", "0.1")   # a status line every 10 s (shown every 30 s)
        _mkdir_private(self.mc.cache_dir)
        return env

    def _restic(self, args: List[str], env: Dict[str, str], timeout: int = 600) -> Tuple[int, str, str]:
        return _run(["restic"] + args, env=env, timeout=timeout)

    def repo_state(self, env: Dict[str, str]) -> Tuple[bool, str]:
        rc, out, err = self._restic(["cat", "config"], env, timeout=300)
        if rc == 0:
            try:
                self.repo_id = str(json.loads(out).get("id") or "")
            except (ValueError, AttributeError):
                self.repo_id = ""
            return True, "ok"
        if rc == 12 or "wrong password" in err.lower():
            raise BackupError("Restic repository password is wrong (check password_file)")
        if rc == 10 or re.search(r"does not exist|Is there a repository|unable to open config file", err, re.I):
            return False, f"Restic repository {self.repo_display()} is not initialised (run files-init)"
        raise BackupError(f"cannot open Restic repository: {err.strip()[-300:]}")

    def require_repo(self, env: Dict[str, str]) -> None:
        ok, msg = self.repo_state(env)
        if not ok:
            known = (self.ctx.ledger.data["collections"].get(self.ledger_coll) or {}) if self.ctx.ledger else {}
            if known:
                msg = (f"TAMPER CHECK {self.ledger_coll}: repository is gone but held {len(known)} snapshot(s) "
                       "made by this machine")
            raise BackupError(msg)

    def policy(self) -> List[str]:
        out = []
        for k in ("last", "daily", "weekly", "monthly", "yearly"):
            n = getattr(self.mc, f"keep_{k}")
            if n > 0:
                out += [f"--keep-{k}", str(n)]
        return out

    def check_paths(self, r: ModuleResult) -> List[str]:
        ok = []
        if not self.mc.paths:
            r.errors.append("no paths configured (modules.files.paths)")
        for p in self.mc.paths:
            if os.path.exists(p):
                ok.append(p)
            elif self.mc.allow_missing_paths:
                r.warnings.append(f"configured path missing, NOT backed up: {p}")
            else:
                r.errors.append(f"configured path missing: {p} (fix it, or set allow_missing_paths)")
        return ok

    def snapshots(self, env: Dict[str, str], latest: int = 0) -> List[dict]:
        args = ["snapshots", "--json", "--host", self.ctx.host, "--tag", RESTIC_TAG]
        if latest:
            args += ["--latest", str(latest)]
        rc, out, err = self._restic(args, env)
        if rc:
            raise BackupError(f"restic snapshots failed: {err.strip()[-300:]}")
        try:
            return json.loads(out or "[]") or []
        except ValueError:
            raise BackupError("unexpected output from restic snapshots")

    def latest_snapshot(self, env: Dict[str, str]) -> Optional[dict]:
        snaps = self.snapshots(env, latest=1)
        return snaps[-1] if snaps else None

    def snapshot_entries(self, env: Dict[str, str]) -> Dict[str, str]:
        """Ledger fingerprints: snapshot id -> time (ids are content hashes, so changes show as gone+new)."""
        return {s["id"]: s.get("time", "") for s in self.snapshots(env)}

    def tamper_check(self, env: Dict[str, str], r: ModuleResult) -> Tuple[bool, Dict[str, str]]:
        """(found something, current snapshots). Call after repo_state()/require_repo()."""
        current = self.snapshot_entries(env)
        bad = ledger_findings(self.ctx, self.ledger_coll, current, r)
        if self.ctx.ledger:
            msg = self.ctx.ledger.check_value(self.ledger_repo_key, self.repo_id)
            if msg:
                r.errors.insert(0, msg + " (repository replaced?)")
                bad = True
        return bad, current

    # ---- size cap
    def _patterns(self) -> List[str]:
        pats = list(self.mc.excludes)
        for f in self.mc.exclude_files:
            with contextlib.suppress(OSError):
                pats += [ln.strip() for ln in Path(f).read_text().splitlines()
                         if ln.strip() and not ln.lstrip().startswith("#")]
        return [os.path.expandvars(p) for p in pats]

    @staticmethod
    def excluded(path: str, patterns: List[str]) -> bool:
        """Close approximation of restic --exclude: '/x' anchors at the root, other patterns match
        any run of path components ('*.tmp', 'node_modules', '**/build/*.o')."""
        parts = path.strip("/").split("/")
        for p in patterns:
            if p.startswith("/"):
                if fnmatch.fnmatchcase(path, p) or path.startswith(p.rstrip("/") + "/"):
                    return True
                continue
            rel = p[3:] if p.startswith("**/") else p
            n = rel.count("/") + 1
            if any(fnmatch.fnmatchcase("/".join(parts[i:i + n]), rel) for i in range(len(parts) - n + 1)):
                return True
        return False

    def find_large_files(self, paths: List[str]) -> List[Tuple[int, str]]:
        """Regular files above max_file_size under the paths, honouring excludes, exclude_caches and
        one_file_system. Reads metadata only. Largest first."""
        limit, pats, big = parse_size(self.mc.max_file_size), self._patterns(), []

        def consider(full: str) -> None:
            try:
                st = os.lstat(full)
            except OSError:
                return
            if stat.S_ISREG(st.st_mode) and st.st_size > limit and not self.excluded(full, pats):
                big.append((st.st_size, full))

        for top in paths:
            if os.path.isfile(top):
                consider(top)
                continue
            try:
                dev = os.lstat(top).st_dev
            except OSError:
                continue
            for root, dirs, files in os.walk(top):
                keep = []
                for d in dirs:
                    full = os.path.join(root, d)
                    if self.excluded(full, pats):
                        continue
                    if self.mc.exclude_caches and os.path.isfile(os.path.join(full, "CACHEDIR.TAG")):
                        continue
                    if self.mc.one_file_system:
                        try:
                            if os.lstat(full).st_dev != dev:
                                continue
                        except OSError:
                            continue
                    keep.append(d)
                dirs[:] = keep
                for f in files:
                    consider(os.path.join(root, f))
        return sorted(big, reverse=True)

    def _large_files(self, paths: List[str], r: ModuleResult) -> List[str]:
        """Report files over the cap; returns extra restic args (exclude mode)."""
        mc = self.mc
        if not mc.max_file_size:
            return []
        big = self.find_large_files(paths)
        exclude = mc.large_file_action == "exclude"
        if big:
            total = sum(s for s, _ in big)
            r.warnings.append(f"{len(big)} file(s) larger than {mc.max_file_size} "
                              f"{'EXCLUDED' if exclude else 'backed up anyway'} ({_fmt_bytes(total)}): "
                              + _few([f"{p} ({_fmt_bytes(s)})" for s, p in big]))
            r.details["large_files"] = {"limit": mc.max_file_size, "action": mc.large_file_action,
                                        "count": len(big), "total_bytes": total,
                                        "files": [{"path": p, "size": s} for s, p in big[:500]]}
        else:
            r.notes.append(f"no files larger than {mc.max_file_size}")
        return ["--exclude-larger-than", mc.max_file_size.upper()] if exclude else []

    # ---- operations
    def backup(self) -> ModuleResult:
        r = ModuleResult(self.name, "backup", started=_now())
        mc = self.mc
        paths = self.check_paths(r)
        if r.errors or not paths:
            return r
        size_args = self._large_files(paths, r)
        with self.environment() as (env, root):
            self.require_repo(env)
            self._restic(["unlock"], env)   # removes stale locks only
            tampered, before = self.tamper_check(env, r)
            args = ["backup", "--json", "--host", self.ctx.host, "--tag", RESTIC_TAG]
            for t in mc.tags + ([f"profile-{self.ctx.profile}"] if self.ctx.profile else []):
                args += ["--tag", t]
            for e in mc.excludes:
                args += ["--exclude", e]
            for f in mc.exclude_files:
                args += ["--exclude-file", f]
            if mc.exclude_caches:
                args.append("--exclude-caches")
            if mc.one_file_system:
                args.append("--one-file-system")
            args += size_args + [str(a) for a in mc.extra_backup_args] + ["--"] + paths
            summary: dict = {}
            unreadable: List[str] = []
            progress = Progress(self.emit, "restic backup")

            def on_line(line: str) -> None:
                if not line.startswith("{"):
                    return
                try:
                    msg = json.loads(line)
                except ValueError:
                    return
                if msg.get("message_type") == "summary":
                    summary.update(msg)
                elif msg.get("message_type") == "status":
                    progress.update(restic_status_text(msg))
                elif msg.get("message_type") == "error":
                    unreadable.append(f"{msg.get('item', '?')}: {(msg.get('error') or {}).get('message', '')}")

            if root is not None:
                self.ctx.dest.assert_mounted()
            self.emit("info", f"restic backup of {len(paths)} path(s) to {self.repo_display()}"
                              + (f", excludes: {', '.join(mc.excludes)}" if mc.excludes else ", no excludes"))
            rc, tail = _run_long(["restic"] + args, env=env, timeout=_hours(mc.timeout_hours), on_line=on_line)
            snap = summary.get("snapshot_id") or ""
            if rc == 3 and snap:
                r.warnings.append(f"snapshot {snap[:8]} created but {len(unreadable)} item(s) could not be read: "
                                  + "; ".join(unreadable[:5]))
            elif rc != 0 or not snap:
                r.errors.append(f"restic backup failed (rc={rc}): {_tail_text(tail)}")
                r.notes.append("retention skipped: no new snapshot, existing snapshots untouched")
                return r
            keys = ("snapshot_id", "files_new", "files_changed", "files_unmodified", "dirs_new", "data_added",
                    "total_files_processed", "total_bytes_processed", "total_duration")
            r.details["summary"] = {k: summary.get(k) for k in keys}
            r.artifacts.append({"type": "restic-snapshot", "id": snap, "repository": self.repo_display(),
                                "paths": paths})
            r.summary = (f"snapshot {snap[:8]}: {summary.get('files_new', 0)} new, "
                         f"{summary.get('files_changed', 0)} changed, {_fmt_bytes(summary.get('data_added'))} added "
                         f"of {_fmt_bytes(summary.get('total_bytes_processed'))}")
            if tampered:
                r.notes.append("retention paused because of tamper findings (see `ledger --accept`)")
            else:
                self._forget(env, r)
            if self.ctx.ledger:
                after = self.snapshot_entries(env)
                removed = (set(before) | {snap}) - set(after)   # only our own forget ran in between
                self.ctx.ledger.update(self.ledger_coll, after, added=[snap], removed=removed)
                self.ctx.ledger.set_value(self.ledger_repo_key, self.repo_id)
            if mc.check_after_backup:
                self._check(env, r, mc.check_read_data_subset)
            if root is not None:
                self.write_readme(root)
        return r

    def _forget(self, env: Dict[str, str], r: ModuleResult) -> None:
        pol = self.policy()
        if not pol:
            r.warnings.append("no keep_* retention configured; nothing forgotten")
            return
        args = ["forget", "--host", self.ctx.host, "--tag", RESTIC_TAG] + pol + (["--prune"] if self.mc.prune else [])
        rc, tail = _run_long(["restic"] + args, env=env)
        if rc:
            r.warnings.append(f"restic forget/prune failed (rc={rc}), snapshots kept: {_tail_text(tail)}")
        else:
            r.notes.append("retention applied: " + " ".join(pol) + (" + prune" if self.mc.prune else ""))

    def _check(self, env: Dict[str, str], r: ModuleResult, subset: str = "") -> None:
        args = ["check"] + ([f"--read-data-subset={subset}"] if subset else [])
        rc, tail = _run_long(["restic"] + args, env=env)
        if rc:
            r.errors.append(f"restic check failed (rc={rc}): {_tail_text(tail)}")
        else:
            r.notes.append("restic check OK" + (f" (read data subset {subset})" if subset else " (structure)"))

    def verify(self, deep: bool = False) -> ModuleResult:
        r = ModuleResult(self.name, "verify", started=_now())
        with self.environment() as (env, _):
            self.require_repo(env)
            self.tamper_check(env, r)
            self._check(env, r, self.mc.check_read_data_subset or ("5%" if deep else ""))
            snap = self.latest_snapshot(env)
            if not snap:
                r.errors.append(f"no snapshots for host {self.ctx.host} in {self.repo_display()}")
            else:
                age = rfc3339_age_days(snap.get("time", ""))
                r.summary = f"latest snapshot {snap.get('short_id', '')} {snap.get('time', '')[:19]}"
                r.artifacts.append({"type": "restic-snapshot", "id": snap.get("id"), "time": snap.get("time"),
                                    "paths": snap.get("paths")})
                if age is not None and self.mc.stale_after_days and age > self.mc.stale_after_days:
                    r.warnings.append(f"latest snapshot is {age:.1f} days old")
                missing = sorted(set(self.mc.paths) - set(snap.get("paths") or []))
                if missing:
                    r.warnings.append(f"latest snapshot does not contain configured path(s): {', '.join(missing)}")
        return r

    def init(self, prompter: Prompter) -> ModuleResult:
        r = ModuleResult(self.name, "files-init", started=_now())
        pw = Path(self.mc.password_file)
        if not pw.exists():
            if not prompter.interactive:
                raise PromptUnavailable(f"{pw} does not exist; create it (0400) or run files-init interactively")
            ch = prompter.choose(f"No Restic password file at {pw}.",
                                 [("g", "Generate a strong random password (recommended)"),
                                  ("e", "Enter a password")], default="g")
            if ch == "g":
                secret = secrets.token_urlsafe(32)
                sys.stderr.write(f"\n  Restic repository password:  {secret}\n"
                                 "  Store it OFF this machine (e.g. Vaultwarden) NOW - without it the backups\n"
                                 "  cannot be restored if this machine is lost.\n\n")
                if not prompter.confirm("Saved it?", True):
                    raise BackupError("aborted; password not saved")
            else:
                secret = prompter.secret("Restic password (input hidden)")
                if len(secret) < 12:
                    raise BackupError("use at least 12 characters")
                if prompter.secret("Repeat password") != secret:
                    raise BackupError("passwords do not match")
            _mkdir_private(pw.parent)
            _write_private(pw, secret)
            os.chmod(pw, 0o400)
            del secret
            r.notes.append(f"password file written: {pw} (0400)")
        with self.environment() as (env, root):
            ok, _ = self.repo_state(env)
            if ok:
                r.notes.append(f"repository {self.repo_display()} already initialised")
            else:
                rc, _, err = self._restic(["init"], env, timeout=600)
                if rc:
                    raise BackupError(f"restic init failed: {err.strip()[-300:]}")
                r.notes.append(f"repository created: {self.repo_display()}")
                self.repo_state(env)
                if self.ctx.ledger:   # a fresh repository is a new baseline
                    self.ctx.ledger.accept(self.ledger_coll, {})
                    self.ctx.ledger.set_value(self.ledger_repo_key, self.repo_id, force=True)
            if root is not None:
                self.write_readme(root)
        r.summary = "Restic repository ready"
        return r

    def _pick_file(self, env: Dict[str, str], snap_id: str, r: ModuleResult) -> Optional[str]:
        """A small regular file from the snapshot, under the configured paths."""
        found: List[str] = []

        def on_line(line: str) -> bool:
            try:
                n = json.loads(line)
            except ValueError:
                return False
            if n.get("type") == "file" and 0 < (n.get("size") or 0) <= 64 * 1024 * 1024:
                found.append(n["path"])
                return True
            return False

        roots = [p for p in self.mc.paths] or ["/"]
        for root in roots:
            _run_long(["restic", "ls", "--json", snap_id, root], env=env, on_line=on_line)
            if found:
                return found[0]
        r.errors.append("no suitable file (<= 64 MiB) found in the latest snapshot; pass --path")
        return None

    def restore_test(self, path: str = "") -> ModuleResult:
        r = ModuleResult(self.name, "restore-test", started=_now())
        with self.environment() as (env, _):
            self.require_repo(env)
            snap = self.latest_snapshot(env)
            if not snap:
                r.errors.append("no snapshots to restore from")
                return r
            sid = snap["id"]
            target = path or self._pick_file(env, sid, r)
            if not target:
                return r
            tmp = tempfile.mkdtemp(prefix="server-backup-restore-test-")
            try:
                self.emit("info", f"restoring {target} from snapshot {sid[:8]} into {tmp}")
                rc, tail = _run_long(["restic", "restore", sid, "--target", tmp, "--include", target], env=env)
                restored = Path(tmp) / target.lstrip("/")
                if rc or not restored.exists():
                    r.errors.append(f"restore of {target} failed (rc={rc}): {_tail_text(tail)}")
                elif restored.is_file():
                    h, live = sha256_file(restored), Path(target)
                    r.summary = f"restored {target} ({_fmt_bytes(restored.stat().st_size)}) from snapshot {sid[:8]}"
                    if not live.is_file():
                        r.notes.append("live file no longer exists; restored copy is readable")
                    elif sha256_file(live) == h:
                        r.notes.append("restored copy is identical to the live file")
                    else:
                        r.notes.append("restored copy differs from the live file (changed since the snapshot?)")
                    r.details = {"snapshot": sid, "path": target, "sha256": h}
                else:
                    n = sum(1 for p in restored.rglob("*") if p.is_file())
                    r.summary = f"restored directory {target} ({n} files) from snapshot {sid[:8]}"
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        return r

    def write_readme(self, root: Path) -> None:
        try:
            _write_atomic(root / "RESTORE-files.txt", FILES_README.format(
                host=self.ctx.host, repo=self.repo_display(), tag=RESTIC_TAG, pw=self.mc.password_file,
                paths="\n".join(f"  {p}" for p in self.mc.paths) or "  (none)",
                excludes="\n".join(f"  {e}" for e in self.mc.excludes) or "  (none)", tool=__version__))
        except OSError as e:
            self.emit("warning", f"could not write RESTORE-files.txt: {e}")


FILES_README = """Restic file/directory backups - host {host}
Written by server_backup.py {tool}

Repository: {repo}
  (on the share: the restic/ directory next to this file)
Snapshots are created with --host {host} --tag {tag}.
Password: {pw} on the backed-up machine. KEEP A COPY OFF THAT MACHINE -
without it the repository cannot be decrypted.

Backed-up paths:
{paths}
Excludes (only these; nothing else is excluded):
{excludes}

Restore (any Linux machine with restic; mount the share first if the repo is on it)
  export RESTIC_REPOSITORY=<path or URL of the repository>
  export RESTIC_PASSWORD_FILE=/root/restic.pass
  restic snapshots --host {host}
  restic ls latest --host {host} /home/user/some/dir
  restic restore latest --host {host} --target /tmp/restore --include /home/user/file.txt
  restic restore <snapshot-id> --target /                # full restore in place (overwrites!)
  restic mount /mnt/restic                               # browse every snapshot (needs FUSE)
Integrity
  restic check                     restic check --read-data-subset=5%
Self-test from the backed-up machine
  server_backup.py restore-test --files [--path /home/user/file.txt]
"""


# --------------------------------------------------------------------------- Proxmox VM module
@dataclass
class VmInfo:
    vmid: int
    exists: bool = False
    name: str = ""
    status: str = ""
    lock: str = ""
    agent_configured: bool = False
    agent_responding: Optional[bool] = None
    disks: List[dict] = field(default_factory=list)
    excluded_disks: List[str] = field(default_factory=list)
    estimated_bytes: int = 0
    config_text: str = ""
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ProxmoxVmBackupService:
    """
    vzdump of configured VM IDs only. A backup counts as valid once its .server-backup.json is
    written (after the archive exists, is non-empty and its checksum is recorded). Retention keeps
    the newest N valid backups; a failed run removes only its own partial files.
    """
    name = "proxmox_vm"

    def __init__(self, ctx: RunContext):
        self.ctx, self.cfg, self.emit = ctx, ctx.cfg, ctx.emit

    @property
    def mc(self) -> ProxmoxVmModuleConfig:
        return self.cfg.modules.proxmox_vm

    # ---- discovery
    @staticmethod
    def list_vms() -> List[dict]:
        rc, out, err = _run(["qm", "list"])
        if rc:
            raise BackupError(f"qm list failed: {err.strip()}")
        vms = []
        for line in out.splitlines()[1:]:
            f = line.split()
            if len(f) >= 3 and f[0].isdigit():
                vms.append({"vmid": int(f[0]), "name": f[1], "status": f[2]})
        return vms

    @staticmethod
    def parse_qm_config(text: str) -> Dict[str, str]:
        cfg = {}
        for line in text.splitlines():
            k, sep, v = line.partition(":")
            if sep and k and not k.startswith(("#", " ")):
                cfg[k.strip()] = v.strip()
        return cfg

    def vm_info(self, vmid: int, probe_agent: bool = True) -> VmInfo:
        vi = VmInfo(vmid)
        rc, out, _ = _run(["qm", "config", str(vmid)])
        if rc:
            return vi
        vi.exists, vi.config_text = True, out
        cfg = self.parse_qm_config(out)
        vi.name, vi.lock = cfg.get("name", ""), cfg.get("lock", "")
        agent = cfg.get("agent", "")
        vi.agent_configured = bool(re.match(r"^(1|enabled=1)(,|$)", agent)) or ",enabled=1" in agent
        _, st, _ = _run(["qm", "status", str(vmid)])
        m = re.search(r"status:\s*(\S+)", st)
        vi.status = m.group(1) if m else "unknown"
        for k, v in cfg.items():
            if not QM_DISK_RE.match(k) or "media=cdrom" in v or v.startswith("none"):
                continue
            m = re.search(r"(?:^|,)size=([^,]+)", v)
            size = parse_size(m.group(1)) if m else 0
            excluded = bool(re.search(r"(?:^|,)backup=(0|no|off|false)(,|$)", v))
            vi.disks.append({"key": k, "volume": v.split(",")[0], "size": size, "backup": not excluded})
            if excluded:
                vi.excluded_disks.append(k)
            else:
                vi.estimated_bytes += size
        if probe_agent and vi.status == "running" and vi.agent_configured:
            rc, _, _ = _run(["qm", "guest", "cmd", str(vmid), "ping"], timeout=20)
            vi.agent_responding = rc == 0
        if vi.status == "running" and self.mc.mode == "snapshot":
            if not vi.agent_configured:
                vi.warnings.append("QEMU guest agent not enabled: snapshot backup is crash-consistent "
                                   "(no filesystem freeze)")
            elif vi.agent_responding is False:
                vi.warnings.append("guest agent enabled but not responding: no filesystem freeze will happen")
        planned = self.mc.excluded_disks_ok.get(str(vmid), [])
        unplanned = [d for d in vi.excluded_disks if d not in planned]
        if unplanned:
            vi.warnings.append(f"disk(s) {', '.join(unplanned)} have backup=0: their data is NOT included in the "
                               "VM backup (list them in excluded_disks_ok if that is intended)")
        if vi.excluded_disks and not unplanned:
            vi.notes.append(f"disk(s) {', '.join(vi.excluded_disks)} excluded as planned (excluded_disks_ok)")
        stale = [d for d in planned if d not in vi.excluded_disks]
        if stale:
            vi.warnings.append(f"excluded_disks_ok lists {', '.join(stale)}, but they are now backed up or gone; "
                               "update the list")
        if vi.lock:
            vi.warnings.append(f"VM is locked ({vi.lock}); vzdump will refuse to run")
        return vi

    # ---- destination
    @contextlib.contextmanager
    def target(self) -> Iterator[Tuple[Path, Callable[[], None], Callable[[Path], str]]]:
        """Yields (proxmox/vm base dir, assert-still-mounted, display). Never falls back to local disk."""
        if self.cfg.cifs.enabled:
            with self.ctx.dest.session() as root:
                base = root / "proxmox" / "vm"
                base.mkdir(parents=True, exist_ok=True)
                yield base, self.ctx.dest.assert_mounted, self.ctx.dest.display
        elif self.mc.dumpdir:
            base = Path(self.mc.dumpdir)

            def check() -> None:
                if not base.is_dir():
                    raise BackupError(f"dumpdir {base} does not exist (backup disk not mounted?)")
                if os.stat(base).st_dev == os.stat("/").st_dev:
                    raise BackupError(f"dumpdir {base} is on the root filesystem; refusing to write VM backups there")

            check()
            yield base, check, str
        else:
            raise BackupError("no destination for VM backups: enable CIFS or set modules.proxmox_vm.dumpdir "
                              "(a separate filesystem)")

    def selected_vmids(self, r: ModuleResult) -> List[int]:
        conf = [int(v) for v in self.mc.vmids]
        if not conf:
            r.errors.append("no VM IDs configured (modules.proxmox_vm.vmids)")
            return []
        if self.ctx.vmids:
            bad = [v for v in self.ctx.vmids if v not in conf]
            if bad:
                r.errors.append(f"VM ID(s) {bad} are not in modules.proxmox_vm.vmids; only configured VMs are handled")
            return [v for v in self.ctx.vmids if v in conf]
        return conf

    @staticmethod
    def _groups(vm_dir: Path, vmid: int) -> Dict[str, List[Path]]:
        groups: Dict[str, List[Path]] = {}
        if vm_dir.is_dir():
            for p in vm_dir.iterdir():
                m = VZDUMP_RE.match(p.name)
                if m and int(m.group(1)) == vmid:
                    groups.setdefault(m.group(2), []).append(p)
        return groups

    @staticmethod
    def _valid(files: List[Path]) -> Optional[Tuple[dict, Path]]:
        meta = next((p for p in files if p.name.endswith(VM_META_SUFFIX)), None)
        if not meta:
            return None
        try:
            m = json.loads(meta.read_text())
        except (OSError, ValueError):
            return None
        archive = meta.parent / m.get("archive", "")
        if m.get("status") != "ok" or not archive.is_file() or archive.stat().st_size != m.get("size"):
            return None
        return m, archive

    def latest(self, vm_dir: Path, vmid: int) -> Optional[Tuple[dict, Path]]:
        groups = self._groups(vm_dir, vmid)
        for k in sorted(groups, reverse=True):
            v = self._valid(groups[k])
            if v:
                return v
        return None

    def entries(self, vm_dir: Path, vmid: int) -> Dict[str, str]:
        """Ledger fingerprints of valid backups: archive -> sha256:size. Deleting the archive or its
        metadata, or truncating it, makes it invalid, so it shows up as gone."""
        out = {}
        for files in self._groups(vm_dir, vmid).values():
            v = self._valid(files)
            if v:
                out[v[1].name] = f"{v[0].get('sha256', '')}:{v[0]['size']}"
        return out

    def _prune(self, vm_dir: Path, vmid: int) -> List[str]:
        groups = self._groups(vm_dir, vmid)
        valid = {k for k, files in groups.items() if self._valid(files)}
        m = self.mc
        return RetentionManager.prune_groups(groups, valid, m.retention, m.keep_daily, m.keep_weekly, m.keep_monthly)

    # ---- operations
    def backup(self) -> ModuleResult:
        r = ModuleResult(self.name, "backup", started=_now())
        vmids = self.selected_vmids(r)
        if not vmids:
            return r
        done = 0
        with self.target() as (base, assert_ok, show):
            self.write_readme(base)
            for vmid in vmids:
                try:
                    self._backup_one(vmid, base, assert_ok, show, r)
                    done += 1
                except BackupError as e:
                    r.errors.append(f"VM {vmid}: {e}")
                    self.emit("error", f"VM {vmid}: {e}")
        r.summary = f"{done}/{len(vmids)} VM(s) backed up"
        return r

    def _backup_one(self, vmid: int, base: Path, assert_ok, show, r: ModuleResult) -> None:
        mc = self.mc
        vi = self.vm_info(vmid)
        if not vi.exists:
            raise BackupError("not found (qm config failed): not a QEMU VM on this node?")
        for w in vi.warnings:
            r.warnings.append(f"VM {vmid} ({vi.name}): {w}")
        r.notes += [f"VM {vmid} ({vi.name}): {n}" for n in vi.notes]
        if vi.lock:
            raise BackupError(f"VM is locked ({vi.lock}); previous backups untouched")
        vm_dir = base / str(vmid)
        vm_dir.mkdir(exist_ok=True)
        label = ledger_label(f"proxmox_vm/{vmid}", show(vm_dir))
        tampered = ledger_findings(self.ctx, label, self.entries(vm_dir, vmid), r, f"VM {vmid}: ")
        free = Destination.free_bytes(vm_dir)
        need = int(vi.estimated_bytes * mc.required_free_ratio) + int(self.cfg.cifs.min_free_gb * 1024 ** 3)
        if free < need:
            raise BackupError(f"not enough free space: {_fmt_bytes(free)} free, {_fmt_bytes(need)} required "
                              f"(allocated disks {_fmt_bytes(vi.estimated_bytes)} x {mc.required_free_ratio} "
                              "+ min_free_gb); previous backups untouched")
        before = set(os.listdir(vm_dir))
        cmd = ["vzdump", str(vmid), "--mode", mc.mode, "--compress", str(mc.compress),
               "--dumpdir", str(vm_dir), "--remove", "0"]
        if str(mc.compress) == "zstd" and mc.zstd_threads > 0:
            cmd += ["--zstd", str(mc.zstd_threads)]
        if mc.bwlimit_kbps > 0:
            cmd += ["--bwlimit", str(mc.bwlimit_kbps)]
        if mc.tmpdir:
            cmd += ["--tmpdir", mc.tmpdir]
        cmd += [str(a) for a in mc.extra_args]
        assert_ok()
        agent = ("agent responding" if vi.agent_responding else "agent NOT responding"
                 if vi.agent_configured and vi.status == "running" else
                 "agent enabled" if vi.agent_configured else "no agent")
        self.emit("info", f"VM {vmid} ({vi.name}, {vi.status}, {agent}): vzdump {mc.mode}/{mc.compress} "
                          f"-> {show(vm_dir)}")
        started = dt.datetime.now()
        rc, tail = _run_long(cmd, timeout=_hours(mc.timeout_hours),
                             on_line=progress_lines(self.emit, f"VM {vmid}: vzdump", parse_vzdump_progress))
        new = sorted(set(os.listdir(vm_dir)) - before)
        archives = [n for n in new if (m := VZDUMP_ARCHIVE_RE.match(n)) and int(m.group(1)) == vmid]
        archive = vm_dir / archives[-1] if archives else None
        problem = ""
        if rc:
            problem = f"vzdump exited {rc}"
        elif archive is None:
            problem = "vzdump reported success but no new archive appeared"
        elif archive.stat().st_size == 0:
            problem = "archive is empty"
        sha = ""
        if not problem and mc.checksum:
            sha = Manifest.write_sidecar(archive, self.emit, "reading it back from the destination")
        zstd_ok = None
        if not problem and mc.verify_zstd and archive.name.endswith(".zst"):
            zstd_ok = self._zstd_test(archive)
            if not zstd_ok:
                problem = "zstd -t reports the archive is corrupt"
        if problem:
            self._discard_partial(vm_dir, vmid, new)
            raise BackupError(f"{problem}: {_tail_text(tail)}; previous backups untouched")
        size = archive.stat().st_size
        stem = archive.name.split(".vma")[0]
        _write_atomic(vm_dir / f"{stem}.qm-config.txt", f"# qm config {vmid} at {started:%Y-%m-%d %H:%M:%S}\n"
                                                          + vi.config_text)
        finished = dt.datetime.now()
        meta = {
            "tool_version": __version__, "host": self.ctx.host, "vmid": vmid, "name": vi.name,
            "archive": archive.name, "size": size, "sha256": sha, "zstd_tested": zstd_ok,
            "mode": mc.mode, "compress": str(mc.compress), "vm_status": vi.status,
            "guest_agent": {"configured": vi.agent_configured, "responding": vi.agent_responding},
            "disks": vi.disks, "excluded_disks": vi.excluded_disks,
            "started": started.isoformat(timespec="seconds"), "finished": finished.isoformat(timespec="seconds"),
            "duration_s": int((finished - started).total_seconds()), "pve_version": self._pveversion(),
            "restore_test": f"qmrestore {archive.name} <NEWID> --storage <STORAGE> --unique 1",
            "restore": f"qmrestore {archive.name} {vmid} --storage <STORAGE>",
            "status": "ok",
        }
        _write_atomic(vm_dir / f"{stem}{VM_META_SUFFIX}", json.dumps(meta, indent=2))  # last: marks it valid
        r.artifacts.append({"type": "vzdump", "vmid": vmid, "name": vi.name, "path": show(archive),
                            "size": size, "sha256": sha, "ok": True})
        if tampered:
            pruned = []
            r.notes.append(f"VM {vmid}: retention paused because of tamper findings (see `ledger --accept`)")
        else:
            pruned = self._prune(vm_dir, vmid)
        if pruned:
            r.notes.append(f"VM {vmid}: retention removed {len(pruned)} file(s) of older backups")
        if self.ctx.ledger:
            self.ctx.ledger.update(label, self.entries(vm_dir, vmid), added=[archive.name], removed=pruned)
        self.emit("info", f"  VM {vmid}: {archive.name} {_fmt_bytes(size)}"
                          + (" sha256 recorded" if sha else "") + (" zstd OK" if zstd_ok else ""))

    @staticmethod
    def _discard_partial(vm_dir: Path, vmid: int, new: List[str]) -> None:
        """Remove what this failed run created (keep its .log for diagnosis). Never touches older files."""
        for n in new:
            m = VZDUMP_RE.match(n)
            if m and int(m.group(1)) == vmid and not n.endswith(".log"):
                with contextlib.suppress(OSError):
                    (vm_dir / n).unlink()

    def _zstd_test(self, archive: Path) -> bool:
        if not shutil.which("zstd"):
            raise BackupError("verify_zstd is set but zstd is not installed")
        self.emit("info", f"  zstd -t {archive.name} ({_fmt_bytes(archive.stat().st_size)}, reads the whole archive)...")
        rc, _ = _run_long(["zstd", "-t", "-q", str(archive)])
        return rc == 0

    @staticmethod
    def _pveversion() -> str:
        try:
            rc, out, _ = _run(["pveversion"], timeout=30)
            return out.strip() if rc == 0 else ""
        except BackupError:
            return ""

    def verify(self, deep: bool = False) -> ModuleResult:
        r = ModuleResult(self.name, "verify", started=_now())
        vmids = self.selected_vmids(r)
        ok = 0
        with self.target() as (base, _, show):
            for vmid in vmids:
                vm_dir = base / str(vmid)
                ledger_findings(self.ctx, ledger_label(f"proxmox_vm/{vmid}", show(vm_dir)),
                                self.entries(vm_dir, vmid), r, f"VM {vmid}: ")
                latest = self.latest(vm_dir, vmid)
                if not latest:
                    r.errors.append(f"VM {vmid}: no valid backup in {show(vm_dir)}")
                    continue
                meta, archive = latest
                problems = []
                if deep:
                    if meta.get("sha256"):
                        if sha256_with_progress(archive, self.emit, "deep verify") != meta["sha256"]:
                            problems.append("sha256 mismatch")
                    else:
                        r.notes.append(f"VM {vmid}: no checksum recorded (checksum=false)")
                    if archive.name.endswith(".zst"):
                        if shutil.which("zstd"):
                            if not self._zstd_test(archive):
                                problems.append("zstd -t failed")
                        else:
                            r.warnings.append("zstd not installed; archive decompression not tested")
                for p in problems:
                    r.errors.append(f"VM {vmid}: {archive.name}: {p}")
                age = stamp_age_days(VZDUMP_RE.match(archive.name).group(2))
                if age is not None and self.mc.stale_after_days and age > self.mc.stale_after_days:
                    r.warnings.append(f"VM {vmid}: latest backup is {age:.0f} days old")
                r.artifacts.append({"type": "vzdump", "vmid": vmid, "path": show(archive), "size": meta["size"],
                                    "age_days": round(age, 1) if age is not None else None,
                                    "checked": "sha256+zstd" if deep else "metadata+size", "ok": not problems})
                ok += not problems
        r.summary = f"{ok}/{len(vmids)} VM backup(s) verified" + (" (deep)" if deep else "")
        return r

    def _id_in_use(self, vmid: int) -> bool:
        if glob.glob(f"/etc/pve/nodes/*/qemu-server/{vmid}.conf") or glob.glob(f"/etc/pve/nodes/*/lxc/{vmid}.conf"):
            return True
        if _run(["qm", "status", str(vmid)])[0] == 0:
            return True
        return bool(shutil.which("pct")) and _run(["pct", "status", str(vmid)])[0] == 0

    def restore_test(self, vmid: int, test_vmid: int, storage: str, prompter: Prompter,
                     assume_yes: bool = False) -> ModuleResult:
        r = ModuleResult(self.name, "restore-test", started=_now())
        if vmid not in [int(v) for v in self.mc.vmids]:
            raise BackupError(f"VM {vmid} is not in modules.proxmox_vm.vmids")
        if not storage:
            raise BackupError("--storage is required (target Proxmox storage for the test VM's disks)")
        if test_vmid == vmid or self._id_in_use(test_vmid):
            raise BackupError(f"test VM ID {test_vmid} is in use; choose an unused ID (it must not be {vmid})")
        with self.target() as (base, _, show):
            latest = self.latest(base / str(vmid), vmid)
            if not latest:
                raise BackupError(f"no valid backup of VM {vmid} found")
            meta, archive = latest
            if meta.get("sha256") and self.ctx.deep and sha256_file(archive) != meta["sha256"]:
                raise BackupError(f"{archive.name}: sha256 mismatch; not restoring")
            msg = (f"Restore {archive.name} ({_fmt_bytes(meta['size'])}) as NEW VM {test_vmid} on storage "
                   f"'{storage}'? It will not be started and its network links will be down.")
            if not assume_yes and not (prompter.interactive and prompter.confirm(msg, False)):
                raise BackupError("restore test not confirmed (use --yes for non-interactive runs)")
            self.emit("info", f"qmrestore {show(archive)} {test_vmid} --storage {storage} --unique 1")
            rc, tail = _run_long(["qmrestore", str(archive), str(test_vmid), "--storage", storage, "--unique", "1"],
                                 on_line=progress_lines(self.emit, f"qmrestore {test_vmid}",
                                                        parse_qmrestore_progress))
            if rc:
                r.errors.append(f"qmrestore failed (rc={rc}): {_tail_text(tail)}")
                return r
        name = re.sub(r"[^A-Za-z0-9.-]", "-", f"restoretest-{meta.get('name') or vmid}")[:60]
        sets = ["--onboot", "0", "--name", name]
        rc, out, _ = _run(["qm", "config", str(test_vmid)])
        tcfg = self.parse_qm_config(out)
        for k, v in tcfg.items():
            if re.match(r"^net\d+$", k) and "link_down=1" not in v:
                sets += [f"--{k}", v + ",link_down=1"]
        # the original VM owns these: passed-through GPUs/USB, hugepages, CPU pinning, NUMA binding
        strip = [k for k in tcfg if re.match(r"^(hostpci|usb|numa)\d+$", k) or k in ("hugepages", "affinity")]
        if strip:
            sets += ["--delete", ",".join(strip)]
        rc, _, err = _run(["qm", "set", str(test_vmid)] + sets)
        if rc:
            r.warnings.append(f"could not adjust test VM {test_vmid} ({err.strip()}): it may still have onboot, "
                              "network or passthrough devices - do not start it")
        elif strip:
            r.notes.append(f"removed from the test VM (the original keeps them): {', '.join(strip)}")
        mem_mb = int(re.sub(r"\D", "", tcfg.get("memory", "0")) or 0)
        avail = self._mem_available_mb()
        if avail and mem_mb > avail:
            r.warnings.append(f"test VM {test_vmid} is set to {mem_mb // 1024} GiB RAM but only {avail // 1024} GiB "
                              f"is free; lower it before starting: qm set {test_vmid} --memory <MiB>")
        r.summary = f"VM {vmid} restored from {archive.name} as test VM {test_vmid} ({name})"
        r.notes += [f"boot test (network links down): qm start {test_vmid}",
                    f"remove when done: qm destroy {test_vmid} --purge"]
        r.details = {"archive": archive.name, "test_vmid": test_vmid, "storage": storage}
        return r

    @staticmethod
    def _mem_available_mb() -> int:
        try:
            m = re.search(r"^MemAvailable:\s+(\d+) kB", Path("/proc/meminfo").read_text(), re.M)
            return int(m.group(1)) // 1024 if m else 0
        except OSError:
            return 0

    def write_readme(self, base: Path) -> None:
        try:
            _write_atomic(base / "RESTORE-vm.txt", VM_README.format(host=self.ctx.host, tool=__version__))
        except OSError as e:
            self.emit("warning", f"could not write RESTORE-vm.txt: {e}")


VM_README = """Proxmox VM backups (vzdump) - host {host}
Written by server_backup.py {tool}

Layout   <vmid>/vzdump-qemu-<vmid>-<YYYY_MM_DD-HH_MM_SS>.vma.zst   archive: all backed-up disks + VM config
               ...log                 vzdump log
               ...qm-config.txt       `qm config <vmid>` at backup time (hardware, passthrough, storage names)
               ...vma.zst.sha256      checksum (sha256sum -c)
               ...server-backup.json  metadata; its presence marks a complete, verified backup
Only backups with a .server-backup.json count towards retention, so failed runs never displace
the last good backup. Disks with backup=0 are NOT in the archive (listed in the metadata).

Verify
  sha256sum -c <archive>.sha256
  zstd -t <archive>
  server_backup.py verify --proxmox-vm --deep

Restore on any Proxmox VE host that can read the file (mount the share, or add it as CIFS storage)
  Test restore under a NEW id - the original VM is untouched:
    qmrestore <archive> <NEWID> --storage <STORAGE> --unique 1
    qm set <NEWID> --onboot 0        # and add link_down=1 to its netX lines before booting
    or: server_backup.py restore-test --proxmox-vm --vmid <VMID> --test-vmid <NEWID> --storage <STORAGE>
  Disaster recovery to the original id (DESTRUCTIVE if that VM still exists):
    qmrestore <archive> <VMID> --storage <STORAGE> [--force 1]
  Compare with ...qm-config.txt and adjust host-specific settings (hostpci/usb passthrough, cpu type,
  bridges, storage names) with `qm set` if the new host differs.
  Disks excluded with backup=0 (data disks) are not restored: the restored config may still list them.
  Re-attach the surviving data disks, or create empty ones and restore their data from where it is
  backed up (e.g. Restic inside the VM).
"""


# --------------------------------------------------------------------------- Proxmox host module
class ProxmoxHostBackupService:
    """Configuration + inventory needed to rebuild the Proxmox host (not an OS image)."""
    name = "proxmox_host"
    kind = "proxmox/host"
    CONFIG_DB = "/var/lib/pve-cluster/config.db"

    def __init__(self, ctx: RunContext):
        self.ctx, self.cfg, self.emit = ctx, ctx.cfg, ctx.emit

    @property
    def mc(self) -> ProxmoxHostModuleConfig:
        return self.cfg.modules.proxmox_host

    def backup(self) -> ModuleResult:
        r = ModuleResult(self.name, "backup", started=_now())
        now = dt.datetime.now()
        ts = now.strftime(TS_FMT)
        local_kind = self.ctx.dest.local_dir(self.kind)
        staging = local_kind / ts
        for d in (Path(self.cfg.local_dir), local_kind.parent.parent, local_kind.parent, local_kind, staging):
            _mkdir_private(d)
        for sub in ("files", "commands", "pve-cluster"):
            _mkdir_private(staging / sub)
        inv: dict = {"tool_version": __version__, "host": self.ctx.host, "timestamp": ts,
                     "paths": {"included": [], "missing": [], "excluded": [], "skipped": [], "errors": []},
                     "commands": {}, "vms": []}
        self.emit("info", f"Proxmox host configuration -> {staging}")
        count = self._archive(staging / "files" / "etc.tar", inv, r)
        self._commands(staging / "commands", inv)
        if self.mc.include_config_db:
            self._config_db(staging / "pve-cluster" / "config.db", r)
        pve = inv["commands"].get("pveversion-v")
        _write_private(staging / "inventory.json", json.dumps(inv, indent=2))
        _write_private(staging / "README.txt", HOST_README.format(host=self.ctx.host, ts=ts, tool=__version__))
        _write_private(staging / "manifest.json", json.dumps({
            "tool_version": __version__, "module": self.name, "host": self.ctx.host, "timestamp": ts,
            "file_count": count, "warnings": r.warnings, "errors": r.errors, "pveversion_rc": pve}, indent=2))
        Manifest.write_sha256sums(staging)
        check = verify_timestamped(local_kind)
        if check["latest"] != ts or check["problems"]:
            r.errors += [f"staged archive check: {p}" for p in check["problems"]] or ["staged archive not found"]
        if not self.cfg.gpg_recipient:
            msg = "archive is not GPG-encrypted but contains secrets (/etc/pve/priv, keys); run gpg-setup"
            (r.notes if self.mc.allow_unencrypted else r.warnings).append(msg)
        dests, removed = ArtifactPublisher(self.cfg, self.emit, self.ctx.dest, self.ctx.ledger).publish(
            staging, self.kind, self.mc.retention, r.errors, r.warnings, lambda: not r.errors,
            (self.mc.keep_daily, self.mc.keep_weekly, self.mc.keep_monthly))
        r.artifacts = dests
        r.summary = f"{count} file(s)/dir(s), {len(inv['commands'])} command output(s), backup {ts}"
        return r

    def _expand(self, inv: dict, r: ModuleResult) -> List[str]:
        paths = []
        for pat in list(self.mc.paths) + list(self.mc.extra_paths):
            hits = sorted(glob.glob(pat)) if any(ch in pat for ch in "*?[") else (
                [pat] if os.path.lexists(pat) else [])
            if not hits:
                inv["paths"]["missing"].append(pat)
                if pat in self.mc.extra_paths:
                    r.warnings.append(f"configured extra path missing: {pat}")
            paths += [h for h in hits if h not in paths]
        inv["paths"]["included"] = paths
        return paths

    def _archive(self, tar_path: Path, inv: dict, r: ModuleResult) -> int:
        count = 0
        fd = os.open(tar_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w") as tf:
            for p in self._expand(inv, r):
                count += self._add_tree(tf, p, inv)
        errs = inv["paths"]["errors"]
        if errs:
            r.warnings.append(f"{len(errs)} item(s) could not be read (see inventory.json): " + "; ".join(errs[:3]))
        try:
            with tarfile.open(tar_path) as tf:
                n = len(tf.getmembers())
            if n != count:
                r.errors.append(f"etc.tar has {n} entries, expected {count}")
        except (tarfile.TarError, OSError) as e:
            r.errors.append(f"etc.tar unreadable after writing: {e}")
        return count

    def _add_tree(self, tf: tarfile.TarFile, path: str, inv: dict) -> int:
        if any(fnmatch.fnmatch(path, x) for x in self.mc.excludes):
            inv["paths"]["excluded"].append(path)
            return 0
        try:
            st = os.lstat(path)
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                inv["paths"]["skipped"].append(path)   # sockets, fifos, device nodes
                return 0
            tf.add(path, arcname=path.lstrip("/"), recursive=False)
        except OSError as e:
            inv["paths"]["errors"].append(f"{path}: {e.strerror or e}")
            return 0
        n = 1
        if stat.S_ISDIR(st.st_mode):
            try:
                names = sorted(os.listdir(path))
            except OSError as e:
                inv["paths"]["errors"].append(f"{path}: {e.strerror or e}")
                return n
            for name in names:
                n += self._add_tree(tf, os.path.join(path, name), inv)
        return n

    def _commands(self, d: Path, inv: dict) -> None:
        cmds = list(PVE_HOST_COMMANDS)
        cmds += [(f"qm-config-{v}", ["qm", "config", str(v)]) for v in self.cfg.modules.proxmox_vm.vmids]
        cmds += [(str(k), [str(a) for a in v]) for k, v in self.mc.extra_commands.items() if v]
        for name, argv in cmds:
            if not shutil.which(argv[0]):
                inv["commands"][name] = "not installed"
                continue
            rc, out, err = _run(argv, timeout=120)
            _write_private(d / f"{_safe(name)}.txt", f"# {' '.join(argv)}\n# rc={rc}\n{out}"
                           + (f"\n# stderr:\n{err}" if err.strip() else ""))
            inv["commands"][name] = rc
            if name == "qm-list" and rc == 0:
                for line in out.splitlines()[1:]:
                    f = line.split()
                    if len(f) >= 3 and f[0].isdigit():
                        inv["vms"].append({"vmid": int(f[0]), "name": f[1], "status": f[2]})

    def _config_db(self, dst: Path, r: ModuleResult) -> None:
        src = Path(self.CONFIG_DB)
        if not src.is_file():
            r.notes.append(f"{src} not found; skipped")
            return
        try:
            import sqlite3
            s = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
            d = sqlite3.connect(str(dst))
            try:
                s.backup(d)   # online backup API: consistent even while pmxcfs is writing
            finally:
                s.close()
                d.close()
            os.chmod(dst, 0o600)
            c = sqlite3.connect(str(dst))
            try:
                res = c.execute("PRAGMA integrity_check").fetchone()[0]
            finally:
                c.close()
            if res != "ok":
                r.warnings.append(f"config.db copy integrity_check: {res}")
        except Exception as e:  # sqlite3 missing or locked: the /etc/pve files are still in etc.tar
            r.warnings.append(f"config.db backup failed ({e}); /etc/pve files are still in etc.tar")

    def verify(self, deep: bool = False) -> ModuleResult:
        r = ModuleResult(self.name, "verify", started=_now())
        verify_stored(self.ctx, self.kind, self.mc.stale_after_days, r)
        r.summary = "latest host configuration backup " + ("verified" if not r.errors else "has problems")
        return r


HOST_README = """Proxmox host configuration backup - host {host} - {ts}
Created by server_backup.py {tool}

This is a configuration backup, not an image of the Proxmox OS. Rebuild = fresh install of the
same Proxmox VE version + this configuration + VM restores from proxmox/vm/ (RESTORE-vm.txt).

Contents
  files/etc.tar          /etc/pve, /etc/network, hosts, hostname, fstab, crypttab, grub, modules,
                         modprobe.d, systemd units, ... (exact list: inventory.json "paths")
  pve-cluster/config.db  consistent copy of the pmxcfs database behind /etc/pve
  commands/              pveversion -v, qm list, qm config <vmid>, pvesm status, lsblk, blkid,
                         pvs/vgs/lvs, zpool, ip addr/route, uname -a, installed packages, ...
  inventory.json, manifest.json, SHA256SUMS   (verify: sha256sum -c SHA256SUMS)

If you received <timestamp>.tar.gpg
  sha256sum -c <timestamp>.tar.gpg.sha256
  gpg --import server-backup-key-XXXXXXXX.SECRET.asc   # once: the backup key from Vaultwarden
                                                       # (older keys are named luks-backup-key-*)
  gpg -d <timestamp>.tar.gpg | tar x

Inspect without restoring
  tar tvf files/etc.tar | less
  mkdir -p /root/restore && tar xf files/etc.tar -C /root/restore

Rebuild outline (single node)
  1. Install the same Proxmox VE version (commands/pveversion-v.txt) with the same hostname and
     management IP (etc/hostname, etc/hosts, etc/network/interfaces in etc.tar).
  2. Recreate the storage below Proxmox: LUKS (crypttab + LUKS module backup), LVM/ZFS layout
     (commands/pvs vgs lvs zpool-status lsblk blkid), fstab mounts.
  3. Restore host files selectively - do not blindly overwrite /etc:
       tar xf files/etc.tar -C / etc/network/interfaces etc/hosts etc/fstab etc/modules ...
     then update-initramfs -u; update-grub (or proxmox-boot-tool refresh).
  4. Restore /etc/pve (single node, before guests exist):
       systemctl stop pve-cluster
       cp /var/lib/pve-cluster/config.db /var/lib/pve-cluster/config.db.fresh-install
       install -m 0600 pve-cluster/config.db /var/lib/pve-cluster/config.db
       systemctl start pve-cluster
     or copy individual files from etc/pve in etc.tar (storage.cfg, user.cfg, qemu-server/*.conf)
     into /etc/pve. Cluster members: follow the Proxmox docs for re-joining instead.
  5. Restore VM disks: qmrestore <archive> <vmid> --storage <storage>  (proxmox/vm/RESTORE-vm.txt)
"""


# --------------------------------------------------------------------------- orchestrator
class ServerBackup:
    def __init__(self, cfg: Config, prompter: Optional[Prompter] = None,
                 reporter: Optional[Reporter] = None, config_path: Optional[Path] = None):
        self.cfg = cfg
        self.prompter = prompter or Prompter()
        self.reporter = reporter or (lambda lvl, msg: None)
        self.config_path = Path(config_path) if config_path else None
        self.host = host_id(cfg)
        self.dest = Destination(cfg, self.emit)
        self.ledger: Optional[Ledger] = None

    def emit(self, level: str, msg: str) -> None:
        log.log(getattr(logging, level.upper(), logging.INFO), msg)
        self.reporter(level, msg)

    def context(self, **kw) -> RunContext:
        return RunContext(cfg=self.cfg, emit=self.emit, prompter=self.prompter, dest=self.dest, host=self.host,
                          config_path=self.config_path, reporter=self.reporter, ledger=self.ledger, **kw)

    def luks_service(self) -> LuksBackupService:
        return LuksBackupService(self.cfg, self.prompter, self.reporter, self.config_path, dest=self.dest,
                                 ledger=self.ledger)

    def open_ledger(self) -> List[str]:
        """Load the ledger; warns if it vanished while earlier runs exist."""
        self.ledger = Ledger.for_config(self.cfg)
        ran_before = bool(self.config_path and (self.config_path.parent / "last_run.json").is_file())
        if self.ledger.was_missing and ran_before:
            return [f"tamper ledger {self.ledger.path} is missing although backups ran before (deleted?); "
                    "starting a new baseline"]
        return []

    def resolve_modules(self, profile: str = "", selected: Optional[List[str]] = None) -> Tuple[List[str], List[str]]:
        """(modules to run, notes). Profiles pick from enabled modules; explicit flags must be enabled."""
        notes: List[str] = []
        if profile:
            if profile not in self.cfg.profiles:
                raise BackupError(f"unknown profile '{profile}' (configured: {', '.join(self.cfg.profiles) or 'none'})")
            wanted = self.cfg.profiles[profile]
            unknown = [m for m in wanted if m not in MODULE_ORDER]
            if unknown:
                raise BackupError(f"profile '{profile}' names unknown module(s): {', '.join(unknown)}")
            mods = [m for m in wanted if self.cfg.module(m).enabled]
            notes += [f"profile '{profile}': module {m} is not enabled on this host; skipped"
                      for m in wanted if m not in mods]
            if not mods:
                raise BackupError(f"profile '{profile}' selects no module enabled in this config")
        elif selected:
            off = [m for m in selected if not self.cfg.module(m).enabled]
            if off:
                raise BackupError("not enabled in config: " + ", ".join(off)
                                  + " (set modules.<name>.enabled=true)")
            mods = list(selected)
        else:
            mods = [m for m in MODULE_ORDER if self.cfg.module(m).enabled]
            if not mods:
                raise BackupError("no modules enabled in config")
        return [m for m in MODULE_ORDER if m in mods], notes

    # ---- backup / verify
    def run(self, action: str, modules: List[str], profile: str = "", vmids: Optional[List[int]] = None,
            deep: bool = False, luks_opts: Optional[BackupOptions] = None, notes: Optional[List[str]] = None,
            wait_lock: int = 0) -> RunReport:
        LuksBackupService.require_root()
        rep = RunReport(host=self.host, action=action, profile=profile, selected=list(modules),
                        started=_now(), notes=list(notes or []))
        caps = EnvironmentDetector(self.cfg, self.emit).detect(probe_luks="luks" in modules)
        problems = self.cfg.validate()   # errors block their module; warnings are reported by the modules
        self.emit("info", f"{action} on {self.host} ({caps.host_type}): {', '.join(modules)}"
                          + (f" [profile {profile}]" if profile else ""))
        with LockManager(wait=wait_lock), self.dest.hold():
            rep.warnings += self.open_ledger()
            ctx = self.context(profile=profile, vmids=list(vmids or []), deep=deep)
            for s, lvl, msg in problems:
                if s == "global":
                    (rep.errors if lvl == "error" else rep.warnings).append(f"config: {msg}")
            try:
                self._run_modules(rep, modules, action, ctx, caps, problems, luks_opts)
            finally:
                self.ledger.save()
            rep.disk = disk_usage(self.cfg, self.dest._root, self.dest.display(self.dest._root) if self.dest.mounted
                                  else "")
            e, w = disk_messages(rep.disk)
            rep.errors += e
            rep.warnings += w
            for msg in rep.warnings:
                log.warning("%s", msg)
            for msg in rep.errors:
                self.emit("error", msg)
            if self.dest.mounted:
                rep.destination = dict(self.dest.preflight)
                self._finish(rep)
                try:
                    with self.dest.session() as root:
                        _write_atomic(root / "last_run.json", json.dumps(rep.to_dict(), indent=2))
                except (BackupError, OSError) as e:
                    self.emit("warning", f"could not write last_run.json to the share: {e}")
        return self._finish(rep)

    def _run_modules(self, rep: RunReport, modules: List[str], action: str, ctx: RunContext,
                     caps: Capabilities, problems, luks_opts: Optional[BackupOptions]) -> None:
        for m in modules:
            r = ModuleResult(m, action, started=_now())
            blocking = [msg for s, lvl, msg in problems if lvl == "error" and s == m]
            if not caps.modules[m]["available"]:
                r.errors.append(f"not available on this host: {caps.modules[m]['reason']}")
            elif blocking:
                r.errors += blocking
            else:
                self.emit("info", f"--- {m} {action}")
                try:
                    r = self._dispatch(m, action, ctx, luks_opts)
                except PromptUnavailable as e:
                    r.errors.append(f"input required but running non-interactively: {e}")
                except BackupError as e:
                    r.errors.append(str(e))
                except (OSError, subprocess.SubprocessError, ValueError, tarfile.TarError) as e:
                    log.debug("module %s failed", m, exc_info=True)
                    r.errors.append(f"{type(e).__name__}: {e}")
            r.finalize()
            rep.modules.append(r)
            for e in r.errors:
                self.emit("error", f"{m}: {e}")
            for w in r.warnings:   # log only: the console gets them in the final summary
                log.warning("%s: %s", m, w)
            for n in r.notes:
                log.info("%s: %s", m, n)
            self.emit("info", f"{m}: {r.status.upper()} {r.summary}")

    def _dispatch(self, m: str, action: str, ctx: RunContext, luks_opts: Optional[BackupOptions]) -> ModuleResult:
        if m == "luks":
            return self._luks(action, ctx, luks_opts)
        svc = {"files": DirectoryBackupService, "proxmox_vm": ProxmoxVmBackupService,
               "proxmox_host": ProxmoxHostBackupService}[m](ctx)
        return svc.verify(ctx.deep) if action == "verify" else svc.backup()

    def _luks(self, action: str, ctx: RunContext, opts: Optional[BackupOptions]) -> ModuleResult:
        svc = self.luks_service()
        opts = opts or BackupOptions()
        rep = svc.verify(opts) if action == "verify" else svc.backup(opts)
        r = ModuleResult("luks", action, started=rep.started, details=rep.to_dict())
        r.errors += rep.errors
        r.warnings += rep.warnings
        for d in rep.devices:
            r.errors += [f"{d.device}: {e}" for e in d.errors]
            r.warnings += [f"{d.device}: {w}" for w in d.warnings]
        r.artifacts = list(rep.destinations)
        r.summary = f"{len(rep.devices)} LUKS device(s)" + (f", backup {rep.timestamp}" if action == "backup"
                                                            else ", keys validated")
        if action == "verify":
            verify_stored(ctx, "luks", self.cfg.modules.luks.stale_after_days, r)
        return r

    def _finish(self, rep: RunReport, record: bool = True) -> RunReport:
        rep.finished = _now()
        rep.status, rep.exit_code = "ok", EXIT_OK
        if rep.errors or any(m.status == "error" for m in rep.modules):
            rep.status, rep.exit_code = "error", EXIT_ERROR
        elif rep.warnings or any(m.status == "warning" for m in rep.modules):
            rep.status, rep.exit_code = "warning", EXIT_WARN
        if self.config_path and record:
            try:
                _mkdir_private(self.config_path.parent)
                _write_private(self.config_path.parent / "last_run.json", json.dumps(rep.to_dict(), indent=2))
            except OSError:
                pass
        return rep

    # ---- single-module commands
    def _single(self, action: str, fn: Callable[[RunContext], ModuleResult], module: str,
                **ctx_kw) -> RunReport:
        LuksBackupService.require_root()
        rep = RunReport(host=self.host, action=action, selected=[module], started=_now())
        r = ModuleResult(module, action, started=_now())
        with LockManager(), self.dest.hold():
            rep.warnings += self.open_ledger()
            try:
                r = fn(self.context(**ctx_kw))
            except PromptUnavailable as e:
                r.errors.append(f"input required but running non-interactively: {e}")
            except BackupError as e:
                r.errors.append(str(e))
            finally:
                self.ledger.save()
        rep.modules.append(r.finalize())
        return self._finish(rep)

    # ---- tamper ledger
    def ledger_current(self, modules: List[str]) -> Dict[str, Dict[str, str]]:
        """What is on the destinations now, per ledger collection (+ restic repo ids under '#repo')."""
        out: Dict[str, Dict[str, str]] = {}
        ctx = self.context()
        for m in modules:
            if m in ("luks", "proxmox_host"):
                kind = "luks" if m == "luks" else ProxmoxHostBackupService.kind
                if self.cfg.cifs.enabled:
                    with self.dest.session() as root:
                        out[ledger_label(kind, self.dest.display(root / kind))] = timestamped_entries(root / kind)
                if self.cfg.keep_local:
                    local = self.dest.local_dir(kind)
                    out[ledger_label(kind, local)] = timestamped_entries(local)
            elif m == "proxmox_vm":
                svc = ProxmoxVmBackupService(ctx)
                with svc.target() as (base, _, show):
                    for vmid in svc.mc.vmids:
                        out[ledger_label(f"proxmox_vm/{vmid}", show(base / str(vmid)))] = svc.entries(base / str(vmid), vmid)
            elif m == "files":
                svc = DirectoryBackupService(ctx)
                with svc.environment() as (env, _):
                    svc.require_repo(env)
                    out[svc.ledger_coll] = svc.snapshot_entries(env)
                    out.setdefault("#repo", {})[svc.ledger_repo_key] = svc.repo_id
        return out

    def ledger_accept(self, modules: List[str]) -> RunReport:
        """Re-baseline: trust what is on the destinations now (after intended manual deletions)."""
        LuksBackupService.require_root()
        rep = RunReport(host=self.host, action="ledger-accept", selected=list(modules), started=_now())
        with LockManager(), self.dest.hold():
            self.open_ledger()
            for m in modules:
                r = ModuleResult(m, "ledger-accept", started=_now())
                try:
                    for coll, entries in self.ledger_current([m]).items():
                        if coll == "#repo":
                            for k, v in entries.items():
                                self.ledger.set_value(k, v, force=True)
                            continue
                        e, w = self.ledger.check(coll, entries)
                        self.ledger.accept(coll, entries)
                        r.notes.append(f"{coll}: {len(entries)} backup(s) accepted"
                                       + (" (resolved: " + "; ".join(e + w) + ")" if e or w else ""))
                except BackupError as e:
                    r.errors.append(str(e))
                rep.modules.append(r.finalize())
            self.ledger.save()
        return self._finish(rep)

    # ---- backup key test
    def _newest_encrypted_archive(self) -> Optional[Path]:
        """Newest <ts>.tar.gpg of the host-config or LUKS module, on the share (preferred) or local."""
        dirs = []
        if self.cfg.cifs.enabled:
            with self.dest.session() as root:   # stays mounted: called inside hold()
                dirs += [root / ProxmoxHostBackupService.kind, root / "luks"]
        dirs += [self.dest.local_dir(ProxmoxHostBackupService.kind), self.dest.local_dir("luks")]
        found = [p for d in dirs if d.is_dir() for p in d.glob("*.tar.gpg") if TS_RE.match(p.name)]
        return max(found, key=lambda p: (TS_RE.match(p.name).group(1), "luks" not in str(p))) if found else None

    def gpg_test(self, key_file: str = "", archive: str = "") -> RunReport:
        """Restore drill for the backup key: does the key + passphrase from Vaultwarden decrypt the
        newest real archive? Uses a temporary keyring in RAM; writes nothing decrypted to disk."""
        LuksBackupService.require_root()
        rep = RunReport(host=self.host, action="gpg-test", selected=["gpg"], started=_now())
        r = ModuleResult("gpg", "gpg-test", started=_now())
        try:
            data = read_private_key(self.prompter, key_file)
            passphrase = self.prompter.secret("Passphrase of the backup key (input hidden)")
            with self.dest.hold():
                arch = Path(archive) if archive else self._newest_encrypted_archive()
                if arch is None:
                    r.warnings.append("no encrypted archive found yet (run a proxmox_host or luks backup); "
                                      "tested the key and passphrase only")
                elif not arch.is_file():
                    raise BackupError(f"archive not found: {arch}")
                else:
                    r.details["archive"] = self.dest.display(arch) if self.dest.mounted else str(arch)
                restore_key_test(data, passphrase, self.cfg.gpg_recipient, arch, r)
                del passphrase
            r.summary = "backup key, passphrase" + (" and newest archive" if arch else "") + (
                " OK" if not r.errors else " - PROBLEM")
        except PromptUnavailable as e:
            r.errors.append(f"gpg-test is interactive (passphrase prompt): {e}")
        except (BackupError, OSError) as e:
            r.errors.append(str(e))
        rep.modules.append(r.finalize())
        return self._finish(rep, record=False)

    def ledger_summary(self) -> dict:
        led = Ledger.for_config(self.cfg)
        return {"path": str(led.path), "exists": not led.was_missing, "updated": led.data.get("updated"),
                "collections": {k: len(v) for k, v in led.data["collections"].items()},
                "values": led.data["values"]}

    def restore_test_files(self, path: str = "") -> RunReport:
        return self._single("restore-test", lambda ctx: DirectoryBackupService(ctx).restore_test(path), "files")

    def restore_test_vm(self, vmid: int, test_vmid: int, storage: str, assume_yes: bool, deep: bool) -> RunReport:
        return self._single("restore-test", lambda ctx: ProxmoxVmBackupService(ctx).restore_test(
            vmid, test_vmid, storage, self.prompter, assume_yes), "proxmox_vm", deep=deep)

    def files_init(self) -> RunReport:
        return self._single("files-init", lambda ctx: DirectoryBackupService(ctx).init(self.prompter), "files")

    def files_snapshots(self) -> List[dict]:
        LuksBackupService.require_root()
        with self.dest.hold():
            svc = DirectoryBackupService(self.context())
            with svc.environment() as (env, _):
                svc.require_repo(env)
                return svc.snapshots(env)

    # ---- status
    def status(self, quick: bool = False) -> dict:
        LuksBackupService.require_root()
        caps = EnvironmentDetector(self.cfg, self.emit).detect(probe_luks=True)
        st: dict = {"tool_version": __version__, "host": self.host, "time": _now(),
                    "disk_warn": self.cfg.disk_warn_percent,
                    "config": str(self.config_path or ""), "capabilities": asdict(caps), "modules": {},
                    "profiles": self.cfg.profiles, "destination": {}, "gpg": {}, "luks": {}, "files": {},
                    "proxmox_vm": [], "proxmox_host": {}, "disk": [], "last_run": None,
                    "notes": [], "warnings": [], "errors": []}
        for scope, lvl, msg in self.cfg.validate():
            {"error": st["errors"], "warning": st["warnings"]}.get(lvl, st["notes"]).append(f"config: {msg}")
        if LockManager.is_locked():
            st["notes"].append("a backup run is in progress right now")
        for m in MODULE_ORDER:
            mc, cap = self.cfg.module(m), caps.modules[m]
            st["modules"][m] = {"enabled": mc.enabled, "available": cap["available"], "reason": cap["reason"],
                                "profiles": [p for p, mods in self.cfg.profiles.items() if m in mods]}
            if mc.enabled and not cap["available"]:
                st["warnings"].append(f"{m} is enabled but not available here: {cap['reason']}")
            elif not mc.enabled and cap["available"]:
                st["notes"].append(f"{m} could run here but is not enabled ({cap['reason']})")
        gs = self.luks_service().gpg_status()
        st["gpg"] = asdict(gs)
        if gs.enabled and not gs.encrypt_test_ok:
            st["errors"].append(f"GPG encryption configured but not usable: {gs.message}")
        for f in gs.pending_exports:
            st["warnings"].append(f"private key export {f} still on this machine (see gpg-status)")
        n = self.cfg.notify
        st["notify"] = {"email": n.email, "on": n.on, "method": n.method,
                        "via": n.smtp_host if n.method == "smtp" else "local sendmail"}
        if not n.email:
            st["notes"].append("email reports are off (set notify.email and notify.smtp_host, then notify-test)")
        try:
            st["warnings"] += self.open_ledger()   # read-only here: status never saves the ledger
        except BackupError as e:
            st["errors"].append(str(e))
        ctx = self.context()
        with self.dest.hold():
            root = self._status_destination(st, quick)
            if self.cfg.modules.luks.enabled:
                self._status_luks(st, ctx, root, quick)
            if self.cfg.modules.files.enabled:
                self._status_files(st, ctx, quick)
            if self.cfg.modules.proxmox_vm.enabled:
                self._status_vms(st, ctx, root, caps)
            if self.cfg.modules.proxmox_host.enabled:
                self._status_kind(st["proxmox_host"], ctx, root, ProxmoxHostBackupService.kind,
                                  self.cfg.modules.proxmox_host.stale_after_days, st)
            st["disk"] = disk_usage(self.cfg, self.dest._root,
                                    self.dest.display(self.dest._root) if self.dest.mounted else "")
        e, w = disk_messages(st["disk"])
        st["errors"] += e
        st["warnings"] += w
        if self.config_path and (self.config_path.parent / "last_run.json").is_file():
            try:
                lr = json.loads((self.config_path.parent / "last_run.json").read_text())
                st["last_run"] = {k: lr.get(k) for k in ("action", "profile", "started", "finished", "status")}
                st["last_run"]["modules"] = {m.get("module"): m.get("status") for m in lr.get("modules", [])}
            except (OSError, ValueError):
                pass
        return st

    def _status_destination(self, st: dict, quick: bool) -> Optional[Path]:
        c = self.cfg.cifs
        if not c.enabled:
            ld = Path(self.cfg.local_dir)
            st["destination"] = {"type": "local", "path": str(ld),
                                 "free_bytes": Destination.free_bytes(ld) if ld.is_dir() else None}
            st["notes"].append("CIFS disabled: LUKS/host backups stay local only")
            return None
        st["destination"] = {"type": "cifs", "share": c.share, "subdir": c.subdir,
                             "credentials_user": read_cifs_username(c.credentials_file) or "?",
                             "seal": "seal" in c.mount_options, "checked": not quick}
        if "seal" not in c.mount_options:
            st["notes"].append("SMB traffic is not encrypted (no 'seal' in mount_options); VM archives and "
                               "unencrypted backups cross the network in clear")
        if quick:
            return None
        try:
            with self.dest.session():
                st["destination"].update(self.dest.preflight, ok=True)
            return self.dest._root
        except (BackupError, OSError) as e:
            st["destination"].update(ok=False, error=str(e))
            st["errors"].append(f"CIFS destination: {e}")
            emit_cifs_hints(self.emit, str(e))
            return None

    def _status_kind(self, out: dict, ctx: RunContext, root: Optional[Path], kind: str, stale: int, st: dict) -> None:
        locs = []
        if root is not None:
            locs.append(("cifs", root / kind))
        if ctx.dest.local_dir(kind).is_dir():
            locs.append(("local", ctx.dest.local_dir(kind)))
        for where, d in locs:
            s = latest_timestamped(d)
            age = stamp_age_days(s) if s else None
            out[where] = {"latest": s, "age_days": round(age, 1) if age is not None else None}
            self._status_tamper(st, ledger_label(kind, ctx.dest.display(d) if where == "cifs" else d),
                                timestamped_entries(d))
            if s is None:
                st["warnings"].append(f"{kind}: no backups yet ({where})")
            elif stale and age is not None and age > stale:
                st["warnings"].append(f"{kind}: latest {where} backup is {age:.0f} days old")

    def _status_tamper(self, st: dict, label: str, current: Dict[str, str]) -> None:
        if self.ledger:
            e, w = self.ledger.check(label, current)
            st["errors"] += e
            st["warnings"] += w

    def _status_luks(self, st: dict, ctx: RunContext, root: Optional[Path], quick: bool) -> None:
        if not quick and shutil.which("cryptsetup"):
            try:
                devs = self.luks_service().discover()
                st["luks"]["devices"] = [{"path": d.path, "uuid": d.uuid, "luks_version": d.luks_version,
                                          "open": d.mapped_name, "crypttab": d.crypttab.name if d.crypttab else None,
                                          "slots": {str(k): v for k, v in sorted(d.slot_types.items())}}
                                         for d in devs]
                for d in devs:
                    if d.keyslots and not any(t in (PASS_SLOT, "recovery-key") for t in d.slot_types.values()):
                        st["warnings"].append(f"luks: {d.path} has no passphrase/recovery keyslot")
            except BackupError as e:
                st["warnings"].append(f"luks: discovery failed: {e}")
        self._status_kind(st["luks"], ctx, root, "luks", self.cfg.modules.luks.stale_after_days, st)

    def _status_files(self, st: dict, ctx: RunContext, quick: bool) -> None:
        mc, svc = self.cfg.modules.files, DirectoryBackupService(ctx)
        info = st["files"]
        info.update(repository=svc.repo_display(), paths=mc.paths, excludes=mc.excludes,
                    exclude_files=mc.exclude_files, max_file_size=mc.max_file_size,
                    large_file_action=mc.large_file_action,
                    missing_paths=[p for p in mc.paths if not os.path.exists(p)],
                    password_file=mc.password_file, password_file_present=Path(mc.password_file).is_file())
        if info["missing_paths"]:
            lvl = "warnings" if mc.allow_missing_paths else "errors"
            st[lvl].append(f"files: configured path(s) missing: {', '.join(info['missing_paths'])}")
        if not info["password_file_present"]:
            st["errors"].append(f"files: Restic password file {mc.password_file} missing (run files-init)")
            return
        if quick or not shutil.which("restic"):
            return
        try:
            with svc.environment() as (env, _):
                try:
                    svc.require_repo(env)
                    info["repository_ok"] = True
                except BackupError as e:
                    info["repository_ok"] = False
                    st["errors"].append(f"files: {e}")
                    return
                r = ModuleResult("files", "status")
                svc.tamper_check(env, r)
                st["errors"] += r.errors
                st["warnings"] += r.warnings
                snap = svc.latest_snapshot(env)
                if snap:
                    age = rfc3339_age_days(snap.get("time", ""))
                    info["latest_snapshot"] = {"id": snap.get("short_id"), "time": snap.get("time"),
                                               "age_days": round(age, 1) if age is not None else None}
                    if age is not None and mc.stale_after_days and age > mc.stale_after_days:
                        st["warnings"].append(f"files: latest snapshot is {age:.1f} days old")
                else:
                    st["warnings"].append("files: no snapshots yet")
        except BackupError as e:
            st["errors"].append(f"files: {e}")

    def _status_vms(self, st: dict, ctx: RunContext, root: Optional[Path], caps: Capabilities) -> None:
        if not caps.modules["proxmox_vm"]["available"]:
            return
        svc = ProxmoxVmBackupService(ctx)
        base = None
        if root is not None:
            base = root / "proxmox" / "vm"
        elif not self.cfg.cifs.enabled and svc.mc.dumpdir and os.path.isdir(svc.mc.dumpdir):
            base = Path(svc.mc.dumpdir)
        try:
            known = {v["vmid"]: v for v in svc.list_vms()}
        except BackupError as e:
            st["errors"].append(f"proxmox_vm: {e}")
            known = {}
        unconfigured = sorted(set(known) - set(svc.mc.vmids))
        if unconfigured:
            st["notes"].append(f"proxmox_vm: VMs not configured for backup: {', '.join(map(str, unconfigured))}")
        for vmid in svc.mc.vmids:
            vi = svc.vm_info(vmid)
            e = {"vmid": vmid, "exists": vi.exists, "name": vi.name, "status": vi.status,
                 "agent_configured": vi.agent_configured, "agent_responding": vi.agent_responding,
                 "allocated_bytes": vi.estimated_bytes, "excluded_disks": vi.excluded_disks, "warnings": vi.warnings}
            if not vi.exists:
                st["errors"].append(f"proxmox_vm: configured VM {vmid} does not exist on this node")
            st["warnings"] += [f"proxmox_vm: VM {vmid} ({vi.name}): {w}" for w in vi.warnings]
            st["notes"] += [f"proxmox_vm: VM {vmid} ({vi.name}): {n}" for n in vi.notes]
            if base is not None:
                show = self.dest.display if root is not None else str
                self._status_tamper(st, ledger_label(f"proxmox_vm/{vmid}", show(base / str(vmid))),
                                    svc.entries(base / str(vmid), vmid))
                latest = svc.latest(base / str(vmid), vmid)
                if latest:
                    meta, archive = latest
                    age = stamp_age_days(VZDUMP_RE.match(archive.name).group(2))
                    e["latest_backup"] = {"archive": archive.name, "size": meta["size"],
                                          "age_days": round(age, 1) if age is not None else None}
                    if age is not None and svc.mc.stale_after_days and age > svc.mc.stale_after_days:
                        st["warnings"].append(f"proxmox_vm: VM {vmid} latest backup is {age:.0f} days old")
                else:
                    st["warnings"].append(f"proxmox_vm: VM {vmid} has no valid backup yet")
            st["proxmox_vm"].append(e)

    # ---- configure
    def configure_modules(self) -> None:
        p, c = self.prompter, self.cfg
        if not p.interactive:
            raise PromptUnavailable("configure requires an interactive prompter")
        caps = EnvironmentDetector(c, self.emit).detect()
        self.emit("info", f"\nThis machine: {caps.host_type}" + (f" ({caps.virtualization})" if caps.virtualization
                                                                  not in ("", "none") else ""))
        for m in MODULE_ORDER:
            self.emit("info", f"  {m:<13} {'available' if caps.modules[m]['available'] else 'not available'}: "
                              f"{caps.modules[m]['reason']}")

        def ask_list(msg, cur):
            return [x.strip() for x in p.text(msg, ",".join(map(str, cur))).split(",") if x.strip()]

        def ask_int(msg, cur):
            while True:
                try:
                    return int(p.text(msg, str(cur)))
                except ValueError:
                    pass

        m = c.modules
        m.luks.enabled = p.confirm("Enable the LUKS recovery module?",
                                   m.luks.enabled and caps.modules["luks"]["available"])
        if caps.modules["files"]["available"] or m.files.enabled:
            m.files.enabled = p.confirm("Enable Restic backups of selected directories?", m.files.enabled)
        if m.files.enabled:
            f = m.files
            f.paths = ask_list("Absolute paths to back up (comma-separated)", f.paths)
            f.excludes = ask_list("Exclude patterns (comma-separated; NOTHING is excluded unless listed)", f.excludes)
            f.repository = p.text("Restic repository ('' = on the CIFS share at <subdir>/<host>/restic)",
                                  f.repository)
            f.password_file = p.text("Restic password file", f.password_file)
            f.keep_daily = ask_int("Snapshots: keep daily", f.keep_daily)
            f.keep_weekly = ask_int("Snapshots: keep weekly", f.keep_weekly)
            f.keep_monthly = ask_int("Snapshots: keep monthly", f.keep_monthly)
        if caps.modules["proxmox_vm"]["available"] or m.proxmox_vm.enabled:
            m.proxmox_vm.enabled = p.confirm("Enable Proxmox VM backups (vzdump)?", m.proxmox_vm.enabled)
        if m.proxmox_vm.enabled:
            try:
                for v in ProxmoxVmBackupService(self.context()).list_vms():
                    self.emit("info", f"    {v['vmid']:>5}  {v['name']:<24} {v['status']}")
            except BackupError as e:
                self.emit("warning", str(e))
            while True:
                try:
                    m.proxmox_vm.vmids = [int(x) for x in ask_list(
                        "VM IDs to back up (comma-separated; VMs are never added automatically)", m.proxmox_vm.vmids)]
                    break
                except ValueError:
                    self.emit("warning", "  numbers only")
            m.proxmox_vm.retention = ask_int("Valid backups to keep per VM (0 = keep all)", m.proxmox_vm.retention)
        if caps.modules["proxmox_host"]["available"] or m.proxmox_host.enabled:
            m.proxmox_host.enabled = p.confirm("Enable Proxmox host configuration backups?", m.proxmox_host.enabled)
        if m.proxmox_host.enabled:
            m.proxmox_host.retention = ask_int("Host config backups to keep", m.proxmox_host.retention)
        for scope, lvl, msg in c.validate():
            self.emit("warning" if lvl == "error" else "info", f"  config {lvl}: {msg}")


# --------------------------------------------------------------------------- email reports
class Notifier:
    """Email reports, sent directly over SMTP (no local mail server needed) or via a local sendmail."""
    RANK = {"ok": 0, "warning": 1, "error": 2}
    THRESHOLD = {"always": 0, "warning": 1, "error": 2}

    def __init__(self, cfg: Config, emit: Optional[Reporter] = None):
        self.cfg, self.emit = cfg, emit or (lambda lvl, msg: None)

    @property
    def configured(self) -> bool:
        return bool(self.cfg.notify.email)

    def wants(self, status: str) -> bool:
        n = self.cfg.notify
        return self.configured and self.RANK.get(status, 2) >= self.THRESHOLD.get(n.on, 1)

    def send(self, subject: str, body: str) -> None:
        n = self.cfg.notify
        host = socket.getfqdn() or host_id(self.cfg)
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject, n.sender or f"server-backup@{host}", ", ".join(n.email)
        msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain=host)
        msg.set_content(body)
        try:
            if n.method == "sendmail":
                sendmail = shutil.which("sendmail") or "/usr/sbin/sendmail"
                rc, _, err = _run([sendmail, "-t", "-oi"], input_bytes=msg.as_bytes(), timeout=n.timeout)
                if rc:
                    raise BackupError(f"sendmail failed: {err.strip()[-300:]}")
                return
            user, pw = read_credentials(n.credentials_file) if n.credentials_file else ("", "")
            smtp_cls = smtplib.SMTP_SSL if n.security == "ssl" else smtplib.SMTP
            with smtp_cls(n.smtp_host, n.smtp_port, timeout=n.timeout) as smtp:
                if n.security == "starttls":
                    smtp.starttls(context=ssl.create_default_context())
                if user:
                    smtp.login(user, pw)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as e:   # messages never contain the password
            raise BackupError(f"email to {', '.join(n.email)} via {n.smtp_host or n.method} failed: {e}")

    def report(self, rep: RunReport) -> Optional[str]:
        """Send the run report if notify.on asks for it. Returns an error message if sending failed."""
        if not self.wants(rep.status):
            return None
        out = io.StringIO()
        print_run_human(rep, out)
        prof = f" {rep.profile}" if rep.profile else ""
        body = (out.getvalue().lstrip("\n") + f"\nstarted {rep.started}, finished {rep.finished}\n"
                f"server_backup.py {__version__} on {rep.host}; log: {self.cfg.log_file}\n"
                f"details: server_backup.py status\n")
        try:
            self.send(f"[server-backup] {rep.host}: {rep.status.upper()} - {rep.action}{prof}", body)
            self.emit("info", f"Report emailed to {', '.join(self.cfg.notify.email)}")
            return None
        except BackupError as e:
            return str(e)

    def failure(self, action: str, error: str) -> Optional[str]:
        """A run that could not even start (lock busy, unreadable config, ...)."""
        if not self.wants("error"):
            return None
        try:
            self.send(f"[server-backup] {host_id(self.cfg)}: ERROR - {action} did not run",
                      f"server_backup.py {action} failed before any backup ran:\n\n  {error}\n\n"
                      f"log: {self.cfg.log_file}\n")
            return None
        except BackupError as e:
            return str(e)

    def test(self) -> None:
        if not self.configured:
            raise BackupError("notify.email is empty; add recipients to the config first")
        n = self.cfg.notify
        self.send(f"[server-backup] {host_id(self.cfg)}: test message",
                  f"Test message from server_backup.py {__version__} on {host_id(self.cfg)}.\n\n"
                  f"If you can read this, email reports work.\n"
                  f"method: {n.method}  relay: {n.smtp_host or '-'}:{n.smtp_port}  security: {n.security}\n"
                  f"reports are sent when a run ends with: "
                  f"{ {'always': 'any result', 'warning': 'warning or error', 'error': 'error'}.get(n.on, n.on)}\n")


# --------------------------------------------------------------------------- examples
def example_config() -> dict:
    c = Config()
    c.cifs = CifsConfig(enabled=True, share="//nas.example.lan/backups", mount_options="vers=3,seal")
    c.modules.files = FilesModuleConfig(enabled=True, paths=["/home/user", "/mnt/local-data/project",
                                                             "/mnt/local-data-hdd/project"])
    c.modules.proxmox_vm = ProxmoxVmModuleConfig(enabled=False, vmids=[101, 102])
    c.modules.proxmox_host = ProxmoxHostModuleConfig(enabled=False)
    c.notify = NotifyConfig(email=["you@example.org"], smtp_host="smtp-relay.example.org")
    d = c.to_dict()
    d = {"_comment": "server_backup.py config. Detection says what CAN run; 'enabled' says what SHOULD. "
                     "Secrets live in separate files (cifs.credentials_file, modules.files.password_file).",
         **d}
    d["notify"]["_comment"] = ("Email reports after backup/verify: on = error | warning | always. "
                               "method smtp talks to the relay directly; credentials_file only if it needs a login.")
    d["schedules"]["_comment"] = ("systemd OnCalendar per profile; 'verify' = scheduled verify --deep. "
                                  "systemd-units writes timers only for profiles with an enabled module.")
    d["modules"]["_comment"] = ("On a Proxmox host set proxmox_vm.enabled/proxmox_host.enabled to true and "
                                "list VM IDs explicitly; on a VM leave them false.")
    return d


SERVICE_TEMPLATE = """[Unit]
Description=server_backup.py {what}
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart={exe}{cfg} {args} --non-interactive --wait-lock {wait}
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
# SIGTERM goes to server_backup.py first so it can stop vzdump/restic and unmount the share
KillMode=mixed
TimeoutStartSec=infinity
TimeoutStopSec=10min
# exit 2 = completed with warnings; uncomment to not mark the unit failed for warnings only
#SuccessExitStatus=2
"""

TIMER_TEMPLATE = """[Unit]
Description=server_backup.py {what}

[Timer]
OnCalendar={calendar}
RandomizedDelaySec={delay}
Persistent=true
Unit={unit}

[Install]
WantedBy=timers.target
"""


def systemd_units(cfg: Config, config_path: Path) -> Tuple[Dict[str, str], List[str], List[str]]:
    """
    (unit files, timers to enable, notes), built from this machine's config: one timer per profile
    that has an enabled module and a schedules.<profile> entry, plus the scheduled verify --deep
    (schedules.verify). Profiles that would do nothing here get no timer.
    """
    exe = str(Path(__file__).resolve())
    cfg_arg = "" if config_path == DEFAULT_CONFIG else f" -c {config_path}"
    units = {"server-backup@.service": SERVICE_TEMPLATE.format(
        what="profile %i", exe=exe, cfg=cfg_arg, args="backup --profile %i", wait="4h")}
    timers, notes = [], []
    for prof, mods in cfg.profiles.items():
        enabled = [m for m in mods if m in MODULE_ORDER and cfg.module(m).enabled]
        cal = cfg.schedules.get(prof, "")
        if prof == "verify":
            notes.append("profile 'verify': name is reserved for the scheduled verify; no timer")
        elif not enabled:
            notes.append(f"profile '{prof}': no module enabled on this machine; no timer")
        elif not cal:
            notes.append(f"profile '{prof}': no schedules.{prof} entry; no timer (run it by hand or add one)")
        else:
            name = f"server-backup-{prof}.timer"
            units[name] = TIMER_TEMPLATE.format(what=f"profile {prof}: {', '.join(enabled)}", calendar=cal,
                                                delay="15min", unit=f"server-backup@{prof}.service")
            timers.append(name)
    cal = cfg.schedules.get("verify", "")
    if cal and any(cfg.module(m).enabled for m in MODULE_ORDER):
        units["server-backup-verify.service"] = SERVICE_TEMPLATE.format(
            what="verify --deep", exe=exe, cfg=cfg_arg, args="verify --deep", wait="6h")
        units["server-backup-verify.timer"] = TIMER_TEMPLATE.format(
            what="verify --deep (reads every backup back)", calendar=cal, delay="30min",
            unit="server-backup-verify.service")
        timers.append("server-backup-verify.timer")
    elif not cal:
        notes.append("schedules.verify is empty; no scheduled verify --deep")
    return units, timers, notes


# --------------------------------------------------------------------------- CLI
COMMANDS = ["status", "backup", "verify", "restore-test", "ledger", "files-init", "files-snapshots", "discover",
            "configure", "cifs-setup", "cifs-test", "gpg-setup", "gpg-status", "gpg-test", "notify-test", "run",
            "example-config", "systemd-units"]

HELP_DESCRIPTION = """\
Backups for Proxmox hosts and Linux VMs/servers. One file, run as root.

modules (enabled in the config; detection decides what can run on this machine)
  luks          LUKS headers, keyfiles, saved passphrases     -> <share>/.../<host>/luks/
  files         Restic snapshots of configured directories    -> <host>/restic/
  proxmox_vm    vzdump of configured VM IDs                   -> <host>/proxmox/vm/<vmid>/
  proxmox_host  Proxmox host configuration + inventory        -> <host>/proxmox/host/

quick start
  server_backup.py configure                interactive setup: share, encryption, modules
  server_backup.py status                   what can run, what is enabled, share health, warnings
  server_backup.py files-init               once, before the first files backup
  server_backup.py backup --profile daily   run a profile (daily / weekly / recovery)
  server_backup.py systemd-units --output-dir /etc/systemd/system
"""

HELP_EPILOG = """\
commands
  status            report only, no backup (--quick: skip share mount and repository checks)
  backup            run --profile NAME, or module flags, or every enabled module
  verify            check stored backups and tamper ledger (--deep: full checksums, restic data
                    read, zstd -t)
  restore-test      --files [--path P]: restore into a temp dir and compare with the live file
                    --proxmox-vm --vmid V --test-vmid N --storage S: restore as a NEW stopped VM,
                    links down
  ledger            show the tamper ledger; --accept trusts what is on the destinations now
                    (after you deleted backups on purpose); module flags limit it
  gpg-test          restore drill for the backup key: paste the key from Vaultwarden (or give the
                    downloaded file), enter the passphrase; decrypts and checks the newest archive
  notify-test       send a test email with the notify settings
  files-init        create the Restic repository and password file
  files-snapshots   list this host's Restic snapshots
  discover          list LUKS devices, keyslots, crypttab matches
  configure, cifs-setup, cifs-test, gpg-setup, gpg-status    setup and checks
  run               legacy luks_backup.py LUKS backup (same output and --json)
  example-config    print a starting config
  systemd-units     write the service and the timers this machine needs (from profiles + schedules,
                    incl. the bi-monthly verify --deep) and print the systemctl enable line

examples
  server_backup.py backup --proxmox --vmid 101
  server_backup.py backup --files -v
  server_backup.py verify --deep --json
  server_backup.py restore-test --files --path /home/user/notes.txt
  server_backup.py restore-test --proxmox-vm --vmid 101 --test-vmid 9101 --storage local-lvm
  server_backup.py ledger --accept --files
  server_backup.py gpg-test --key-file /root/server-backup-key-XXXXXXXX.SECRET.asc

email        notify.email + notify.smtp_host in the config; backup/verify mail a report when the result
             is at least notify.on (default: warning). --no-notify skips it for a manual run.

exit codes   0 ok, 1 error (includes tamper findings), 2 warnings only, 130 interrupted
files        /etc/server-backup/config.json   /var/lib/server-backup/ledger.json
             /var/log/server-backup.log       README.md for the full documentation
"""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="server_backup.py", description=HELP_DESCRIPTION, epilog=HELP_EPILOG,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="status", choices=COMMANDS, metavar="command",
                    help="see 'commands' below (default: status)")
    ap.add_argument("-c", "--config", default=str(DEFAULT_CONFIG), metavar="FILE",
                    help=f"JSON config (default {DEFAULT_CONFIG})")
    ap.add_argument("-n", "--non-interactive", action="store_true", help="never prompt (scheduled jobs)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON on stdout")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug output (mount command, tool output)")
    ap.add_argument("--save", action="store_true", help="persist the 'overrides' options into the config")
    s = ap.add_argument_group("module selection (backup, verify, restore-test, ledger)")
    s.add_argument("--profile", metavar="NAME", help="modules in profiles.NAME that are enabled here")
    s.add_argument("--luks", action="store_true", help="LUKS recovery module")
    s.add_argument("--files", action="store_true", help="Restic directory module")
    s.add_argument("--proxmox", action="store_true", help="both Proxmox modules")
    s.add_argument("--proxmox-vm", action="store_true", help="vzdump of configured VMs")
    s.add_argument("--proxmox-host", action="store_true", help="Proxmox host configuration")
    s.add_argument("--vmid", type=int, action="append", default=[], metavar="ID",
                   help="only these configured VM IDs (repeatable)")
    o = ap.add_argument_group("command options")
    o.add_argument("--deep", action="store_true", help="verify: read everything back (slow)")
    o.add_argument("--quick", action="store_true", help="status: no share mount, no repository checks")
    o.add_argument("--accept", action="store_true", help="ledger: re-baseline to what exists now")
    o.add_argument("--wait-lock", type=parse_duration, default=0, metavar="DURATION",
                   help="wait up to DURATION (600, 30m, 4h) for a running backup instead of failing")
    o.add_argument("--path", default="", help="restore-test --files: file or directory to restore")
    o.add_argument("--test-vmid", type=int, metavar="ID", help="restore-test --proxmox-vm: an unused VM ID")
    o.add_argument("--storage", default="", help="restore-test --proxmox-vm: Proxmox storage for the disks")
    o.add_argument("--yes", action="store_true", help="restore-test: no confirmation prompt")
    o.add_argument("--output-dir", metavar="DIR", help="systemd-units: write files instead of printing")
    o.add_argument("--no-notify", action="store_true", help="backup/verify: do not send the email report")
    o.add_argument("--key-file", metavar="FILE", default="", help="gpg-test: private key file (else prompted)")
    o.add_argument("--archive", metavar="FILE", default="", help="gpg-test: .tar.gpg to decrypt (default: newest)")
    g = ap.add_argument_group("overrides (luks_backup.py compatible; persisted with --save)")
    g.add_argument("--local-dir")
    g.add_argument("--retention", type=int, help="LUKS backups kept per destination")
    g.add_argument("--keep-local", choices=["yes", "no"])
    g.add_argument("--cifs-share", help="//server/share[/subfolder] (enables CIFS)")
    g.add_argument("--cifs-subdir")
    g.add_argument("--cifs-credentials", help="credentials file (username=/password=/domain=)")
    g.add_argument("--cifs-user", help="write a credentials file for this user (password prompted "
                                       "or taken from $SERVER_BACKUP_CIFS_PASSWORD / $LUKS_BACKUP_CIFS_PASSWORD)")
    g.add_argument("--cifs-domain", default="")
    g.add_argument("--cifs-options", help="mount options, e.g. vers=3 or vers=3,seal ('' for none)")
    g.add_argument("--no-cifs", action="store_true")
    g.add_argument("--gpg-recipient", help="fingerprint of a key already in gpg_home ('' disables)")
    g.add_argument("--device", action="append", default=[], help="LUKS: limit to device path/UUID/mapper name")
    g.add_argument("--check-passphrases", action="store_true",
                   help="LUKS: also prompt to test a passphrase/recovery key on each device")
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
        pw = os.environ.get("SERVER_BACKUP_CIFS_PASSWORD", os.environ.get("LUKS_BACKUP_CIFS_PASSWORD"))
        if pw is None:
            pw = prompter.secret(f"CIFS password for {a.cifs_user}")
        write_cifs_credentials(cfg.cifs.credentials_file, a.cifs_user, pw, a.cifs_domain)
    return changed


def selected_modules(a) -> List[str]:
    sel = [m for m, flag in (("luks", a.luks), ("files", a.files), ("proxmox_vm", a.proxmox_vm or a.proxmox),
                             ("proxmox_host", a.proxmox_host or a.proxmox)) if flag]
    return [m for m in MODULE_ORDER if m in sel]


def print_human(rep: BackupReport) -> None:
    out = sys.stdout
    out.write(f"\n{rep.mode.upper()} {rep.timestamp} on {rep.host}: {rep.status.upper()}\n")
    for d in rep.devices:
        _print_luks_device(out, asdict(d))
    for dst in rep.destinations:
        out.write(f"  -> {dst['type']}: {dst.get('path', dst.get('share'))} "
                  f"{'OK' if dst.get('ok') else 'FAILED ' + dst.get('error', '')}\n")
    for w in rep.warnings:
        out.write(f"  ! {w}\n")
    for e in rep.errors:
        out.write(f"  X {e}\n")


def _print_luks_device(out, d: dict, indent: str = "  ") -> None:
    keys = [k for k in d["keys"] if k["ok"]]
    kdesc = ", ".join(f"{os.path.basename(k['path'])}(slot {k['slot']})" for k in keys) or "none"
    pp = sum(1 for c in d["passphrase_checks"] if c["ok"])
    out.write(f"{indent}{d['device']:<16} {d['status'].upper():<8} header={'OK' if d['header_verified'] else '-'}"
              f"  keyfiles={kdesc}" + (f"  passphrases_ok={pp}" if d["passphrase_checks"] else "")
              + f"  slots={','.join(f'{k}:{v}' for k, v in d['slot_types'].items())}\n")
    for w in d["warnings"]:
        out.write(f"{indent}    ! {w}\n")
    for e in d["errors"]:
        out.write(f"{indent}    X {e}\n")


def print_run_human(rep: RunReport, out=None) -> None:
    out = out or sys.stdout
    prof = f" (profile {rep.profile})" if rep.profile else ""
    out.write(f"\n{rep.action.upper()} on {rep.host}{prof}: {rep.status.upper()}\n")
    for m in rep.modules:
        out.write(f"  {m.module:<13} {m.status.upper():<8} {m.summary}\n")
        if m.module == "luks":
            for d in m.details.get("devices", []):
                _print_luks_device(out, d, "      ")
        for a in m.artifacts:
            where = a.get("path") or a.get("share") or a.get("dir") or a.get("id")
            if where:
                ok = a.get("ok", True)
                out.write(f"      -> {a.get('location') or a.get('type')}: {where} "
                          f"{'OK' if ok else 'FAILED ' + str(a.get('error', ''))}\n")
        for n in m.notes:
            out.write(f"      - {n}\n")
        # LUKS device problems are already shown per device above
        devs = tuple(f"{d['device']}: " for d in m.details.get("devices", [])) if m.module == "luks" else ()
        for w in m.warnings:
            if not (devs and w.startswith(devs)):
                out.write(f"      ! {w}\n")
        for e in m.errors:
            if not (devs and e.startswith(devs)):
                out.write(f"      X {e}\n")
    for n in rep.notes:
        out.write(f"  - {n}\n")
    for w in rep.warnings:
        out.write(f"  ! {w}\n")
    for e in rep.errors:
        out.write(f"  X {e}\n")


def print_status_human(st: dict) -> None:
    out = sys.stdout
    cap = st["capabilities"]
    out.write(f"\nserver_backup {st['tool_version']} on {st['host']}: {cap['host_type']}"
              + (f" ({cap['virtualization']})" if cap["virtualization"] not in ("", "none") else "")
              + (f", {cap['os']}" if cap["os"] else "") + "\n")
    out.write(f"  config: {st['config']}\n\nModules\n")
    for m, e in st["modules"].items():
        state = ("ENABLED " if e["enabled"] else "disabled") + ("  available" if e["available"] else "  unavailable")
        prof = f"  profiles: {','.join(e['profiles'])}" if e["profiles"] else ""
        out.write(f"  {m:<13} {state:<22} {e['reason']}{prof}\n")
    d = st["destination"]
    out.write("\nDestination\n")
    if d.get("type") == "cifs":
        health = ("OK" if d.get("ok") else f"FAILED: {d.get('error')}") if d.get("checked") else "not checked (--quick)"
        out.write(f"  CIFS {d['share']} (subdir {d['subdir']}, user {d['credentials_user']}"
                  f"{', sealed' if d['seal'] else ''}): {health}\n")
        if d.get("ok"):
            out.write(f"  {d['path']}  {_fmt_bytes(d['free_bytes'])} free\n")
    else:
        out.write(f"  local only: {d.get('path')}"
                  + (f"  {_fmt_bytes(d['free_bytes'])} free" if d.get("free_bytes") is not None else "") + "\n")
    nt = st.get("notify") or {}
    out.write("  Email reports: " + (f"to {', '.join(nt['email'])} via {nt['via']}, when the result is "
                                     f"{ {'always': 'anything', 'warning': 'warning or error', 'error': 'error'}.get(nt['on'], nt['on'])}"
                                     if nt.get("email") else "off") + "\n")
    g = st["gpg"]
    out.write(f"  Backup encryption key (LUKS + host-config archives): {'READY' if g['encrypt_test_ok'] else 'NOT WORKING' if g['enabled'] else 'off'}"
              + (f" [{g['recipient'][-16:]}]" if g["recipient"] else "") + "\n")

    def latest(info):
        return "  ".join(f"{w}: {v['latest'] or 'none'}" + (f" ({v['age_days']}d)" if v.get("age_days") is not None else "")
                         for w, v in info.items() if isinstance(v, dict) and "latest" in v)

    if st["luks"]:
        out.write("\nLUKS\n")
        for dv in st["luks"].get("devices", []):
            out.write(f"  {dv['path']:<16} LUKS{dv['luks_version']} open={dv['open'] or '-'} "
                      f"slots={','.join(f'{k}:{v}' for k, v in dv['slots'].items())}\n")
        if latest(st["luks"]):
            out.write(f"  latest backup  {latest(st['luks'])}\n")
    if st["files"]:
        f = st["files"]
        out.write(f"\nFiles (Restic)  {f['repository']}\n")
        for p in f["paths"]:
            out.write(f"  {p}{'  MISSING' if p in f['missing_paths'] else ''}\n")
        out.write(f"  excludes: {', '.join(f['excludes']) or 'none'}\n")
        if f.get("latest_snapshot"):
            ls = f["latest_snapshot"]
            out.write(f"  latest snapshot {ls['id']} {str(ls['time'])[:19]} ({ls['age_days']}d)\n")
    if st["proxmox_vm"]:
        out.write("\nProxmox VMs (configured)\n")
        for v in st["proxmox_vm"]:
            if not v["exists"]:
                out.write(f"  {v['vmid']:>5}  MISSING\n")
                continue
            agent = ("agent ok" if v["agent_responding"] else "agent NOT responding" if v["agent_responding"] is False
                     else "agent on" if v["agent_configured"] else "no agent")
            lb = v.get("latest_backup")
            out.write(f"  {v['vmid']:>5}  {v['name']:<20} {v['status']:<8} {agent:<20} "
                      f"disks {_fmt_bytes(v['allocated_bytes'])}"
                      + (f"  latest {lb['archive']} {_fmt_bytes(lb['size'])} ({lb['age_days']}d)" if lb else "") + "\n")
    if st["proxmox_host"]:
        out.write(f"\nProxmox host config  {latest(st['proxmox_host'])}\n")
    if st.get("disk"):
        out.write(f"\nDisk usage (warn {st.get('disk_warn', 90)}%)\n")
        for e in st["disk"]:
            mark = {"ok": " ", "warning": "!", "error": "X"}[e["level"]]
            free = f"  {_fmt_bytes(e['free_bytes'])} free" if e["free_bytes"] is not None else ""
            out.write(f"  {mark} {e['used_percent']:5.1f}%  {e['what']}{free}\n")
    if st["last_run"]:
        lr = st["last_run"]
        out.write(f"\nLast run: {lr['action']}{' ' + lr['profile'] if lr.get('profile') else ''} "
                  f"{lr['started']} -> {str(lr['status']).upper()}  "
                  + " ".join(f"{k}={v}" for k, v in (lr.get("modules") or {}).items()) + "\n")
    if st["notes"] or st["warnings"] or st["errors"]:
        out.write("\n")
    for n in st["notes"]:
        out.write(f"  - {n}\n")
    for w in st["warnings"]:
        out.write(f"  ! {w}\n")
    for e in st["errors"]:
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


def _install_signal_handlers() -> None:
    def handler(signum, frame):
        raise Interrupted(f"signal {signum}")
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, handler)


def load_config(path: Path, explicit: bool, reporter: Reporter) -> Tuple[Config, bool]:
    """(config, first_run). Without an explicit -c, a luks_backup.py config is imported if present."""
    if path.exists():
        return Config.load(path), False
    if not explicit and LEGACY_CONFIG.exists():
        reporter("warning", f"No config at {path}; imported {LEGACY_CONFIG} (luks_backup.py). "
                            f"It is written to {path} when saved; LUKS backups now go to "
                            "<subdir>/<host>/luks/ on the share and <local_dir>/<host>/luks/ locally.")
        return Config.load(LEGACY_CONFIG), False
    return Config(), True


def main(argv: Optional[List[str]] = None) -> int:
    os.umask(0o077)
    a = build_parser().parse_args(argv)
    interactive = not a.non_interactive and sys.stdin.isatty()
    prompter: Prompter = ConsolePrompter() if interactive else Prompter()
    reporter = console_reporter(a.verbose)

    if a.command == "example-config":
        print(json.dumps(example_config(), indent=2))
        return EXIT_OK
    if a.command == "systemd-units":   # needs to read the config, not root as such
        try:
            cfg, _ = load_config(Path(a.config), a.config != str(DEFAULT_CONFIG), reporter)
        except (OSError, BackupError, ValueError) as e:
            reporter("error", f"cannot read the config ({e}); run as root")
            return EXIT_ERROR
        units, timers, notes = systemd_units(cfg, Path(a.config))
        if a.output_dir:
            os.makedirs(a.output_dir, exist_ok=True)
            for name, body in units.items():
                Path(a.output_dir, name).write_text(body)
                os.chmod(Path(a.output_dir, name), 0o644)
                reporter("info", f"wrote {Path(a.output_dir, name)}")
            for old in sorted(Path(a.output_dir).glob("server-backup-*.timer")):
                if old.name not in units:
                    reporter("warning", f"{old} is not needed by this config: "
                                        f"systemctl disable --now {old.name} && rm {old}")
        else:
            for name, body in units.items():
                print(f"# ---- /etc/systemd/system/{name}\n{body}")
        for n in notes:
            reporter("info", f"note: {n}")
        if timers:
            reporter("info", "enable with: systemctl daemon-reload && systemctl enable --now " + " ".join(timers))
        return EXIT_OK

    _install_signal_handlers()
    notifier: Optional[Notifier] = None
    try:
        LuksBackupService.require_root()
        cfg_path = Path(a.config)
        cfg, first_run = load_config(cfg_path, a.config != str(DEFAULT_CONFIG), reporter)
        changed = apply_overrides(cfg, a, prompter)
        setup_logging(cfg.log_file, a.verbose)
        if a.command in ("backup", "verify") and not a.no_notify:
            notifier = Notifier(cfg, reporter)
        svc = LuksBackupService(cfg, prompter, reporter, cfg_path)
        sb = ServerBackup(cfg, prompter, reporter, cfg_path)

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

        if a.command == "configure" or (first_run and interactive and a.command in ("run", "backup")):
            if first_run:
                reporter("info", f"No config at {cfg_path}; starting first-run setup.")
            svc.configure()
            sb.configure_modules()
            svc.save_config()
            if a.command == "configure":
                return EXIT_OK
        elif (first_run and a.command in ("run", "backup")) or (changed and a.save):
            if first_run:
                reporter("warning", "No config found; using defaults + command-line options")
            svc.save_config()

        if a.command == "status":
            st = sb.status(quick=a.quick)
            print(json.dumps(st, indent=2, default=str)) if a.json else print_status_human(st)
            return EXIT_ERROR if st["errors"] else (EXIT_WARN if st["warnings"] else EXIT_OK)

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

        if a.command == "files-snapshots":
            snaps = sb.files_snapshots()
            if a.json:
                print(json.dumps(snaps, indent=2))
            else:
                for s in snaps:
                    print(f"{s.get('short_id', ''):<10} {str(s.get('time', ''))[:19]}  "
                          f"{','.join(s.get('tags') or [])}  {' '.join(s.get('paths') or [])}")
            return EXIT_OK

        luks_opts = BackupOptions(devices=a.device, check_passphrases=a.check_passphrases)
        if a.command == "run":   # luks_backup.py compatible: same report, output and JSON
            svc.ledger = Ledger.for_config(cfg)
            try:
                rep = svc.backup(luks_opts)
            finally:
                svc.ledger.save()
            print(json.dumps(rep.to_dict(), indent=2)) if a.json else print_human(rep)
            return rep.exit_code

        if a.command == "ledger" and not a.accept:
            led = sb.ledger_summary()
            if a.json:
                print(json.dumps(led, indent=2))
            else:
                print(f"tamper ledger {led['path']}" + (f" (updated {led['updated']})" if led["exists"] else
                                                        " - not created yet (first backup creates it)"))
                for coll, n in sorted(led["collections"].items()):
                    print(f"  {n:>4}  {coll}")
            return EXIT_OK

        if a.command == "notify-test":
            Notifier(cfg, reporter).test()
            reporter("info", f"test message sent to {', '.join(cfg.notify.email)} - check the inbox (and spam folder)")
            return EXIT_OK
        if a.command == "gpg-test":
            if not interactive:
                raise PromptUnavailable("gpg-test asks for the passphrase; run it in a terminal")
            rrep = sb.gpg_test(a.key_file, a.archive)
        elif a.command == "files-init":
            rrep = sb.files_init()
        elif a.command == "restore-test":
            if a.files == bool(a.proxmox_vm):
                raise BackupError("restore-test needs exactly one of --files or --proxmox-vm")
            if a.files:
                rrep = sb.restore_test_files(a.path)
            else:
                if len(a.vmid) != 1 or a.test_vmid is None:
                    raise BackupError("restore-test --proxmox-vm needs --vmid V --test-vmid N --storage S")
                rrep = sb.restore_test_vm(a.vmid[0], a.test_vmid, a.storage, a.yes, a.deep)
        elif a.command == "ledger":   # --accept
            mods, _ = sb.resolve_modules("", selected_modules(a))
            rrep = sb.ledger_accept(mods)
        else:   # backup / verify
            if a.profile and selected_modules(a):
                raise BackupError("use either --profile or module flags, not both")
            mods, notes = sb.resolve_modules(a.profile or "", selected_modules(a))
            if a.vmid and "proxmox_vm" not in mods:
                raise BackupError("--vmid given but proxmox_vm is not selected")
            rrep = sb.run(a.command, mods, profile=a.profile or "", vmids=a.vmid, deep=a.deep,
                          luks_opts=luks_opts, notes=notes, wait_lock=a.wait_lock)
        print(json.dumps(rrep.to_dict(), indent=2)) if a.json else print_run_human(rrep)
        if notifier:
            err = notifier.report(rrep)
            if err:
                reporter("warning", err)
                log.warning("%s", err)
                return max(rrep.exit_code, EXIT_WARN)
        return rrep.exit_code
    except PromptUnavailable as e:
        reporter("error", f"input required but running non-interactively: {e}")
        return EXIT_ERROR
    except BackupError as e:
        reporter("error", str(e))
        if notifier:
            err = notifier.failure(a.command, str(e))
            if err:
                reporter("warning", err)
        return EXIT_ERROR
    except KeyboardInterrupt:
        reporter("error", "interrupted")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
