"""
Tests for server_backup.py that run without root, Proxmox, restic or a real CIFS share.

External tools (qm, vzdump, qmrestore, restic, pveversion, lsblk, cryptsetup) are replaced by small
fakes in tests/fakebin; the CIFS mount is replaced by a local directory that reports fstype "cifs".
What is exercised is server_backup.py's own logic: preflight, module orchestration, artifact
detection, metadata, retention, verification, restore tests and reporting.

    python3 -m unittest discover -s tests -v
"""
import fcntl
import io
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import server_backup as sb  # noqa: E402

FAKEBIN = HERE / "fakebin"


class FakeDestination(sb.Destination):
    """The 'share' is a local directory; mount state is simulated."""
    share_dir: Path = None
    fs_ok = True
    mounts = 0

    def _mount_share(self):
        FakeDestination.mounts += 1
        self.share_dir.mkdir(parents=True, exist_ok=True)
        return self.share_dir

    def _is_mount(self, path):
        return FakeDestination.fs_ok

    def fstype(self, path):
        return ("cifs", self.cfg.cifs.share) if FakeDestination.fs_ok else ("ext4", "/dev/sda1")

    def _close(self):
        self._cifs, self._mnt, self._root = None, None, None


def silent(level, msg):
    pass


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sbtest-"))
        self.state = self.tmp / "state"
        self.state.mkdir()
        self.share = self.tmp / "share"
        self.pve = self.tmp / "pve"
        self.pve.mkdir()
        cred = self.tmp / "cifs.cred"
        cred.write_text("username=u\npassword=p\n")
        cred.chmod(0o600)
        self.cfg = sb.Config(local_dir=str(self.tmp / "local"), log_file=str(self.tmp / "log"),
                             gpg_home=str(self.tmp / "gnupg"), state_dir=str(self.tmp / "var-lib"))
        self.cfg.cifs = sb.CifsConfig(enabled=True, share="//nas/backups", credentials_file=str(cred),
                                      min_free_gb=0)
        self.cfg.disk_warn_percent = self.cfg.disk_error_percent = 100   # tests that need it lower it
        self.patches = [
            mock.patch("os.geteuid", return_value=0),
            mock.patch.object(sb, "LOCK_PATH", str(self.tmp / "lock")),
            mock.patch.object(sb, "LEGACY_LOCK_PATH", str(self.tmp / "legacy.lock")),
            mock.patch.object(sb, "Destination", FakeDestination),
            mock.patch.object(sb.EnvironmentDetector, "PVE_DIR", str(self.pve)),
            mock.patch.object(sb.ProxmoxHostBackupService, "CONFIG_DB", str(self.tmp / "config.db")),
            mock.patch.dict(os.environ, {"PATH": f"{FAKEBIN}:{os.environ['PATH']}",
                                         "FAKE_STATE": str(self.state)}),
        ]
        for p in self.patches:
            p.start()
        FakeDestination.share_dir, FakeDestination.fs_ok, FakeDestination.mounts = self.share, True, 0

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        os.system(f"chmod -R u+rwx '{self.tmp}' 2>/dev/null; rm -rf '{self.tmp}'")

    def server(self) -> sb.ServerBackup:
        return sb.ServerBackup(self.cfg, sb.Prompter(), silent, self.tmp / "etc" / "config.json")

    def root(self) -> Path:
        return self.share / "serverBackup" / sb.host_id(self.cfg)


# --------------------------------------------------------------------------- units
class TestConfig(unittest.TestCase):
    def test_legacy_luks_backup_config_loads(self):
        legacy = {"local_dir": "/var/backups/luks", "keep_local": True, "retention": 5,
                  "keyfile_globs": ["/root/*.key"], "gpg_recipient": "ABC", "gpg_home": "/etc/luks-backup/gnupg",
                  "log_file": "/var/log/luks-backup.log",
                  "cifs": {"enabled": True, "share": "//s/x", "subdir": "luks-backups",
                           "credentials_file": "/etc/luks-backup/cifs.cred", "mount_options": "vers=3"},
                  "devices": {"ABCD-1": {"keyfiles": ["/root/k"], "no_keyfile_ok": False, "skip": False, "note": ""}}}
        c = sb.Config.from_dict(legacy)
        self.assertTrue(c.modules.luks.enabled)
        self.assertFalse(c.modules.files.enabled)
        self.assertEqual(c.gpg_home, "/etc/luks-backup/gnupg")
        self.assertEqual(c.cifs.subdir, "luks-backups")
        self.assertEqual(c.override("abcd-1").keyfiles, ["/root/k"])
        self.assertEqual(sb.Config.from_dict(c.to_dict()), c)

    def test_validate(self):
        c = sb.Config()
        c.profiles["bad"] = ["nope"]
        c.modules.files.enabled = True
        c.modules.files.paths = ["relative/path"]
        c.modules.proxmox_vm.enabled = True
        c.modules.proxmox_vm.mode = "live"
        msgs = [(s, lvl) for s, lvl, _ in c.validate()]
        self.assertIn(("profiles", "error"), msgs)
        self.assertIn(("files", "error"), msgs)
        self.assertIn(("proxmox_vm", "error"), msgs)

    def test_unknown_and_duplicate_keys_are_reported(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "c.json"
        p.write_text('{"notfy": {}, "_comment": "ok", "modules": {"proxmox_vm": {"enabled": true}, '
                     '"proxmox_vm": {"vmids": [], "excluded_disk_ok": {}}}}')   # last duplicate wins
        msgs = [m for _, lvl, m in sb.Config.load(p).validate() if lvl == "warning"]
        self.assertIn("unknown key notfy is ignored (did you mean notify?)", msgs)
        self.assertIn("unknown key modules.proxmox_vm.excluded_disk_ok is ignored "
                      "(did you mean modules.proxmox_vm.excluded_disks_ok?)", msgs)
        self.assertTrue(any("'proxmox_vm' appears more than once" in m for m in msgs))
        self.assertFalse(any("_comment" in m for m in msgs))
        self.assertEqual(sb.Config.from_dict(sb.Config().to_dict()).load_problems, [])

    def test_notify_and_disk_validation(self):
        c = sb.Config()
        c.notify.email = ["a@b"]
        c.disk_warn_percent = 99
        c.disk_error_percent = 90
        msgs = " ".join(m for _, _, m in c.validate())
        self.assertIn("notify.smtp_host is empty", msgs)
        self.assertIn("disk_warn_percent", msgs)

    def test_bad_vmids(self):
        with self.assertRaises(sb.BackupError):
            sb.Config.from_dict({"modules": {"proxmox_vm": {"vmids": ["abc"]}}})
        self.assertEqual(sb.Config.from_dict({"modules": {"proxmox_vm": {"vmids": ["101"]}}}).modules.proxmox_vm.vmids,
                         [101])

    def test_progress_throttle(self):
        said, clock = [], [100.0]
        with mock.patch("server_backup.time.monotonic", lambda: clock[0]):
            on_line = sb.progress_lines(lambda lvl, m: said.append((lvl, m)), "VM 1: vzdump", sb.parse_vzdump_progress)
            for t, pct in ((100, 1), (110, 5), (131, 9)):
                clock[0] = t
                on_line(f"INFO:  {pct}% (1 GiB of 9 GiB) in 1s, read: x")
        self.assertEqual([m for lvl, m in said if lvl == "info"],
                         ["  VM 1: vzdump 1% (1 GiB of 9 GiB, 1s)", "  VM 1: vzdump 9% (1 GiB of 9 GiB, 1s)"])
        self.assertEqual(len([1 for lvl, _ in said if lvl == "debug"]), 3)          # every raw line for -v
        self.assertIsNone(sb.parse_vzdump_progress("INFO: backup is sparse: 213.42 GiB (83%) total zero data"))

    def test_parsers(self):
        self.assertEqual(sb.parse_size("32G"), 32 * 1024 ** 3)
        self.assertEqual(sb.parse_size("528K"), 528 * 1024)
        self.assertEqual(sb.parse_size("junk"), 0)
        self.assertEqual(sb.parse_duration("4h"), 14400)
        self.assertEqual(sb.parse_duration("90"), 90)
        self.assertIsNotNone(sb.rfc3339_age_days("2026-01-01T00:00:00.123456789+01:00"))
        self.assertIsNotNone(sb.stamp_age_days("2026_01_01-00_00_01"))


class TestRetention(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="sbret-"))

    def _groups(self, keys):
        g = {}
        for k in keys:
            p = self.d / f"{k}.dat"
            p.write_text(k)
            g[k] = [p]
        return g

    def test_failed_runs_never_displace_good_backups(self):
        g = self._groups(["a", "b", "c", "d", "e"])
        self.assertEqual(sb.RetentionManager.prune_groups(g, {"a", "c", "e"}, 3), [])
        self.assertEqual(sorted(sb.RetentionManager.prune_groups(g, {"a", "c", "e"}, 2)), ["a.dat", "b.dat"])
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), ["c.dat", "d.dat", "e.dat"])

    def test_date_based_selection(self):
        import datetime as real
        start = real.datetime(2026, 1, 1, 2, 0)
        keys = [(start + real.timedelta(days=i)).strftime("%Y%m%d-%H%M%S") for i in range(120)]   # daily for 4 months
        kept = sorted(sb.RetentionManager.select(keys, 1, daily=3, weekly=2, monthly=2))
        self.assertIn(keys[-1], kept)                                  # newest always
        self.assertEqual(set(keys[-3:]) <= set(kept), True)            # 3 newest days
        self.assertIn("20260331-020000", kept)                         # newest of the previous month
        self.assertEqual(len(kept), 5)                                 # 3 days (+ this week, this month) + last week + last month
        self.assertEqual(sb.RetentionManager.select([], 3), set())

    def test_date_based_prune_keeps_only_selected_valid_groups(self):
        import datetime as real
        keys = [(real.datetime(2026, 1, 1) + real.timedelta(weeks=i)).strftime("%Y_%m_%d-%H_%M_%S") for i in range(10)]
        g = self._groups(keys)
        removed = sb.RetentionManager.prune_groups(g, set(keys), 1, weekly=0, monthly=3)
        left = sorted(p.stem for p in self.d.iterdir())
        self.assertEqual(len(left), 3)                                 # newest of each of the last 3 months
        self.assertEqual(len(removed), 7)

    def test_keep_zero_keeps_all(self):
        g = self._groups(["a", "b"])
        self.assertEqual(sb.RetentionManager.prune_groups(g, {"a", "b"}, 0), [])

    def test_timestamped_matches_luks_backup_rule(self):
        for s in ("20260101-000000", "20260102-000000", "20260103-000000"):
            (self.d / s).mkdir()
            (self.d / f"{s}.tar.gpg").write_text("x")
        removed = sb.RetentionManager.prune_timestamped(self.d, 2)
        self.assertEqual(sorted(removed), ["20260101-000000", "20260101-000000.tar.gpg"])


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.led = sb.Ledger(Path(tempfile.mkdtemp(prefix="sbled-")) / "ledger.json")

    def test_first_run_adopts_then_detects(self):
        self.assertEqual(self.led.check("c", {"a": "1"}), ([], []))          # no baseline yet
        self.led.update("c", {"a": "1", "b": "2"}, added=["b"])
        self.assertEqual(self.led.check("c", {"a": "1", "b": "2"}), ([], []))
        errs, warns = self.led.check("c", {"b": "X", "z": "9"})
        self.assertIn("gone", errs[0])
        self.assertIn("changed", errs[1])
        self.assertIn("not made by this machine", warns[0])

    def test_own_removals_are_not_tamper_and_findings_persist(self):
        self.led.update("c", {"a": "1", "b": "2"})
        self.led.update("c", {"b": "2", "n": "3"}, added=["n"], removed=["a"])    # we pruned a
        self.assertEqual(self.led.check("c", {"b": "2", "n": "3"}), ([], []))
        self.led.update("c", {"n": "3", "m": "4"}, added=["m"])                   # b vanished
        self.assertTrue(self.led.check("c", {"n": "3", "m": "4"})[0])             # still flagged
        self.led.accept("c", {"n": "3", "m": "4"})
        self.assertEqual(self.led.check("c", {"n": "3", "m": "4"}), ([], []))

    def test_persistence_and_values(self):
        self.led.update("c", {"a": "1"})
        self.led.set_value("repo", "id1")
        self.led.set_value("repo", "id2")                                         # not overwritten
        self.led.save()
        again = sb.Ledger(self.led.path)
        self.assertFalse(again.was_missing)
        self.assertEqual(again.data["collections"]["c"], {"a": "1"})
        self.assertIn("was id1", again.check_value("repo", "id2"))
        self.assertEqual(oct(self.led.path.stat().st_mode & 0o777), "0o600")


class TestLock(unittest.TestCase):
    def test_reentrant_and_exclusive(self):
        path = tempfile.mktemp(prefix="sblock-")
        with sb.LockManager(path):
            with sb.LockManager(path):
                pass
            self.assertIn(path, sb.LockManager._held)
        self.assertNotIn(path, sb.LockManager._held)
        with open(path, "w") as other:           # simulates another process holding the lock
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(sb.BackupError):
                with sb.LockManager(path):
                    pass
            self.assertTrue(sb.LockManager.is_locked(path))


# --------------------------------------------------------------------------- integration (fakes)
class TestDestination(Base):
    def test_preflight_refuses_non_cifs_mount_and_writes_nothing(self):
        FakeDestination.fs_ok = False
        d = sb.Destination(self.cfg, silent)
        with self.assertRaisesRegex(sb.BackupError, "not a CIFS mount"):
            with d.session():
                pass
        self.assertEqual(list(self.share.rglob("*")), [])

    def test_one_mount_per_run_and_failure_memo(self):
        d = sb.Destination(self.cfg, silent)
        with d.hold():
            for _ in range(3):
                with d.session() as root:
                    self.assertTrue(root.is_dir())
        self.assertEqual(FakeDestination.mounts, 1)
        FakeDestination.fs_ok = False
        with d.hold():
            for _ in range(2):
                with self.assertRaises(sb.BackupError):
                    with d.session():
                        pass
        self.assertEqual(FakeDestination.mounts, 2)   # second failing attempt was memoised

    def test_min_free(self):
        self.cfg.cifs.min_free_gb = 10 ** 9
        with self.assertRaisesRegex(sb.BackupError, "free on the share"):
            with sb.Destination(self.cfg, silent).session():
                pass


class TestProxmoxVm(Base):
    def setUp(self):
        super().setUp()
        self.cfg.modules.proxmox_vm = sb.ProxmoxVmModuleConfig(enabled=True, vmids=[101, 102], retention=2)
        self.cfg.modules.luks.enabled = False

    def vm_dir(self, vmid=101) -> Path:
        return self.root() / "proxmox" / "vm" / str(vmid)

    def valid_groups(self, vmid=101):
        return sorted(p.name for p in self.vm_dir(vmid).glob(f"*{sb.VM_META_SUFFIX}"))

    def test_backup_metadata_and_retention(self):
        s = self.server()
        for _ in range(3):
            rep = s.run("backup", ["proxmox_vm"])
            self.assertEqual(rep.modules[0].errors, [])
        self.assertEqual(len(self.valid_groups(101)), 2)
        self.assertEqual(len(self.valid_groups(102)), 2)
        meta_file = self.vm_dir() / self.valid_groups()[-1]
        meta = json.loads(meta_file.read_text())
        archive = self.vm_dir() / meta["archive"]
        self.assertEqual(meta["size"], archive.stat().st_size)
        self.assertEqual(meta["sha256"], sb.sha256_file(archive))
        self.assertEqual(meta["excluded_disks"], ["scsi1"])
        self.assertTrue(meta["guest_agent"]["configured"])
        self.assertTrue((self.vm_dir() / (meta["archive"] + ".sha256")).is_file())
        self.assertTrue((self.vm_dir() / meta["archive"].replace(".vma.zst", ".qm-config.txt")).is_file())
        self.assertTrue((self.root() / "proxmox" / "vm" / "RESTORE-vm.txt").is_file())
        warnings = " ".join(rep.modules[0].warnings)
        self.assertIn("backup=0", warnings)                       # excluded disk is reported, not hidden
        self.assertTrue((self.root() / "last_run.json").is_file())
        # vzdump was told not to prune by itself
        args = (self.state / "vzdump-args").read_text()
        self.assertIn("--remove 0", args)
        self.assertIn("--mode snapshot", args)
        self.assertIn("--compress zstd", args)

    def test_progress_messages_and_logged_warnings(self):
        said = []
        s = sb.ServerBackup(self.cfg, sb.Prompter(), lambda lvl, msg: said.append((lvl, msg)), self.tmp / "etc" / "c.json")
        with self.assertLogs("server_backup", level="INFO") as logs:
            s.run("backup", ["proxmox_vm"], vmids=[102])
        info = [m for lvl, m in said if lvl == "info"]
        self.assertIn("  VM 102: vzdump 50% (128.0 GiB of 256.0 GiB, 3m 20s)", info)   # visible without -v
        self.assertNotIn("  VM 102: vzdump 100% (256.0 GiB of 256.0 GiB, 6m 41s)", info)  # throttled
        self.assertTrue(any(m.startswith("  computing sha256 of vzdump-qemu-102") for m in info))
        self.assertTrue(any("WARNING" in r and "backup=0" in r for r in logs.output))   # warnings reach the log

    def test_failed_backup_keeps_previous_and_cleans_partial(self):
        s = self.server()
        s.run("backup", ["proxmox_vm"])
        before = self.valid_groups()
        with mock.patch.dict(os.environ, {"FAKE_VZDUMP_FAIL": "1"}):
            for _ in range(3):
                rep = s.run("backup", ["proxmox_vm"])
                self.assertEqual(rep.exit_code, sb.EXIT_ERROR)
        self.assertEqual(self.valid_groups(), before)
        self.assertEqual(list(self.vm_dir().glob("*.dat")), [])
        self.assertTrue(list(self.vm_dir().glob("*.log")))       # failed run's log kept for diagnosis
        rep = s.run("backup", ["proxmox_vm"])
        self.assertEqual(rep.modules[0].errors, [])
        self.assertEqual(len(self.valid_groups()), 2)

    def test_tamper_detection_pauses_retention_until_accept(self):
        self.cfg.modules.proxmox_vm.retention = 1
        s = self.server()
        s.run("backup", ["proxmox_vm"], vmids=[101])
        s.run("backup", ["proxmox_vm"], vmids=[101])                       # prunes the first one itself
        meta = self.vm_dir() / self.valid_groups()[0]
        victim = json.loads(meta.read_text())["archive"]
        (self.vm_dir() / victim).unlink()                                  # attacker deletes a backup
        rep = s.run("backup", ["proxmox_vm"], vmids=[101])
        errs = " ".join(rep.modules[0].errors)
        self.assertIn("TAMPER CHECK", errs)
        self.assertIn(victim, errs)
        self.assertIn("retention paused", " ".join(rep.modules[0].notes))
        self.assertTrue(meta.exists())          # evidence kept: without the pause retention would delete it
        self.assertIn("TAMPER CHECK", " ".join(s.run("verify", ["proxmox_vm"], vmids=[101]).modules[0].errors))
        self.assertIn("TAMPER CHECK", " ".join(s.status()["errors"]))
        self.assertEqual(s.ledger_accept(["proxmox_vm"]).exit_code, sb.EXIT_OK)
        rep = s.run("backup", ["proxmox_vm"], vmids=[101])
        self.assertEqual(rep.modules[0].errors, [])

    def test_tamper_changed_metadata(self):
        s = self.server()
        s.run("backup", ["proxmox_vm"], vmids=[101])
        meta_p = self.vm_dir() / self.valid_groups()[0]
        meta = json.loads(meta_p.read_text())
        meta["sha256"] = "0" * 64
        meta_p.write_text(json.dumps(meta))
        rep = s.run("verify", ["proxmox_vm"], vmids=[101])
        self.assertIn("changed since they were written", " ".join(rep.modules[0].errors))

    def test_only_configured_vmids(self):
        s = self.server()
        rep = s.run("backup", ["proxmox_vm"], vmids=[999])
        self.assertIn("not in modules.proxmox_vm.vmids", " ".join(rep.modules[0].errors))
        self.assertFalse((self.root() / "proxmox" / "vm" / "999").exists())
        rep = s.run("backup", ["proxmox_vm"], vmids=[102])
        self.assertEqual(rep.modules[0].summary, "1/1 VM(s) backed up")
        self.assertFalse(self.vm_dir(101).exists())

    def test_no_space_refuses(self):
        self.cfg.modules.proxmox_vm.required_free_ratio = 10.0 ** 12
        rep = self.server().run("backup", ["proxmox_vm"])
        self.assertIn("not enough free space", " ".join(rep.modules[0].errors))
        self.assertFalse(list(self.vm_dir().glob("*.vma.zst")))

    def test_no_destination_never_falls_back_to_local(self):
        self.cfg.cifs.enabled = False
        rep = self.server().run("backup", ["proxmox_vm"])
        self.assertEqual(rep.exit_code, sb.EXIT_ERROR)
        self.assertFalse(Path(self.cfg.local_dir).exists() and list(Path(self.cfg.local_dir).rglob("*.vma*")))

    def test_verify_deep_detects_corruption(self):
        s = self.server()
        s.run("backup", ["proxmox_vm"])
        rep = s.run("verify", ["proxmox_vm"], deep=True)
        self.assertEqual(rep.modules[0].errors, [])
        meta = json.loads((self.vm_dir() / self.valid_groups()[-1]).read_text())
        with open(self.vm_dir() / meta["archive"], "r+b") as f:
            f.write(b"CORRUPT!")
        self.assertEqual(s.run("verify", ["proxmox_vm"]).modules[0].errors, [])   # metadata/size only
        rep = s.run("verify", ["proxmox_vm"], deep=True)
        self.assertIn("sha256 mismatch", " ".join(rep.modules[0].errors))

    def test_restore_test_new_vmid(self):
        s = self.server()
        s.run("backup", ["proxmox_vm"])
        rep = s.restore_test_vm(101, 101, "local-lvm", True, False)
        self.assertIn("in use", " ".join(rep.modules[0].errors))
        rep = s.restore_test_vm(101, 9101, "local-lvm", False, False)
        self.assertIn("not confirmed", " ".join(rep.modules[0].errors))
        said = []
        s.reporter = lambda lvl, msg: said.append((lvl, msg))
        rep = s.restore_test_vm(101, 9101, "local-lvm", True, True)
        self.assertEqual(rep.modules[0].errors, [], rep.modules[0])
        self.assertIn(("info", "  qmrestore 9101 35% (90.0 GiB read, 120 s)"), said)
        sets = (self.state / "qm-set-9101").read_text()
        self.assertIn("--onboot 0", sets)
        self.assertIn("link_down=1", sets)
        self.assertIn("--delete hostpci0,hugepages,affinity,numa0", sets)    # passthrough stays with the original
        self.assertIn("removed from the test VM", " ".join(rep.modules[0].notes))
        self.assertIn("--unique 1", (self.state / "qmrestore-args").read_text())

    def test_planned_exclusions(self):
        self.cfg.modules.proxmox_vm.excluded_disks_ok = {"101": ["scsi1"]}
        rep = self.server().run("backup", ["proxmox_vm"])
        warnings, notes = " ".join(rep.modules[0].warnings), " ".join(rep.modules[0].notes)
        self.assertNotIn("VM 101 (web): disk(s) scsi1 have backup=0", warnings)
        self.assertIn("VM 101 (web): disk(s) scsi1 excluded as planned", notes)
        self.assertIn("VM 102 (db): disk(s) scsi1 have backup=0", warnings)          # not listed -> warning
        self.cfg.modules.proxmox_vm.excluded_disks_ok = {"101": ["scsi1", "scsi0"]}
        rep = self.server().run("backup", ["proxmox_vm"], vmids=[101])
        self.assertIn("lists scsi0, but they are now backed up", " ".join(rep.modules[0].warnings))
        c = sb.Config.from_dict({"modules": {"proxmox_vm": {"excluded_disks_ok": {101: ["scsi1"]}}}})
        self.assertEqual(c.modules.proxmox_vm.excluded_disks_ok, {"101": ["scsi1"]})


class TestProxmoxHost(Base):
    def setUp(self):
        super().setUp()
        etc = self.tmp / "etc-sample"
        (etc / "network").mkdir(parents=True)
        (etc / "network" / "interfaces").write_text("auto vmbr0\n")
        (etc / "hosts").write_text("127.0.0.1 localhost\n")
        (etc / "modules-load").write_text("vfio\n")
        (etc / "link").symlink_to("hosts")
        secret = etc / "unreadable"
        secret.write_text("x")
        secret.chmod(0)
        db = sqlite3.connect(str(self.tmp / "config.db"))
        db.execute("create table tree (inode integer, name text)")
        db.execute("insert into tree values (1, 'storage.cfg')")
        db.commit()
        db.close()
        self.cfg.modules.luks.enabled = False
        self.cfg.modules.proxmox_host = sb.ProxmoxHostModuleConfig(
            enabled=True, paths=[str(etc / "network"), str(etc / "hosts"), str(etc / "modules*"),
                                 str(etc / "link"), str(etc / "unreadable"), str(etc / "absent")])

    def test_backup_publish_verify(self):
        s = self.server()
        rep = s.run("backup", ["proxmox_host"])
        m = rep.modules[0]
        self.assertEqual(m.errors, [])
        self.assertIn("not GPG-encrypted", " ".join(m.warnings))
        if os.geteuid() != 0 and not os.access(self.tmp / "etc-sample" / "unreadable", os.R_OK):
            self.assertIn("could not be read", " ".join(m.warnings))
        kind = self.root() / "proxmox" / "host"
        stamp = sb.latest_timestamped(kind)
        b = kind / stamp
        self.assertEqual(sb.Manifest.verify_sha256sums(b), [])
        with tarfile.open(b / "files" / "etc.tar") as tf:
            names = tf.getnames()
        self.assertTrue(any(n.endswith("network/interfaces") for n in names))
        self.assertTrue(any(n.endswith("modules-load") for n in names))
        self.assertTrue((b / "pve-cluster" / "config.db").is_file())
        self.assertTrue((b / "commands" / "pveversion-v.txt").is_file())
        self.assertIn("absent", json.loads((b / "inventory.json").read_text())["paths"]["missing"][0])
        self.assertTrue((Path(self.cfg.local_dir) / sb.host_id(self.cfg) / "proxmox" / "host" / stamp).is_dir())
        rep = s.run("verify", ["proxmox_host"])
        self.assertEqual(rep.modules[0].errors, [], rep.modules[0])
        (b / "hosts-tamper").write_text("x")
        (b / "inventory.json").write_text("{}")
        rep = s.run("verify", ["proxmox_host"])
        self.assertIn("checksum mismatch", " ".join(rep.modules[0].errors))

    def test_deleted_remote_backup_is_tamper(self):
        self.cfg.modules.proxmox_host.retention = 1
        s = self.server()
        s.run("backup", ["proxmox_host"])
        kind = self.root() / "proxmox" / "host"
        stamp = sb.latest_timestamped(kind)
        import shutil
        shutil.rmtree(kind / stamp)
        with mock.patch("server_backup.dt") as fake_dt:          # distinct timestamp for the next run
            import datetime as real
            fake_dt.datetime.now.return_value = real.datetime(2099, 1, 1)
            rep = s.run("backup", ["proxmox_host"])
        self.assertIn("TAMPER CHECK", " ".join(rep.modules[0].errors))
        self.assertEqual(rep.exit_code, sb.EXIT_ERROR)
        local = Path(self.cfg.local_dir) / sb.host_id(self.cfg) / "proxmox" / "host"
        self.assertEqual(len([p for p in local.iterdir() if p.is_dir()]), 2)   # retention=1 but paused

    def test_missing_ledger_is_reported(self):
        s = self.server()
        s.run("backup", ["proxmox_host"])
        Path(self.cfg.state_dir, "ledger.json").unlink()
        rep = s.run("backup", ["proxmox_host"])
        self.assertIn("ledger", " ".join(rep.warnings))


class TestFiles(Base):
    def setUp(self):
        super().setUp()
        self.data = self.tmp / "data"
        (self.data / "sub").mkdir(parents=True)
        (self.data / "a.txt").write_text("alpha\n")
        (self.data / "sub" / "b.txt").write_text("beta\n")
        pw = self.tmp / "restic.pass"
        pw.write_text("secret-password")
        pw.chmod(0o400)
        self.cfg.modules.luks.enabled = False
        self.cfg.modules.files = sb.FilesModuleConfig(enabled=True, paths=[str(self.data)],
                                                      password_file=str(pw), cache_dir=str(self.tmp / "cache"),
                                                      keep_daily=1, keep_weekly=0, keep_monthly=0)

    def test_requires_init(self):
        rep = self.server().run("backup", ["files"])
        self.assertIn("not initialised", " ".join(rep.modules[0].errors))

    def test_init_backup_verify_restore(self):
        said = []
        s = sb.ServerBackup(self.cfg, sb.Prompter(), lambda lvl, msg: said.append(msg), self.tmp / "etc" / "c.json")
        self.assertEqual(s.files_init().modules[0].errors, [])
        self.assertTrue((self.root() / "restic" / "config").is_file())
        rep = s.run("backup", ["files"], profile="daily")
        m = rep.modules[0]
        self.assertEqual(m.errors, [], m)
        self.assertTrue(m.artifacts[0]["id"])
        self.assertIn("retention applied: --keep-daily 1", " ".join(m.notes))
        args = (self.state / "restic-backup-args").read_text()
        self.assertIn("--tag server-backup", args)
        self.assertIn("--tag profile-daily", args)
        self.assertNotIn("--exclude", args)                     # nothing excluded unless configured
        self.assertTrue((self.root() / "RESTORE-files.txt").is_file())
        self.assertIn("  restic backup 50% (1.0 KiB of 2.0 KiB, 1 files)", said)
        self.assertEqual(s.run("verify", ["files"]).modules[0].errors, [])
        rr = s.restore_test_files()
        self.assertEqual(rr.modules[0].errors, [], rr.modules[0])
        self.assertIn("identical", " ".join(rr.modules[0].notes))
        self.assertEqual(len(s.files_snapshots()), 1)

    def test_missing_path_fails_unless_allowed(self):
        self.cfg.modules.files.paths.append(str(self.tmp / "gone"))
        s = self.server()
        s.files_init()
        rep = s.run("backup", ["files"])
        self.assertIn("configured path missing", " ".join(rep.modules[0].errors))
        self.cfg.modules.files.allow_missing_paths = True
        rep = s.run("backup", ["files"])
        self.assertEqual(rep.modules[0].status, "warning")

    def test_snapshot_tamper_and_replaced_repository(self):
        s = self.server()
        s.files_init()
        s.run("backup", ["files"])
        s.run("backup", ["files"])
        snp = self.root() / "restic" / "snapshots.json"
        snaps = json.loads(snp.read_text())
        snp.write_text(json.dumps(snaps[1:]))                       # attacker forgets a snapshot
        rep = s.run("backup", ["files"])
        self.assertIn("TAMPER CHECK", " ".join(rep.modules[0].errors))
        self.assertIn("retention paused", " ".join(rep.modules[0].notes))
        s.ledger_accept(["files"])
        self.assertEqual(s.run("backup", ["files"]).modules[0].errors, [])
        import shutil
        shutil.rmtree(self.root() / "restic")                        # repository deleted
        rep = s.run("backup", ["files"])
        self.assertIn("repository is gone", " ".join(rep.modules[0].errors))

    def test_size_cap_warn_and_exclude(self):
        big = self.data / "sub" / "big.iso"
        with open(big, "wb") as f:
            f.truncate(3 * 1024 * 1024)                              # sparse 3 MiB
        skipped = self.data / "cache" / "huge.bin"
        skipped.parent.mkdir()
        with open(skipped, "wb") as f:
            f.truncate(5 * 1024 * 1024)
        self.cfg.modules.files.excludes = [str(self.data / "cache")]
        self.cfg.modules.files.max_file_size = "1M"
        s = self.server()
        s.files_init()
        rep = s.run("backup", ["files"])
        m = rep.modules[0]
        self.assertEqual(m.status, "warning")
        self.assertIn("backed up anyway", " ".join(m.warnings))
        self.assertEqual([f["path"] for f in m.details["large_files"]["files"]], [str(big)])   # excluded dir not listed
        self.assertNotIn("--exclude-larger-than", (self.state / "restic-backup-args").read_text())
        self.cfg.modules.files.large_file_action = "exclude"
        m = s.run("backup", ["files"]).modules[0]
        self.assertIn("EXCLUDED", " ".join(m.warnings))
        self.assertIn("--exclude-larger-than 1M", (self.state / "restic-backup-args").read_text())
        self.cfg.modules.files.max_file_size = "100MB"
        self.assertIn("max_file_size", " ".join(msg for _, _, msg in self.cfg.validate()))

    def test_exclude_matcher(self):
        ex = sb.DirectoryBackupService.excluded
        self.assertTrue(ex("/home/u/.cache/x", ["/home/u/.cache"]))
        self.assertFalse(ex("/home/u/.cachex/x", ["/home/u/.cache"]))
        self.assertTrue(ex("/a/b/node_modules/c.js", ["**/node_modules"]))
        self.assertTrue(ex("/a/b/f.tmp", ["*.tmp"]))
        self.assertTrue(ex("/a/b/build/x.o", ["build/*.o"]))
        self.assertTrue(ex("/home/u/v/m.iso", ["/home/u/**/*.iso"]))
        self.assertFalse(ex("/mnt/p/m.iso", ["/home/u/**/*.iso"]))

    def test_unreadable_files_are_a_warning(self):
        s = self.server()
        s.files_init()
        with mock.patch.dict(os.environ, {"FAKE_RESTIC_RC3": "1"}):
            rep = s.run("backup", ["files"])
        self.assertEqual(rep.modules[0].status, "warning")
        self.assertIn("could not be read", " ".join(rep.modules[0].warnings))


class TestLuksAndOrchestration(Base):
    def test_luks_module_publishes_like_luks_backup(self):
        svc = sb.LuksBackupService(self.cfg, sb.Prompter(), silent, self.tmp / "etc" / "config.json")
        rep = svc.backup()
        self.assertEqual(rep.exit_code, sb.EXIT_WARN)            # no LUKS devices on the fake host
        self.assertIn("no LUKS devices found", rep.warnings)
        kind = self.root() / "luks"
        stamp = sb.latest_timestamped(kind)
        self.assertEqual(sb.Manifest.verify_sha256sums(kind / stamp), [])
        self.assertTrue((kind / stamp / "README.txt").is_file())
        self.assertTrue([d for d in rep.destinations if d["type"] == "cifs" and d["ok"]])
        self.assertTrue((Path(self.cfg.local_dir) / sb.host_id(self.cfg) / "luks" / stamp).is_dir())

    def test_luks_failed_cifs_skips_retention(self):
        self.cfg.retention = 1
        svc = sb.LuksBackupService(self.cfg, sb.Prompter(), silent)
        svc.backup()
        FakeDestination.fs_ok = False
        with mock.patch("server_backup.dt") as fake_dt:          # distinct timestamp for the second run
            import datetime as real
            fake_dt.datetime.now.return_value = real.datetime(2099, 1, 1)
            rep = svc.backup()
        self.assertEqual(rep.exit_code, sb.EXIT_ERROR)
        local = Path(self.cfg.local_dir) / sb.host_id(self.cfg) / "luks"
        self.assertEqual(len([p for p in local.iterdir() if p.is_dir()]), 2)   # nothing pruned after failure

    def test_profiles(self):
        s = self.server()
        self.cfg.modules.luks.enabled = False
        self.cfg.modules.files.enabled = True
        mods, notes = s.resolve_modules("weekly")
        self.assertEqual(mods, ["files"])
        self.assertTrue(any("proxmox_vm" in n for n in notes))
        with self.assertRaises(sb.BackupError):
            s.resolve_modules("recovery")                         # only luks, which is disabled
        with self.assertRaises(sb.BackupError):
            s.resolve_modules("", ["proxmox_vm"])                 # explicit flag on a disabled module
        with self.assertRaises(sb.BackupError):
            s.resolve_modules("nope")

    def test_unavailable_module_is_an_error_not_a_crash(self):
        self.cfg.modules.luks.enabled = True
        rep = self.server().run("backup", ["luks"])
        self.assertEqual(rep.exit_code, sb.EXIT_ERROR)
        self.assertIn("not available on this host", rep.modules[0].errors[0])

    def test_weekly_and_status(self):
        pw = self.tmp / "restic.pass"
        pw.write_text("pw")
        data = self.tmp / "data"
        data.mkdir()
        (data / "f").write_text("f")
        self.cfg.modules.luks.enabled = False
        self.cfg.modules.files = sb.FilesModuleConfig(enabled=True, paths=[str(data)], password_file=str(pw),
                                                      cache_dir=str(self.tmp / "cache"))
        self.cfg.modules.proxmox_vm = sb.ProxmoxVmModuleConfig(enabled=True, vmids=[101])
        self.cfg.modules.proxmox_host = sb.ProxmoxHostModuleConfig(enabled=True, paths=[str(data)],
                                                                   allow_unencrypted=True)
        s = self.server()
        s.files_init()
        FakeDestination.mounts = 0
        mods, _ = s.resolve_modules("weekly")
        self.assertEqual(mods, ["proxmox_host", "files", "proxmox_vm"])
        rep = s.run("backup", mods, profile="weekly")
        self.assertEqual([m.status for m in rep.modules], ["ok", "ok", "warning"], rep.to_dict())
        self.assertEqual(FakeDestination.mounts, 1)
        st = s.status()
        json.dumps(st, default=str)
        self.assertTrue(st["destination"]["ok"])
        self.assertEqual(st["proxmox_vm"][0]["name"], "web")
        self.assertTrue(st["proxmox_vm"][0]["agent_responding"])
        self.assertIn("latest_backup", st["proxmox_vm"][0])
        self.assertTrue(st["files"]["latest_snapshot"])
        self.assertEqual(st["last_run"]["status"], "warning")
        with redirect_stdout(io.StringIO()) as out:
            sb.print_status_human(st)
            sb.print_run_human(rep)
        self.assertIn("Proxmox VMs", out.getvalue())


class TestDiskAndNotify(Base):
    def test_disk_usage_thin_pools_and_thresholds(self):
        self.cfg.disk_warn_percent, self.cfg.disk_error_percent = 70, 80
        entries = sb.disk_usage(self.cfg)
        names = {e["what"]: e for e in entries}
        self.assertIn("filesystem /", names)
        self.assertEqual(names["LVM thin pool data_vg/data data"]["level"], "warning")      # 76 %
        self.assertEqual(names["LVM thin pool pve/data data"]["level"], "ok")                    # 69 %
        self.assertEqual(names["LVM thin pool data_vg/data metadata"]["level"], "ok")       # 43 %
        self.assertNotIn("LVM thin pool pve/root data", names)                                   # not a pool
        with mock.patch.dict(os.environ, {"FAKE_THIN_DATA": "98"}):
            errs, warns = sb.disk_messages(sb.disk_usage(self.cfg))
        self.assertTrue(any("pve/data data is 98% full" in e and "stall" in e for e in errs))

    def test_run_and_status_report_disk(self):
        self.cfg.disk_warn_percent, self.cfg.disk_error_percent = 70, 99
        self.cfg.modules.proxmox_host = sb.ProxmoxHostModuleConfig(enabled=True, paths=[str(self.tmp)],
                                                                   allow_unencrypted=True)
        self.cfg.modules.luks.enabled = False
        s = self.server()
        rep = s.run("backup", ["proxmox_host"])
        self.assertTrue(any(e["what"].startswith("share //nas/backups") for e in rep.disk))
        self.assertTrue(any("data_vg/data data is 76% full" in w for w in rep.warnings))
        st = s.status()
        self.assertTrue(st["disk"])
        with redirect_stdout(io.StringIO()) as out:
            sb.print_status_human(st)
        self.assertIn("Disk usage (warn 70%)", out.getvalue())
        self.assertIn("Email reports: off", out.getvalue())

    def test_email_report_over_smtp(self):
        sent = []

        class FakeSMTP:
            def __init__(self, host, port, timeout):
                sent.append(("connect", host, port))
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass
            def starttls(self, context=None):
                sent.append(("starttls",))
            def login(self, user, pw):
                sent.append(("login", user, pw))
            def send_message(self, msg):
                sent.append(("msg", msg))

        cred = self.tmp / "smtp.cred"
        cred.write_text("username=bot\npassword=s3cret\n")
        self.cfg.notify = sb.NotifyConfig(email=["ops@example.org"], smtp_host="relay.example.org",
                                          credentials_file=str(cred))
        n = sb.Notifier(self.cfg)
        ok = sb.RunReport(host="h", action="backup", status="ok")
        warn = sb.RunReport(host="h", action="backup", profile="weekly", status="warning",
                            modules=[sb.ModuleResult("proxmox_vm", "backup", status="warning", summary="1/1 VM(s)",
                                                     warnings=["agent not responding"])])
        with mock.patch("smtplib.SMTP", FakeSMTP):
            self.assertIsNone(n.report(ok))
            self.assertEqual(sent, [])                                   # on=warning: ok runs stay quiet
            self.assertIsNone(n.report(warn))
        self.assertEqual(sent[:3], [("connect", "relay.example.org", 587), ("starttls",), ("login", "bot", "s3cret")])
        msg = sent[3][1]
        self.assertEqual(msg["Subject"], "[server-backup] h: WARNING - backup weekly")
        self.assertIn("agent not responding", msg.get_content())
        self.assertNotIn("s3cret", msg.as_string())

    def test_email_failures_and_sendmail(self):
        self.cfg.notify = sb.NotifyConfig(email=["ops@example.org"], method="sendmail", on="error")
        n = sb.Notifier(self.cfg)
        self.assertIsNone(n.failure("backup", "another server_backup run is in progress"))
        mail = (self.state / "sendmail-message").read_text()
        self.assertIn("ERROR - backup did not run", mail)
        self.assertIn("in progress", mail)
        self.cfg.notify = sb.NotifyConfig(email=["ops@example.org"], smtp_host="127.0.0.1", smtp_port=1, timeout=2)
        self.assertIn("failed", sb.Notifier(self.cfg).failure("backup", "x"))   # nothing listens on port 1
        with self.assertRaises(sb.BackupError):
            sb.Notifier(sb.Config()).test()                                 # no recipients


class TestSystemdUnits(unittest.TestCase):
    def test_timers_only_for_profiles_that_do_something(self):
        c = sb.Config()
        c.modules.luks.enabled = False
        c.modules.proxmox_vm.enabled = True
        c.profiles["monthly"] = ["proxmox_vm"]
        c.profiles["adhoc"] = ["proxmox_vm"]
        c.schedules["monthly"] = "Sun *-*-01..07 01:30"
        units, timers, notes = sb.systemd_units(c, Path("/etc/server-backup/other.json"))
        self.assertEqual(sorted(timers), ["server-backup-monthly.timer", "server-backup-verify.timer",
                                          "server-backup-weekly.timer"])
        self.assertIn("OnCalendar=Wed *-1/2-15..21 03:00", units["server-backup-verify.timer"])
        self.assertIn("verify --deep --non-interactive", units["server-backup-verify.service"])
        self.assertIn(f"{Path(sb.__file__).resolve()} -c /etc/server-backup/other.json backup --profile %i",
                      units["server-backup@.service"])
        self.assertIn("Unit=server-backup@monthly.service", units["server-backup-monthly.timer"])
        text = " ".join(notes)
        self.assertIn("'daily': no module enabled", text)
        self.assertIn("'recovery': no module enabled", text)
        self.assertIn("'adhoc': no schedules.adhoc", text)

    def test_cli_writes_units_and_flags_stale_timers(self):
        d = Path(tempfile.mkdtemp())
        cfgp = d / "c.json"
        c = sb.Config()
        c.modules.luks.enabled = False
        c.modules.proxmox_vm.enabled = True
        c.save(cfgp)
        (d / "server-backup-daily.timer").write_text("old")
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(sb.main(["systemd-units", "-c", str(cfgp), "--output-dir", str(d)]), 0)
        self.assertTrue((d / "server-backup-weekly.timer").is_file())
        self.assertIn("server-backup-daily.timer is not needed", err.getvalue())
        self.assertIn("systemctl enable --now server-backup-weekly.timer server-backup-verify.timer", err.getvalue())


class Scripted(sb.Prompter):
    """Answers prompts from a queue (secret/text/confirm/choose/paste all pop the next answer);
    a callable answer is evaluated when its prompt comes up."""
    interactive = True

    def __init__(self, *answers):
        self.answers = list(answers)

    def _next(self, *_a, **_k):
        a = self.answers.pop(0)
        return a() if callable(a) else a

    text = secret = confirm = choose = paste = _next


@unittest.skipUnless(sb.shutil.which("gpg"), "gpg not installed")
class TestBackupKey(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sbgpg-", dir="/tmp"))
        self.cfg = sb.Config(gpg_home=str(self.tmp / "gnupg"))

    def tearDown(self):
        for home in [self.tmp / "gnupg", self.tmp / "other"]:
            sb.GpgKeyring(str(home)).kill_agent()
        os.system(f"rm -rf '{self.tmp}'")

    def generate(self, *answers):
        svc = sb.LuksBackupService(self.cfg, Scripted("pass-phrase-123", "pass-phrase-123", *answers), silent)
        with redirect_stderr(io.StringIO()) as err:
            fpr = svc._gpg_generate()
        return fpr, err.getvalue()

    def test_generate_hands_over_and_deletes_private_key(self):
        fpr, shown = self.generate(True, False, True)   # show blocks: yes; test now: no; delete: yes
        exports = sorted(p.name for p in self.cfg.gpg_export_dir.iterdir())
        self.assertEqual(exports, [f"server-backup-key-{fpr[-8:]}.pub.asc"])
        self.assertIn("BEGIN PGP PRIVATE KEY BLOCK", shown)
        self.assertIn("BEGIN PGP PUBLIC KEY BLOCK", shown)
        self.assertIn(sb.GPG_SCOPE, shown)
        key = sb.GpgKeyring(self.cfg.gpg_home).get(fpr)
        self.assertTrue(key.uid.startswith("server-backup key"))
        self.assertFalse(key.has_secret)

    def test_declining_keeps_export_pending(self):
        fpr, _ = self.generate(True, False, False)      # shown, not tested, not deleted
        svc = sb.LuksBackupService(self.cfg)
        self.assertEqual(len(svc.pending_key_exports()), 1)

    def test_import_by_pasting_the_vaultwarden_note(self):
        fpr, shown = self.generate(True, False, False)
        note = "passphrase: pass-phrase-123\n" + shown   # whole note: passphrase + both blocks
        other = sb.Config(gpg_home=str(self.tmp / "other"))
        svc = sb.LuksBackupService(other, Scripted("p", note), silent)
        self.assertEqual(svc._gpg_import(), fpr)
        self.assertFalse(sb.GpgKeyring(other.gpg_home).get(fpr).has_secret)
        self.assertTrue(sb.GpgKeyring(other.gpg_home).test_encrypt(fpr)[0])

    def test_public_half_from_private_block_only(self):
        fpr, _ = self.generate(True, False, False)
        sec = next(self.cfg.gpg_export_dir.glob("*.SECRET.asc")).read_bytes()
        data, how = sb.public_key_material(sec)
        self.assertIn(b"PUBLIC KEY BLOCK", data)
        self.assertNotIn(b"PRIVATE KEY BLOCK", data)
        self.assertIn("private key not kept", how)
        other = sb.Config(gpg_home=str(self.tmp / "other"))
        svc = sb.LuksBackupService(other, Scripted("f", str(next(self.cfg.gpg_export_dir.glob("*.SECRET.asc")))), silent)
        self.assertEqual(svc._gpg_import(), fpr)
        with self.assertRaises(sb.BackupError):
            sb.public_key_material(b"not a key")

    def secret_file(self) -> str:
        return str(next(self.cfg.gpg_export_dir.glob("*.SECRET.asc")))

    def test_setup_tests_the_saved_copy_before_deleting(self):
        fpr, _ = self.generate(False, True, "f", self.secret_file, "pass-phrase-123", True)
        self.assertEqual(list(self.cfg.gpg_export_dir.glob("*.SECRET.asc")), [])
        # wrong passphrase: the test fails, user stops retrying; delete defaults to no -> kept
        self.cfg = sb.Config(gpg_home=str(self.tmp / "gnupg2"))
        self.generate(False, True, "f", self.secret_file, "wrong-passphrase", False, False)
        self.assertEqual(len(list(self.cfg.gpg_export_dir.glob("*.SECRET.asc"))), 1)
        sb.GpgKeyring(str(self.tmp / "gnupg2")).kill_agent()

    def encrypted_archive(self, fpr: str, tamper: bool = False) -> Path:
        """A host-config style <ts>.tar.gpg in local_dir, as ArtifactPublisher makes it."""
        self.cfg.gpg_recipient = fpr
        self.cfg.local_dir = str(self.tmp / "local")
        kind = Path(self.cfg.local_dir) / sb.host_id(self.cfg) / "proxmox" / "host"
        staging = kind / "20260101-000000"
        (staging / "files").mkdir(parents=True)
        (staging / "files" / "etc.tar").write_bytes(os.urandom(5000))
        (staging / "README.txt").write_text("readme")
        sb.Manifest.write_sha256sums(staging)
        if tamper:
            (staging / "README.txt").write_text("changed after SHA256SUMS")
        out = sb.GpgEncryption(self.cfg).encrypt_dir(staging)
        sb.shutil.rmtree(staging)
        return out

    def gpg_test(self, *answers, **kw):
        with mock.patch("os.geteuid", return_value=0):
            rep = sb.ServerBackup(self.cfg, Scripted(*answers), silent).gpg_test(**kw)
        return rep.modules[0]

    def test_gpg_test_decrypts_newest_archive(self):
        fpr, _ = self.generate(False, False, False)
        arch = self.encrypted_archive(fpr)
        m = self.gpg_test("pass-phrase-123", key_file=self.secret_file())
        self.assertEqual(m.errors, [], m)
        notes = " ".join(m.notes)
        self.assertIn("passphrase OK", notes)
        self.assertIn("is the backup key this machine encrypts to", notes)
        self.assertIn(f"{arch.name}: decrypted and readable, 3 files match SHA256SUMS", notes)
        self.assertIn("decrypted and readable", " ".join(
            self.gpg_test("p", lambda: Path(self.secret_file()).read_text(), "pass-phrase-123").notes))   # pasted
        self.assertIn("passphrase rejected", " ".join(self.gpg_test("wrong", key_file=self.secret_file()).errors))

    def test_gpg_test_detects_bad_content_and_wrong_key(self):
        fpr, _ = self.generate(False, False, False)
        self.encrypted_archive(fpr, tamper=True)
        m = self.gpg_test("pass-phrase-123", key_file=self.secret_file())
        self.assertIn("do not match SHA256SUMS: README.txt", " ".join(m.errors))
        pub = next(self.cfg.gpg_export_dir.glob("*.pub.asc"))
        self.assertIn("not a private key", " ".join(self.gpg_test("x", key_file=str(pub)).errors))
        self.cfg.gpg_recipient = "0" * 40
        self.assertIn("is NOT the backup key", " ".join(self.gpg_test("pass-phrase-123",
                                                                      key_file=self.secret_file()).errors))

    def test_legacy_export_names_still_recognised(self):
        d = self.tmp / "exp"
        d.mkdir()
        (d / "luks-backup-key-89ABCDEF.SECRET.asc").write_text("x")
        (d / "server-backup-key-89ABCDEF.pub.asc").write_text("x")
        self.assertEqual(len(sb.key_export_files(d, "0123456789ABCDEF0123456789ABCDEF89ABCDEF")), 2)


class TestCli(unittest.TestCase):
    def test_example_config_and_units(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(sb.main(["example-config"]), 0)
        c = sb.Config.from_dict(json.loads(out.getvalue()))
        self.assertTrue(c.modules.files.enabled)
        d = tempfile.mkdtemp()
        self.assertEqual(sb.main(["systemd-units", "--output-dir", d]), 0)
        self.assertIn("--profile %i", (Path(d) / "server-backup@.service").read_text())

    def test_help_is_informative(self):
        with redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit):
            sb.main(["--help"])
        for s in ("quick start", "commands", "examples", "exit codes", "ledger --accept"):
            self.assertIn(s, out.getvalue())

    def test_requires_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        self.assertEqual(sb.main(["status", "-c", "/nonexistent.json"]), sb.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()
