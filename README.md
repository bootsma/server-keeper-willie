# server_backup.py

Backups for Proxmox hosts and Linux VMs/servers. It is one Python file (3.8+, standard library
only) and runs as root. It replaces `luks_backup.py`, which stays in this repo unchanged as the
regression baseline.

| module         | backs up                                     | stored on the share at          |
|----------------|----------------------------------------------|---------------------------------|
| `luks`         | LUKS headers, keyfiles, saved passphrases    | `<host>/luks/`                  |
| `files`        | chosen directories, with history (Restic)    | `<host>/restic/`                |
| `proxmox_vm`   | chosen VMs: OS disk, EFI, TPM, config (vzdump) | `<host>/proxmox/vm/<vmid>/`   |
| `proxmox_host` | Proxmox host configuration and inventory     | `<host>/proxmox/host/`          |

`<host>` is `//server/share/<cifs.subdir>/<hostname>`. The tool detects what *can* run on a
machine; the config decides what *does* run. `server_backup.py --help` lists every command,
option and example.

---

## Quick guide

```bash
# 1. install (the file is all you need)
sudo install -m 0755 server_backup.py /usr/local/sbin/server_backup.py
sudo apt install cifs-utils gnupg restic        # restic only where the files module is used

# 2. configure: share, encryption, modules, paths/VMs
sudo server_backup.py configure

# 3. email reports: set notify.email and notify.smtp_host in the config, then
sudo server_backup.py notify-test

# 4. check everything (fix all X and ! lines)
sudo server_backup.py status

# 5. first backups and restore tests: see "End-to-end test" below

# 6. schedule: writes only the timers this machine needs and prints the enable command
sudo server_backup.py systemd-units --output-dir /etc/systemd/system
```

What to enable:
- **Proxmox host:** `proxmox_vm` (with an explicit `vmids` list) and `proxmox_host`; `luks` if
  the host uses LUKS. **Before the first VM backup**, decide which disks each VM backup includes:
  vzdump backs up *every* disk of a VM unless the disk is marked `backup=0` in the VM's Proxmox
  config. That's done in Proxmox (`qm set` or the GUI), not in this tool's config. For OS-only
  backups, see [OS-only VM backups](#os-only-vm-backups).
- **VM or server:** `files`; `luks` if the machine uses LUKS. See [Setting up a VM](#setting-up-a-vm).
- **Encryption:** `gpg-setup` on the first machine generates the backup key. On every other
  machine, `gpg-setup` imports the same key from Vaultwarden. See [Backup encryption key](#backup-encryption-key).

Run long jobs inside `tmux`. Closing an SSH session sends a hangup signal, and the tool stops
cleanly when it gets one. Long steps (vzdump, qmrestore, restic, checksums) print a progress line
about every 30 s; `-v` shows every line of the underlying tool.

---

## End-to-end test

Do this once per machine before relying on the timers. Each step says what a pass looks like.

### On the Proxmox host

| # | command | pass looks like |
|---|---|---|
| 0 | **OS-only backups:** mark each data disk `backup=0` in Proxmox and list it in `excluded_disks_ok` ([how](#os-only-vm-backups)). Check with `qm config <vmid> \| grep -E '^(scsi\|virtio\|sata)[0-9]'` | every data-disk line contains `backup=0` (Proxmox sorts the options, so it's often mid-line); the OS-disk line doesn't |
| 1 | `server_backup.py status` | `server_backup 2.3.0` on the first line, destination `OK`, both VMs listed with only their OS disk size, notes `… excluded as planned`, no `X` lines |
| 2 | `server_backup.py notify-test` | the test email arrives |
| 3 | `server_backup.py backup --proxmox-host` | `proxmox_host OK`; a `<ts>.tar.gpg` appears in `proxmox/host/` |
| 4 | `server_backup.py gpg-test` (paste the key from Vaultwarden, or `--key-file`) | `passphrase OK` and `… files match SHA256SUMS` |
| 5 | `server_backup.py backup --proxmox-vm --vmid 102` | `1/1 VM(s) backed up`. Progress lines every 30 s: `VM 102: vzdump 45% (…)`, then `computing sha256 …` while the archive is read back |
| 6 | `server_backup.py verify --proxmox-vm --vmid 102 --deep` | no errors (reads the archive back) |
| 7 | `server_backup.py restore-test --proxmox-vm --vmid 102 --test-vmid 9102 --storage vm_data2` | `qmrestore 9102 NN% (…)` progress, then `VM 102 restored … as test VM 9102`, with passthrough, hugepages and pinning listed as removed |
| 8 | `qm set 9102 --memory 8192 --cores 2` then `qm start 9102` | the console (Proxmox GUI) boots to a login. GPU and network messages are expected (no GPU, links down). With OS-only backups, a stop in **emergency mode** after `Job dev-mapper-…` timeouts also passes: the root filesystem loaded, and only the excluded data disks from `/etc/fstab` are missing (see [OS-only VM backups](#os-only-vm-backups)) |
| 9 | `qm stop 9102 && qm destroy 9102 --purge` | the test VM is gone |
| 10 | repeat 5–6 for the other VMs (e.g. `--vmid 101`) | as above |
| 11 | `server_backup.py systemd-units --output-dir /etc/systemd/system`, then the printed `systemctl enable --now …` | `systemctl list-timers 'server-backup*'` shows the next runs |
| 12 | after the first scheduled run: `server_backup.py status` | the *Last run* line is `OK`/`WARNING`, and a report email arrived if the result was at least `notify.on` |

The original VM keeps running during steps 5–9. The test VM is a separate copy with its network
links down. Never bring them up: inside, it's a clone with the same hostname and IP address.

### On a VM using the files module

| # | command | pass looks like |
|---|---|---|
| 1 | `server_backup.py status` | destination `OK`, paths listed, none `MISSING` |
| 2 | `server_backup.py files-init` | `Restic repository ready` (save the generated password in Vaultwarden) |
| 3 | `server_backup.py backup --files` | `files OK`, `snapshot xxxxxxxx: … added` |
| 4 | `server_backup.py restore-test --files` (or `--path /some/file`) | `restored … identical to the live file` |
| 5 | `server_backup.py verify --files --deep` | `restic check OK (read data subset 5%)` |
| 6 | `server_backup.py notify-test`, then `systemd-units` as on the host | email arrives; timers listed |

---

## Setting up a VM

1. Copy and install the file as in the Quick guide, plus `apt install cifs-utils restic`.
2. Run `server_backup.py configure`: point it at the same share (each machine gets its own
   `<hostname>` folder), and enable only `files`.
3. In `/etc/server-backup/config.json`, set `modules.files.paths` to the data folders, e.g. the
   contents of disks excluded from vzdump on the host. Add `excludes` and `max_file_size` as
   needed. See [Excludes and size cap](#excludes-and-size-cap-files-module).
4. Set up email. VMs need no local mail server; the tool talks to the SMTP relay directly:
   ```json
   "notify": {"email": ["you@example.org"], "smtp_host": "smtp-relay.example.org", "smtp_port": 587,
              "security": "starttls", "credentials_file": "", "on": "warning"}
   ```
   If the relay needs a login, put `username=` and `password=` lines into a 0600 file and set
   `credentials_file` to it.
5. `files-init`, then the VM part of the end-to-end test.

---

## Details

### Commands

| command | does |
|---|---|
| `status [--quick]` | Reports what's detected and enabled, share health, VMs, latest backups, disk usage, email settings, tamper findings and warnings. Never backs anything up. |
| `backup` | Runs `--profile NAME`, the modules you name (`--luks --files --proxmox --proxmox-vm --proxmox-host`, `--vmid N`), or every enabled module. Sends the email report unless `--no-notify` is given. |
| `verify [--deep]` | Checks stored backups and the tamper ledger. `--deep` reads everything back: sha256, a `restic check` data sample, `zstd -t`. |
| `restore-test` | `--files [--path P]`, or `--proxmox-vm --vmid V --test-vmid N --storage S [--yes]` |
| `gpg-test [--key-file F] [--archive A]` | Restore drill for the backup key: decrypts and checks the newest encrypted archive with the key and passphrase from Vaultwarden |
| `notify-test` | Sends a test email using the `notify` settings |
| `ledger [--accept]` | Shows the tamper ledger. `--accept` re-baselines it after you deleted backups on purpose |
| `systemd-units [--output-dir D]` | Writes the service, the timers this machine needs, and the scheduled deep verify; prints the enable command |
| `files-init`, `files-snapshots` | Creates the Restic repository and password file / lists snapshots |
| `discover`, `configure`, `cifs-setup`, `cifs-test`, `gpg-setup`, `gpg-status` | Setup and checks |
| `run` | Legacy `luks_backup.py` LUKS backup, with the same output and JSON |

Common options: `-c FILE`, `-n` (never prompt), `--json`, `-v`, `--wait-lock 4h`.
Exit codes: `0` ok · `1` error (includes tamper findings) · `2` warnings only · `130` interrupted.

### Configuration

The config is `/etc/server-backup/config.json` (mode 0600). `example-config` prints a starting
point (see [server_backup.example.json](server_backup.example.json)). Every run and `status`
reports **unknown or misspelled keys** (with a "did you mean" suggestion) and keys that appear
twice. Secrets live in separate files: `cifs.credentials_file`, `files.password_file`,
`notify.credentials_file` and the GPG keyring.

| key | default | meaning |
|---|---|---|
| `cifs.share`, `cifs.subdir` | — , `serverBackup` | `//server/share`; top directory on it |
| `cifs.mount_options` | `vers=3` | add `,seal` to encrypt SMB traffic |
| `cifs.min_free_gb`, `cifs.marker_file` | `5`, `""` | preflight limits; a file that must exist on the share |
| `gpg_recipient` | `""` | the backup encryption key (`gpg-setup`) |
| `state_dir` | `/var/lib/server-backup` | holds the tamper ledger |
| `notify.*` | off | email reports, see [Email reports](#email-reports) |
| `disk_warn_percent`, `disk_error_percent`, `disk_check_paths` | `90`, `97`, `[]` | see [Disk usage](#disk-usage) |
| `personality` | `true` | one sign-off line after a clean run in a terminal; never in errors, logs, JSON or email |
| `profiles`, `schedules` | daily/weekly/recovery | see [Profiles, schedules and retention](#profiles-schedules-and-retention) |
| `files.paths` | `[]` | absolute paths; nothing is backed up unless listed |
| `files.repository` | `""` | `""` = on the share; or any restic repository URL |
| `files.keep_daily/weekly/monthly` | 7/4/6 | snapshot retention |
| `files.allow_missing_paths` | `false` | if false, a missing path fails the run instead of being skipped |
| `proxmox_vm.vmids` | `[]` | explicit list; VMs are never added automatically |
| `proxmox_vm.excluded_disks_ok` | `{}` | planned `backup=0` disks per VM, e.g. `{"101": ["scsi1"]}` |
| `proxmox_vm.mode`, `compress` | `snapshot`, `zstd` | vzdump options (`extra_args` for others, e.g. `--fleecing`) |
| `proxmox_vm.retention` + `keep_daily/weekly/monthly` | `3` + 0/0/0 | newest N, plus optional newest per day/week/month |
| `proxmox_vm.required_free_ratio` | `1.0` | free space required before a VM backup = allocated disk size × ratio |
| `proxmox_vm.dumpdir` | `""` | alternative to CIFS; must be a separate filesystem |
| `proxmox_host.paths`, `extra_paths` | the list in `docs/brief.md` | what goes into the host-config archive |
| `proxmox_host.retention` + `keep_*` | `8` + 0/0/0 | as for VMs |
| `retention` (top level) | `8` | LUKS backups to keep |
| `*.stale_after_days` | 35/2/8/8 | warn when the newest backup is older than this |

### Profiles, schedules and retention

A profile is a name for a list of modules. The modules do the same work whichever profile runs
them. `schedules` says when each profile runs (systemd `OnCalendar` syntax). The special entry
`verify` schedules `verify --deep`.

```json
"profiles":  {"daily": ["files"], "weekly": ["files", "proxmox_vm", "proxmox_host"], "recovery": ["luks"]},
"schedules": {"daily": "Mon..Sat *-*-* 01:30", "weekly": "Sun *-*-* 01:30",
              "recovery": "*-*-01 05:00", "verify": "Wed *-1/2-15..21 03:00"}
```

- A profile runs only those of its modules that are enabled on the machine. `systemd-units`
  writes a timer only for profiles that have an enabled module and a schedule, so on a Proxmox
  host without `files` and `luks`, only `weekly` and `verify` get timers.
- **Custom schedule (e.g. monthly):** add `"monthly": ["proxmox_vm", "proxmox_host"]` to
  `profiles` and `"monthly": "Sun *-*-01..07 01:30"` (first Sunday of the month) to `schedules`.
  Rerun `systemd-units`; it lists timers that are no longer needed, with the command to remove
  them.
- **The deep verify** runs on the third Wednesday of every second month at 03:00 and reads every
  latest backup back. Set `"verify": ""` to turn it off.
- Check an expression with `systemd-analyze calendar "<expr>"`. Avoid overlapping runs: a timer
  waits at most 4 h (verify: 6 h) for a running backup.

Retention:

| module | keeps (default) | history at default schedule |
|---|---|---|
| files | by **date**: newest snapshot per day/week/month (7/4/6) | about 6 months |
| proxmox_vm | newest N **valid** backups (3) | ≈ 3 weeks (weekly) |
| proxmox_host | newest N (8) | ≈ 8 weeks |
| luks | newest N (8) | ≈ 8 months (monthly) |

For VMs and host config, `keep_daily`, `keep_weekly` and `keep_monthly` add date-based restore
points on top of `retention`. For example, `"retention": 1, "keep_weekly": 4, "keep_monthly": 3`
gives the newest backup, plus one per week for 4 weeks, plus one per month for 3 months. Each VM
backup is a full archive, so space ≈ archive size × backups kept. After changing a schedule,
recheck `retention` and `stale_after_days`.

### Email reports

`backup` and `verify` email a report when the result is at least `notify.on`: `error`,
`warning` (the default) or `always`. A run that can't start at all, for example because the lock
is busy or the config is unreadable, also mails an error.

```json
"notify": {"email": ["you@example.org"], "on": "warning", "method": "smtp",
           "smtp_host": "smtp-relay.example.org", "smtp_port": 587, "security": "starttls",
           "credentials_file": "", "sender": ""}
```

- `method: smtp` talks to the relay directly, so no mail server is needed on the machine.
- `security` is `starttls`, `ssl` (port 465) or `none`.
- `credentials_file` holds `username=` and `password=` lines (0600). Leave it empty for relays
  without login.
- `method: sendmail` uses a local mail server instead, e.g. a Proxmox host whose postfix already
  relays.
- Test with `notify-test`. Skip the report for a manual run with `--no-notify`.

On a Proxmox host, vzdump also sends its own notification per VM through Proxmox's notification
system (`mail-to-root`). Configure that under Datacenter → Notifications, or ignore it; this
report covers every module.

### Disk usage

`status` and every run check how full everything the backups depend on is:
- the share
- `/`, `local_dir` and `state_dir`
- the files module's source filesystems
- any `disk_check_paths`
- **LVM thin pools, data and metadata**
- ZFS pools

At `disk_warn_percent` (90) the result is a warning; at `disk_error_percent` (97) it's an error,
which also triggers the email. A thin pool that fills up stalls every VM on it with I/O errors.
Full metadata can make the pool read-only or damage it; grow it with
`lvextend --poolmetadatasize +1G <vg>/<pool>`.

### Excludes and size cap (files module)

```json
"excludes": ["/home/user/.cache", "/home/user/**/*.iso", "**/node_modules", "*.tmp"],
"exclude_files": ["/etc/server-backup/excludes.txt"],
"exclude_caches": true,
"max_file_size": "100M",
"large_file_action": "warn"
```

- Excludes apply to **all** paths. A pattern starting with `/` only affects that location; other
  patterns match anywhere. Nothing is excluded unless it's listed here.
- `max_file_size` (`500K`, `100M`, `2G`) lists every file over the limit in each run's report.
  With `warn` those files are still backed up; with `exclude` they're skipped. Either way the run
  ends as *warning*. The list comes from a metadata-only scan whose pattern matching approximates
  restic's.

### OS-only VM backups

To back up just a VM's operating system, exclude its data disks. Each archive then holds the VM
config, EFI disk, TPM state and OS disk, all captured together.

1. `qm config <vmid>`: the first disk in `boot: order=` is the OS disk. `efidisk0` and `tpmstate0`
   are always included. Other `scsiN`/`virtioN`/`sataN` disks are data disks.
2. Exclude each data disk: VM → Hardware → disk → Edit → Advanced → untick **Backup**. Or repeat
   the disk's exact definition with `,backup=0`:
   ```bash
   qm set 101 --scsi1 vm_data:vm-101-disk-2,iothread=1,size=1T,backup=0
   ```
3. Record the plan, so runs report the exclusions as a note instead of a warning:
   `"excluded_disks_ok": {"101": ["scsi1", "scsi2"], "102": ["scsi1"]}`.

Excluded disks aren't backed up by vzdump at all. Back up their contents with the files module
inside the VM, or accept that they aren't backed up. Tip: add `discard=on` to the OS disk and
enable `fstrim.timer` in the guest, so blocks of deleted files stop being backed up.

**A restored VM without its data disks stops in emergency mode** if the guest's `/etc/fstab`
mounts them: systemd waits about 90 s for each missing device, then gives up. In a restore test
that still counts as a pass. To see the full boot, log in at the emergency prompt and comment out
the data-disk lines (`mount -o remount,rw /`, edit `/etc/fstab`, `systemctl default`). For real
recoveries, consider `nofail,x-systemd.device-timeout=10s` on those fstab lines, so the VM boots
with network even when a data disk is gone. Guard the empty mount point (`chattr +i` on it while
nothing is mounted, or `RequiresMountsFor=` in the services that use it), so nothing writes to
the root disk by mistake.

**While a VM is backed up** it keeps running. The archive is a point-in-time copy from the start
of the backup. With `qemu-guest-agent` running in the guest, filesystems are frozen for a moment
first, which gives a clean filesystem state. Guest writes are slower during the backup (the
`--fleecing` vzdump option avoids that). The VM is locked against Proxmox operations (snapshot,
migrate, hardware changes) until the backup ends.

### Backup encryption key

One GPG key encrypts the **LUKS and Proxmox host-config archives** (`*.tar.gpg`) on every machine
that uses it. **VM images are not GPG-encrypted**; use `seal` in `cifs.mount_options` to encrypt
them in transit. **Restic** encrypts with its own password. Machines hold only the public key; the
private key and its passphrase live in Vaultwarden and are needed only to restore.

- **First machine:** `gpg-setup`, then **g**. Store the key and passphrase in one Vaultwarden item:
  either attach the `.SECRET.asc`/`.pub.asc` files (self-hosted Vaultwarden allows attachments
  without a paid plan), or paste the key blocks into a note. The tool then tests the copy you
  saved, and only then offers to delete the private-key file from the machine.
- **Other machines:** `gpg-setup`, then **i**; paste the Vaultwarden note or give a file. If you
  supply only the private block, its public half is extracted and the private key isn't kept.
- **Check:** `gpg-status`. **Restore drill:** `gpg-test` decrypts the newest archive in a
  temporary keyring in RAM and checks every file against its `SHA256SUMS`; nothing decrypted is
  written to disk. Run it on another machine with `--archive <file>` to prove you can restore
  without this host.

Keys made before 2.1.0 are labelled "LUKS backup key" (files `luks-backup-key-*`). They work the
same way.

#### Testing the key from Vaultwarden

Do this after saving the key, after the first host-config backup, and every few months.

**With the tool** (as root on a machine with the config, e.g. the Proxmox host):

- From a **note**: run `server_backup.py gpg-test` and choose **p**. Paste the whole note (the
  passphrase line doesn't matter), press Enter on an empty line, then type the passphrase.
- From an **attachment**: download the `.SECRET.asc` file into RAM rather than onto a disk, run
  the test, then delete the file:
  ```bash
  scp server-backup-key-XXXXXXXX.SECRET.asc root@<host>:/dev/shm/
  ```
  ```bash
  server_backup.py gpg-test --key-file /dev/shm/server-backup-key-XXXXXXXX.SECRET.asc; rm /dev/shm/server-backup-key-XXXXXXXX.SECRET.asc
  ```

A pass shows three lines: `key … is the backup key this machine encrypts to`, `passphrase OK`,
and `<ts>.tar.gpg: decrypted and readable, N files match SHA256SUMS`.

| message | meaning |
|---|---|
| `that is not a private key` | you copied the public block; the private block is needed |
| `… is NOT the backup key configured here` | wrong Vaultwarden item, or a different key |
| `passphrase rejected` | the passphrase saved in the item is wrong |
| `no encrypted archive found yet` | only the key and passphrase were tested; repeat after the first host-config backup |

**Without the tool** (any Linux machine with `gpg`, e.g. a laptop; proves you can restore if the
host is lost). Use a throwaway keyring in RAM:
```bash
export GNUPGHOME=$(mktemp -d /dev/shm/gpgtest.XXXX)
```
```bash
gpg --import        # paste the key block from Vaultwarden, then Ctrl-D (or: gpg --import <file>)
```
```bash
gpg --pinentry-mode loopback -d <ts>.tar.gpg | tar tv | head
```
```bash
gpgconf --kill gpg-agent; rm -rf "$GNUPGHOME"; unset GNUPGHOME
```
The third command asks for the passphrase and lists the archive contents. If no archive is at
hand, test the passphrase alone with
`echo ok | gpg --trust-model always -e -r <KEYID> | gpg --pinentry-mode loopback -d`.

### Tamper detection

Every backup this machine writes is recorded in `/var/lib/server-backup/ledger.json`. `backup`,
`verify` and `status` compare that record with what is actually there:

| finding | result |
|---|---|
| a backup is gone or changed, and this tool didn't remove it | **error**; retention pauses for that destination |
| the Restic repository was replaced or deleted | **error** |
| a backup exists that this machine didn't make | warning |
| the ledger disappeared after earlier runs | warning, then a new baseline |

Findings repeat until you run `ledger --accept`; do the same after deleting backups on purpose.
An attacker with root on the machine can edit the ledger too: it detects changes, it doesn't
prevent them.

### Safety rules

- **Share preflight:** fresh private mount point, fstype `cifs`/`smb3`, optional marker file,
  write/read/delete test, free space. Large writes re-check the mount first. VM backups never fall
  back to local disk.
- **One run at a time:** one mount per run; a non-blocking lock in `/run/server-backup.lock`.
- **Retention never displaces a good backup:** only valid backups count, retention runs only after
  a successful backup, failed runs remove only their own partial files, and tamper findings pause
  retention.
- **Secrets stay out of logs:** generated secrets go to the terminal only; files are created with
  umask 077.
- **Nothing is dropped silently:** missing paths, `backup=0` disks, guest-agent problems, large
  files, full disks, unknown config keys and unencrypted host-config archives are all reported.
  Warnings and notes go to `/var/log/server-backup.log` as well.
- **Interrupts clean up:** SIGTERM/SIGHUP stop vzdump or restic, unmount the share, and exit 130.

### Restore

Instructions are written next to the data: `luks/<ts>/README.txt`, `proxmox/host/<ts>/README.txt`,
`proxmox/vm/RESTORE-vm.txt` and `RESTORE-files.txt`.

- **Files:** `restic restore latest --host <host> --target /tmp/r --include /path`
- **VM:** `qmrestore <archive> <NEWID> --storage <S> --unique 1`. `restore-test` does this safely:
  it refuses a VM ID already in use, never starts the test VM, sets its links down, removes
  passthrough/hugepages/pinning, and warns about RAM. Disks excluded with `backup=0` aren't
  restored; re-attach or recreate them.
- **Proxmox host:** reinstall the same PVE version, restore selected files from `files/etc.tar`,
  put `config.db` back into pmxcfs, then restore the VMs.
- **LUKS:** `cryptsetup luksHeaderRestore`, plus the keyfiles and saved passphrases.

### Migrating from luks_backup.py

Without `-c`, and with no `/etc/server-backup/config.json`, the tool imports
`/etc/luks-backup/config.json`. LUKS backups move to `<host>/luks/`; delete old-layout backups by
hand later. Without a command the tool now shows `status`; `run` keeps the old behaviour.

### Changelog

The first line of `status` shows the installed version.

- **2.3.0** A groundskeeper sign-off line after a clean `backup`, `verify`, `restore-test`,
  `gpg-test` or `status` in a terminal. Never in errors, warnings, logs, JSON or email;
  `"personality": false` turns it off. `--version` / `-V`.
- **2.2.1** Progress for vzdump, qmrestore (`restore-test`) and restic backups, about every 30 s,
  without needing `-v`. Previously these steps were silent for minutes.
- **2.2.0**
  - Email reports after `backup`/`verify`, over SMTP or sendmail; `notify-test`; `--no-notify`.
  - Disk-usage warnings at 90 % and errors at 97 %: share, local filesystems, LVM thin pools
    (data and metadata), ZFS.
  - Config check: unknown or misspelled keys (with suggestions) and duplicate keys are reported.
  - Progress messages while checksums and `zstd -t` read archives back.
  - Warnings and notes are written to the log file.
  - Date-based retention (`keep_daily/weekly/monthly`) for VM and host-config backups.
  - `systemd-units` builds timers from `profiles` + `schedules` (only where a module is enabled),
    adds a `verify --deep` timer every second month, and flags timers that are no longer needed.
    The repo's fixed `systemd/` folder is gone.
  - Existing configs work unchanged; the new settings take their defaults.
- **2.1.0** Backup-key naming and Vaultwarden flow, `gpg-test`, `excluded_disks_ok`,
  passthrough-safe `restore-test`.
- **2.0.0** First release: four modules, shared CIFS preflight, profiles, tamper ledger, size cap,
  restore tests, systemd units.

### Tests

```bash
python3 -m unittest discover -s tests -v
```

62 tests use fake `qm`, `vzdump`, `qmrestore`, `restic`, `pveversion`, `lsblk`, `lvs`,
`sendmail` and `cryptsetup`, and a local directory in place of the CIFS mount. The backup-key
tests use the real `gpg` when it's installed.

**Verified on real systems (2026-11-20, 2.1.0):** CIFS preflight against the NAS; `status` and
the backup-key setup on the Proxmox host; vzdump backup of VM 102 (42.5 GiB); `restore-test` of
VM 102 as VM 9102 (passthrough stripped, links down, onboot off); boot to emergency mode, as
expected for an OS-only restore.

**Not yet verified:** VM 101; host config backup and `gpg-test` against a real archive; email;
disk checks on real thin pools; Restic on a VM; a LUKS comparison against `luks_backup.py`.
