# Server Backup Utility - Development Brief

## Goal

Evolve the existing `luks_backup.py` into a single deployable utility, tentatively `server_backup.py`, that can run both on a Proxmox host and inside Linux VMs/servers.

The utility should keep the deployment simplicity of one Python file while being internally modular. Environment detection determines which capabilities are available; configuration determines which capabilities actually run.

## Core Design

Use one program with shared infrastructure and independent backup modules:

```text
server_backup.py
|
+-- Shared infrastructure
|   +-- configuration
|   +-- logging
|   +-- locking
|   +-- CIFS mount/destination management
|   +-- GPG encryption where appropriate
|   +-- manifests/checksums
|   +-- retention
|   +-- verification/reporting
|
+-- Backup modules
    +-- LUKS recovery backup
    +-- selected-directory incremental backup
    +-- Proxmox VM backup
    +-- Proxmox host configuration backup
```

Preserve and reuse the proven CIFS, GPG, locking, validation, retention, and LUKS logic from the supplied `luks_backup.py`. Do not rewrite working LUKS functionality unnecessarily.

## Capability Detection

Detect capabilities rather than imposing a hard `VM` versus `Proxmox` role.

Examples:

- `cryptsetup` + discovered LUKS volumes -> LUKS module available
- `restic` -> directory backup available
- `qm` / `vzdump` -> Proxmox VM backup available
- `/etc/pve` -> Proxmox host backup available
- configured CIFS destination -> remote backup available

Detection only says what *can* run. The configuration must explicitly say what *should* run.

## 1. LUKS Recovery Module

Preserve the current behavior of `luks_backup.py`, including LUKS discovery, header backup, keyslot/recovery validation, GPG protection, checksums, restore metadata, retention, and secure remote copy.

LUKS backups are primarily configuration/recovery backups and do not need to run with every routine data backup. They should remain manually runnable and schedulable.

## 2. Incremental File/Directory Module

Add VM/server-side backup of configurable paths such as:

```text
/home/user
/mnt/local-data/project
/mnt/local-data-hdd/project
```

Use Restic rather than implementing incremental/deduplicated storage in Python. The Python utility should orchestrate repository access, backup, snapshots, verification, retention (`forget/prune`), and restore instructions.

Paths and excludes must be explicit in configuration. Do not silently exclude user data.

## 3. Proxmox VM Backup Module

When running on a Proxmox host, use native `vzdump` backups instead of raw `dd` imaging.

Requirements:

- configured VM IDs only, never automatically back up every discovered VM
- default to live `snapshot` backup
- use `zstd` compression
- detect VM state
- detect/report QEMU guest-agent availability
- capture `qm config <VMID>`
- verify backup artifact creation
- record size/checksum/metadata
- apply retention only after successful backup
- never delete the previous valid backup because a new backup failed

The VM backup provides complete disaster recovery, including guest OS, boot/filesystems, virtual disks, and the VM configuration needed to reconstruct hardware-specific settings.

## 4. Proxmox Host Configuration Module

Back up enough host configuration and inventory to rebuild the Proxmox host, including relevant content from:

```text
/etc/pve/
/etc/network/
/etc/hosts
/etc/hostname
/etc/fstab
/etc/crypttab
/etc/default/grub
/etc/modules*
/etc/modprobe.d/
/etc/systemd/system/
```

Also capture useful state such as:

```text
pveversion -v
qm list
qm config <configured VM IDs>
lsblk
blkid
pvs
vgs
lvs
ip addr
ip route
uname -a
installed package/version information
```

This is configuration backup, not a raw image of the Proxmox OS.

## Shared CIFS Destination

Use the existing CIFS implementation as shared infrastructure for all modules.

Before any large backup, enforce a preflight that verifies:

1. destination configuration is valid
2. CIFS mounted successfully
3. expected remote filesystem/share is actually mounted
4. write/read/delete test succeeds
5. adequate free space exists

Never allow a failed network mount to cause a VM backup to be written into the local root filesystem simply because the mount directory exists.

Suggested remote structure:

```text
serverBackup/<hostname>/
    luks/
    proxmox/
        host/
        vm/
    restic/
```

## Configuration and Profiles

Use one per-machine configuration file. Preserve JSON if that minimizes changes to the existing implementation.

Support profiles such as:

```text
daily   -> incremental selected-directory backup
weekly  -> directory + Proxmox VM + Proxmox host config
recovery -> LUKS recovery backup
```

Example commands:

```bash
server_backup.py status
server_backup.py backup --profile daily
server_backup.py backup --profile weekly
server_backup.py backup --luks
server_backup.py backup --files
server_backup.py backup --proxmox
server_backup.py verify
```

`status` should show detected host type/capabilities, configured modules, destination health, configured VMs, and important warnings without performing a backup.

## Safety Requirements

- Maintain restrictive permissions for credentials, staging data, and sensitive recovery material.
- Never log passwords, CIFS credentials, GPG secrets, Restic passwords, or recovery keys.
- Keep credentials outside normal configuration where practical.
- Use a global/non-blocking lock to prevent overlapping backup jobs.
- Clean temporary mounts/files on failure or interruption where possible.
- Preserve the current useful exit convention: success, failure, warning/partial success, interrupted.
- Retention must never remove the last known-good backup after a failed replacement.
- Every backup type must have a documented and testable restore path.

## Verification and Restore

Treat verification as a first-class feature:

- LUKS: retain existing header/key validation
- Restic: use native repository checks
- Proxmox: validate expected backup artifacts, associated VM config, metadata/checksum where useful
- Host config: verify archive/readability and manifest

Generate enough metadata/README information that restoration does not require remembering how the backup was created.

Test restoration before considering a module complete, including restoring a Proxmox backup under a different/test VM ID and restoring individual files from Restic.

## Implementation Approach

Keep the initial deliverable as a **single Python file**, but organize it into classes/services such as:

```text
Config
LockManager
CifsMount
GpgEncryption
RetentionManager
Manifest
EnvironmentDetector
LuksBackupService
DirectoryBackupService
ProxmoxVmBackupService
ProxmoxHostBackupService
ServerBackup
```

Suggested development order:

1. Refactor shared infrastructure from the existing LUKS code without changing behavior.
2. Regression-test existing LUKS backup functionality.
3. Add environment/capability detection and `status`.
4. Add Proxmox VM discovery/config capture.
5. Add `vzdump` backup, verification, and retention.
6. Add Proxmox host configuration backup.
7. Add Restic selected-directory backup.
8. Add profiles/non-interactive operation and systemd timer examples.
9. Perform restore tests for every module.

## Primary Design Principle

This is one utility, but not one monolithic backup mechanism. It orchestrates separate recovery layers:

```text
LUKS backup       -> encryption recovery
Restic            -> granular file/history recovery
Proxmox vzdump    -> complete VM disaster recovery
Host config       -> Proxmox host reconstruction
```

The supplied `luks_backup.py` should be treated as the regression baseline. Preserve its existing safety behavior while extracting reusable infrastructure for the broader utility.
