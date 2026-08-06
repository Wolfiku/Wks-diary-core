#!/bin/bash
# wks-diary-core off-site backup helper.
# Everything under STORAGE_DIR is already encrypted (vault.wks, history/*.wks),
# except log.json's metadata (hashes/timestamps/sizes/device names, no content).
# Safe to sync anywhere without any extra encryption step.
#
# Usage: set STORAGE_DIR and BACKUP_TARGET, then run from cron, e.g.:
#   0 3 * * * /opt/wks-diary-core/backup.sh >> /var/log/wks-backup.log 2>&1

set -euo pipefail

STORAGE_DIR="${STORAGE_DIR:-/opt/wks-diary-core/storage}"
BACKUP_TARGET="${BACKUP_TARGET:-user@backup-host:/backups/wks-diary-core/}"

echo "[$(date -Iseconds)] starting backup of $STORAGE_DIR -> $BACKUP_TARGET"
rsync -az --delete "$STORAGE_DIR/" "$BACKUP_TARGET"
echo "[$(date -Iseconds)] backup done"

# Alternative using restic (better for versioned/deduplicated backups):
#   restic -r "$RESTIC_REPOSITORY" backup "$STORAGE_DIR"
#   restic -r "$RESTIC_REPOSITORY" forget --keep-daily 14 --keep-weekly 8 --keep-monthly 12 --prune
