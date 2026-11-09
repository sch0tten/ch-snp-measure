#!/usr/bin/env bash
# extract-boot-files.sh <image.qcow2|image.img> <outdir>
# Copy kernel(s) and initramfs image(s) out of a distribution cloud image without booting it, read-only:
# qcow2 -> raw in a temp dir, read-only loop device (losetup -r -P), each partition mounted read-only
# (ext*: ro,noload; xfs: ro,norecovery; btrfs/vfat: ro), boot files copied, everything torn down.
# Needs: qemu-img, sudo (losetup/mount). Output file names keep their in-image names; compare the
# sha256 with tests/vectors.json before using them.
set -euo pipefail
img=${1:?image}; out=${2:?outdir}; mkdir -p "$out"
t=$(mktemp -d); loop=; mnts=()
cleanup() { set +e; for m in "${mnts[@]}"; do sudo umount "$m"; done; [[ -n $loop ]] && sudo losetup -d "$loop"; rm -rf "$t"; }
trap cleanup EXIT
fmt=$(qemu-img info --output=json "$img" | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["format"])')
qemu-img convert -f "$fmt" -O raw "$img" "$t/disk.raw"
loop=$(sudo losetup -r -P -f --show "$t/disk.raw"); sleep 1
for p in "$loop"p*; do
  ty=$(sudo blkid -o value -s TYPE "$p" || true); n=${p##*p}
  case $ty in ext2|ext3|ext4) o=ro,noload ;; xfs) o=ro,norecovery ;; btrfs|vfat) o=ro ;; *) continue ;; esac
  mkdir -p "$t/mnt/p$n"; sudo mount -t "$ty" -o "$o" "$p" "$t/mnt/p$n" && mnts+=("$t/mnt/p$n")
done
sudo find "$t/mnt" -maxdepth 6 \( -path '*/proc' -o -path '*/sys' -o -path '*/usr/share' -o -path '*/var/lib' \) -prune -o \
  \( -name 'vmlinuz*' -o -name 'initrd.img*' -o -name 'initrd-*' -o -name 'initramfs-*' -o -name 'config-*' -o -name 'bzImage' \) \
  -type f -print 2>/dev/null | while read -r f; do
    b=$(basename "$f"); [[ $b == *rescue* ]] && continue
    sudo cp -L "$f" "$out/$b" && echo "$b"
  done
# Arch-style: kernel and config live under /usr/lib/modules/<ver>/
for md in $(sudo find "$t/mnt" -maxdepth 6 -type d -path '*lib/modules/*' -name '[0-9]*' 2>/dev/null); do
  v=$(basename "$md"); for k in vmlinuz bzImage config; do [[ -f $md/$k ]] && sudo cp "$md/$k" "$out/$k-$v" && echo "$k-$v"; done
done
sudo chown -R "$(id -u):$(id -g)" "$out"
(cd "$out" && sha256sum * > SHA256SUMS && cat SHA256SUMS)
