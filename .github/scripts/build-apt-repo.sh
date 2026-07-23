#!/usr/bin/env bash
# build-apt-repo.sh <debs-dir> <out-dir>
#
# Builds a complete, signed APT repository for the veepin packages, ready to be
# served as static files (GitHub Pages). The repository is STATELESS: it is
# regenerated from scratch on every release and carries only that release's
# packages — older versions stay downloadable from GitHub Releases, and apt
# users always track the latest. That keeps this script free of repo-state
# tooling (no reprepro database to persist between runs).
#
# Layout produced under <out-dir>:
#   pool/main/<pkg>/<pkg>_<ver>_<arch>.deb
#   dists/stable/{InRelease,Release,Release.gpg}
#   dists/stable/main/binary-<arch>/Packages{,.gz}   (one per $architectures)
#   veepin-archive-keyring.gpg     (dearmored public key, for signed-by=)
#   index.html                     (install instructions)
#
# Requirements: dpkg-dev (dpkg-scanpackages), apt-utils (apt-ftparchive), gpg
# with the signing secret key already imported (see APT_SIGNING_KEY in
# release.yml). Fails loudly if no secret key is available — an unsigned apt
# repo is worse than none, because users would have to disable verification.
set -euo pipefail

debs_dir=${1:?usage: build-apt-repo.sh <debs-dir> <out-dir>}
out_dir=${2:?usage: build-apt-repo.sh <debs-dir> <out-dir>}
suite=stable
component=main
# Every Debian trixie release architecture — the veepin binary is pure Go, so
# GoReleaser cross-compiles all of them (see goarch in .goreleaser.yaml).
architectures="amd64 arm64 armhf armel i386 ppc64el riscv64 s390x"

if ! gpg --list-secret-keys --with-colons | grep -q '^sec'; then
    echo "build-apt-repo: no GPG secret key imported; refusing to build an unsigned repo" >&2
    exit 1
fi

shopt -s nullglob
debs=("$debs_dir"/*.deb)
if [ ${#debs[@]} -eq 0 ]; then
    echo "build-apt-repo: no .deb files in $debs_dir" >&2
    exit 1
fi

rm -rf "$out_dir"
mkdir -p "$out_dir"

# --- pool/ ------------------------------------------------------------------
# Files are renamed to canonical <pkg>_<ver>_<arch>.deb from their control
# fields: dpkg-scanpackages --arch selects by FILENAME pattern (*_<arch>.deb),
# and GoReleaser names its armhf deb "..._linux_armv7.deb", which would
# silently drop it from the armhf index.
for deb in "${debs[@]}"; do
    pkg=$(dpkg-deb -f "$deb" Package)
    ver=$(dpkg-deb -f "$deb" Version)
    arch=$(dpkg-deb -f "$deb" Architecture)
    dst="$out_dir/pool/$component/$pkg"
    mkdir -p "$dst"
    cp "$deb" "$dst/${pkg}_${ver}_${arch}.deb"
done

# --- dists/<suite>/<component>/binary-<arch>/Packages -----------------------
# dpkg-scanpackages needs to run from the repo root so the Filename: fields it
# writes are pool/... paths relative to the repo base URL.
cd "$out_dir"
for arch in $architectures; do
    bindir="dists/$suite/$component/binary-$arch"
    mkdir -p "$bindir"
    dpkg-scanpackages --arch "$arch" pool > "$bindir/Packages"
    gzip -9 -k "$bindir/Packages"
done

# --- dists/<suite>/Release + signatures -------------------------------------
apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=veepin" \
    -o "APT::FTPArchive::Release::Label=veepin" \
    -o "APT::FTPArchive::Release::Suite=$suite" \
    -o "APT::FTPArchive::Release::Codename=$suite" \
    -o "APT::FTPArchive::Release::Components=$component" \
    -o "APT::FTPArchive::Release::Architectures=$architectures" \
    -o "APT::FTPArchive::Release::Description=veepin APT repository (latest release)" \
    release "dists/$suite" > "dists/$suite/Release"
# InRelease (clearsigned, what modern apt fetches) plus a detached Release.gpg
# for older clients.
gpg --batch --yes --clearsign --output "dists/$suite/InRelease" "dists/$suite/Release"
gpg --batch --yes --armor --detach-sign --output "dists/$suite/Release.gpg" "dists/$suite/Release"

# --- public key + landing page ----------------------------------------------
# Dearmored, because sources.list signed-by= wants a binary keyring.
gpg --batch --yes --export --output veepin-archive-keyring.gpg

cat > index.html <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>veepin APT repository</title>
<style>body{font-family:monospace;max-width:48rem;margin:3rem auto;padding:0 1rem}pre{background:#8882;padding:1rem;overflow-x:auto}</style>
<h1>veepin APT repository</h1>
<p>Signed repository carrying the latest <a href="https://github.com/xen0bit/veepin">veepin</a>
release for Debian/Ubuntu on every Debian release architecture (amd64, arm64,
armhf, armel, i386, ppc64el, riscv64, s390x). Older versions live on
<a href="https://github.com/xen0bit/veepin/releases">GitHub Releases</a>.</p>
<pre>
sudo curl -fsSL https://xen0bit.github.io/veepin/veepin-archive-keyring.gpg \
     -o /usr/share/keyrings/veepin-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/veepin-archive-keyring.gpg] https://xen0bit.github.io/veepin stable main" \
     | sudo tee /etc/apt/sources.list.d/veepin.list
sudo apt update
sudo apt install veepin veepin-nm
</pre>
HTML

echo "build-apt-repo: repository built in $out_dir"
find dists -type f | sort
