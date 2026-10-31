#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <package.deb|package.rpm>" >&2
	exit 1
fi

PACKAGE="$(readlink -f "$1")"

case "${PACKAGE}" in
*.deb) apt-get install -y --no-install-recommends "${PACKAGE}" ;;
*.rpm) dnf -y --setopt=install_weak_deps=False install "${PACKAGE}" ;;
*)
	echo "Not a .deb or .rpm: ${PACKAGE}" >&2
	exit 1
	;;
esac

fail() {
	echo "smoke test: $*" >&2
	exit 1
}

status=0
out="$(lys-secrets unexpected 2>&1)" || status=$?
[[ ${status} -eq 2 ]] || fail "lys-secrets with an argument exited ${status}, want its usage error (2)"
[[ ${out} == *'unexpected argument "unexpected"'* ]] || fail "lys-secrets with an argument printed ${out@Q}"

for file in /usr/lib/systemd/user/lys-secrets.service /usr/share/lys-secrets/org.freedesktop.secrets.service \
	/usr/share/lys-secrets/dev.stubbe.lys.Vault1.service; do
	[[ -f ${file} ]] || fail "${file} is missing"
done

[[ ! -e /etc/systemd/user/default.target.wants/lys-secrets.service ]] || fail "installing enabled lys-secrets.service"

echo "smoke test: ${PACKAGE} installs and runs"
