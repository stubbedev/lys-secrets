#!/usr/bin/env bash
set -euo pipefail

NAME=lys-secrets

usage() {
	echo "Usage: $0 <archive> <version> [deb|rpm]" >&2
	exit 1
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
	usage
fi

ARCHIVE="$(readlink -f "$1")"
VERSION="$2"
FORMAT="${3:-}"
MAINTAINER="${DEBFULLNAME:-Alexander Bugge Stage} <${DEBEMAIL:-abs@stubbe.dev}>"

cd "$(dirname "$0")/../.."

sed_escape() {
	printf '%s' "$1" | sed 's/[&\\|]/\\&/g'
}

render_template() {
	sed \
		-e "s|@VERSION@|$(sed_escape "${VERSION}")|g" \
		-e "s|@DATE@|$(sed_escape "$3")|g" \
		-e "s|@MAINTAINER@|$(sed_escape "${MAINTAINER}")|g" \
		"$1" >"$2"
}

build_deb() {
	local archive_dir archive_arch deb_arch topdir source_dir package_dir out_dir
	archive_dir="$(basename "${ARCHIVE}" .tar.gz)"
	archive_arch="${archive_dir%-linux}"
	archive_arch="${archive_arch##*-}"
	case "${archive_arch}" in
	x86_64) deb_arch=amd64 ;;
	aarch64) deb_arch=arm64 ;;
	*)
		echo "No Debian architecture for ${archive_arch} (from ${ARCHIVE})" >&2
		exit 1
		;;
	esac
	topdir="${PWD}/debbuild"
	source_dir="${topdir}/BUILD/source"
	package_dir="${source_dir}/${NAME}-${VERSION}"
	out_dir="${topdir}/DEBS/${deb_arch}"
	rm -rf "${topdir}/BUILD"
	mkdir -p "${source_dir}" "${out_dir}"
	tar xzf "${ARCHIVE}" -C "${source_dir}"
	mv "${source_dir}/${archive_dir}" "${package_dir}"
	mkdir -p "${package_dir}/debian/source"
	render_template packaging/debian/control.in "${package_dir}/debian/control" ""
	render_template packaging/debian/changelog.in "${package_dir}/debian/changelog" "$(LC_ALL=C date -uR)"
	cp packaging/debian/copyright packaging/debian/rules "${package_dir}/debian/"
	cp packaging/debian/source/format "${package_dir}/debian/source/format"
	(cd "${package_dir}" && dpkg-buildpackage -us -uc -b -a"${deb_arch}")
	find "${source_dir}" -maxdepth 1 -type f -name '*.deb' -exec mv -t "${out_dir}" {} +
}

build_rpm() {
	local topdir="${PWD}/rpmbuild"
	rm -rf "${topdir}/BUILD" "${topdir}/BUILDROOT"
	mkdir -p "${topdir}/SOURCES" "${topdir}/SPECS"
	cp "${ARCHIVE}" "${topdir}/SOURCES/"
	render_template "packaging/rpm/${NAME}.spec.in" "${topdir}/SPECS/${NAME}.spec" "$(LC_ALL=C date -u '+%a %b %d %Y')"
	rpmbuild --define "_topdir ${topdir}" -bb "${topdir}/SPECS/${NAME}.spec"
}

case "${FORMAT}" in
"")
	build_deb
	build_rpm
	;;
deb) build_deb ;;
rpm) build_rpm ;;
*)
	echo "Unknown package format: ${FORMAT}" >&2
	usage
	;;
esac
