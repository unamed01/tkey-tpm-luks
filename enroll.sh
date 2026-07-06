#!/usr/bin/env bash
# Creates a P-256 ECDSA signing key in the TPM sealed to PCR policy,
#
# Usage: enrollment.sh
#
# Env overrides:
#   TPM_HANDLE  persistent handle    (default: 0x81000001)
#   PUBKEY_OUT  output path          (default: ./tpm_pubkey_raw.bin)

set -euo pipefail

PCR_BANK="sha256"
PCR_LIST="0,4,8,9"
TPM_HANDLE="${TPM_HANDLE:-0x81000001}"
PUBKEY_OUT="${PUBKEY_OUT:-./tpm_pubkey_raw.bin}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; tpm2_flushcontext -t 2>/dev/null || true' EXIT

die() {
  echo "ERR: $*" >&2
  exit 1
}

preflight() {
  local deps=(tpm2_createprimary tpm2_create tpm2_load tpm2_evictcontrol
    tpm2_readpublic tpm2_createpolicy tpm2_flushcontext
    tpm2_getcap tpm2_pcrread)
  for cmd in "${deps[@]}"; do
    command -v "$cmd" &>/dev/null || die "missing dependency: $cmd"
  done
  [[ $EUID -eq 0 ]] || die "must run as root"

  if tpm2_pcrread "${PCR_BANK}:${PCR_LIST}" | grep --color '0000000000000000000000000000000000000000000000000000000000000000'; then
    die "one of the PCRs are blank make sure your grub is measuring PCRs correctly "
  fi

  echo "Current PCR values being sealed to (${PCR_BANK}:${PCR_LIST}):"
  tpm2_pcrread "${PCR_BANK}:${PCR_LIST}"
  echo
  echo "  These values must match at EVERY unlock"
  echo "  Re-enrollment required after firmware, kernel, or GRUB updates (which would require a recompiling and renrolling client)"
  echo "  you should probably update your grub kernel before doing this.."
  echo
  read -rp "  Are you sure? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || die "aborted"
}

tpm_create_key() {
  echo "Checking handle ${TPM_HANDLE}.."
  if tpm2_getcap handles-persistent 2>/dev/null | grep -qF "${TPM_HANDLE}"; then
    echo "Handle ${TPM_HANDLE} already occupied."
    read -rp "Evict and re-create? This invalidates any existing enrollment [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "aborted"
    tpm2_evictcontrol -C o -c "${TPM_HANDLE}"
    echo "Evicted handle"
  fi

  echo "Creating primary key (owner hierarchy).."
  tpm2_createprimary \
    -C o \
    -G ecc256 \
    -g sha256 \
    -c "${WORK}/primary.ctx"

  echo "Building PCR policy.."
  tpm2_createpolicy \
    --policy-pcr \
    -l "${PCR_BANK}:${PCR_LIST}" \
    -L "${WORK}/pcr_policy.bin"

  echo "Creating signing key.."
  tpm2_create \
    -C "${WORK}/primary.ctx" \
    -G "ecc256:ecdsa-sha256" \
    -g sha256 \
    -r "${WORK}/sign.priv" \
    -u "${WORK}/sign.pub" \
    -L "${WORK}/pcr_policy.bin" \
    -a "sign|fixedtpm|fixedparent|sensitivedataorigin"

  echo "Loading and persisting signing key at ${TPM_HANDLE}.."
  tpm2_load \
    -C "${WORK}/primary.ctx" \
    -r "${WORK}/sign.priv" \
    -u "${WORK}/sign.pub" \
    -c "${WORK}/sign.ctx"

  tpm2_evictcontrol \
    -C o \
    -c "${WORK}/sign.ctx" \
    "${TPM_HANDLE}"

  tpm2_flushcontext -t 2>/dev/null || true

  echo "created keys at handle: ${TPM_HANDLE}."
}

export_pubkey() {
  echo "Exporting public key from tpm.."
  tpm2_readpublic \
    -c "${TPM_HANDLE}" \
    -o "${WORK}/pubkey.der" \
    --format der

  cp "${WORK}/pubkey.der" "${PUBKEY_OUT}" || die "couldn't copy pubkey from $WORK into $PUBKEY_OUT"
  echo "Public key written to ${PUBKEY_OUT}."
}

main() {
  echo "╔══════════════════════════════════════════════╗"
  echo "║  TKey FDE — TPM Key Enrollment               ║"
  echo "╠══════════════════════════════════════════════╣"
  printf "║  PCRs   : %-34s║\n" "${PCR_BANK}:${PCR_LIST}"
  printf "║  Handle : %-34s║\n" "${TPM_HANDLE}"
  printf "║  Output : %-34s║\n" "${PUBKEY_OUT}"
  echo "╚══════════════════════════════════════════════╝"
  echo

  preflight
  tpm_create_key
  export_pubkey
}

main
