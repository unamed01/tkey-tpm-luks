#!/usr/bin/env bash --
# Creates a P-256 ECDSA signing key in the TPM, and exports pubkey

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
    die "one of the PCRs are blank make sure your grub is measuring PCRs."
  fi
}

tpm_create_key() {
  echo "Checking handle ${TPM_HANDLE}.."
  if tpm2_getcap handles-persistent 2>/dev/null | grep -qF "${TPM_HANDLE}"; then
    echo "Handle ${TPM_HANDLE} already occupied."
    read -rp "Evict and re-create? This invalidates any existing enrollment [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "aborted"
    tpm2_evictcontrol -C o -c "${TPM_HANDLE}"
    echo "Evicted handle."
  fi

  tpm2_createprimary \
    -C o \
    -G ecc256 \
    -g sha256 \
    -c "${WORK}/primary.ctx" >/dev/null

  tpm2_createpolicy \
    --policy-pcr \
    -l "${PCR_BANK}:${PCR_LIST}" \
    -L "${WORK}/pcr_policy.bin" >/dev/null

  tpm2_create \
    -C "${WORK}/primary.ctx" \
    -G "ecc256:ecdsa-sha256" \
    -g sha256 \
    -r "${WORK}/sign.priv" \
    -u "${WORK}/sign.pub" \
    -L "${WORK}/pcr_policy.bin" \
    -a "sign|fixedtpm|fixedparent|sensitivedataorigin" >/dev/null

  tpm2_load \
    -C "${WORK}/primary.ctx" \
    -r "${WORK}/sign.priv" \
    -u "${WORK}/sign.pub" \
    -c "${WORK}/sign.ctx" >/dev/null

  tpm2_evictcontrol \
    -C o \
    -c "${WORK}/sign.ctx" \
    "${TPM_HANDLE}" >/dev/null

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

preflight
tpm_create_key
export_pubkey
