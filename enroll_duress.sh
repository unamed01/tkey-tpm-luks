#!/usr/bin/env bash
set -eu
test -f SALT || head -c 32 /dev/urandom >SALT
touch duress.argon2
cd host/
# dummy env vars, which won't matter since build scripts will recompile with correct ones later.
bootdev=a luksdev=a luksUUID=a cargo run --release --bin enroll_duress
