#!/bin/bash
set -euo pipefail
disp_template=$(qubes-prefs default_dispvm)
qvm-run --dispvm $disp_template xfce4-terminal -x '/home/user/QubesIncoming/qubes_enroll'
