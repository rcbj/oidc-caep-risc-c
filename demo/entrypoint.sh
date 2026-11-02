#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# The image carries the listener CA trust chain tlsCa names from build time
# (scripts/configure_iya_sts.py writes it; the Dockerfile copies demo/ in).
# This start-time refresh is optional on top of that; TLS_CA_REFRESH=0 skips it.
if [ "${TLS_CA_REFRESH:-1}" != "0" ]; then
  python3 /app/scripts/trust_chain.py --config "${OIDC_CONFIG:-/app/demo/oidc.json}" || true
fi
exec "$@"
