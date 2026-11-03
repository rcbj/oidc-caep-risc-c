// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_TEST_STUB_H
#define IYA_TEST_STUB_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iya_test_provider iya_test_provider;
typedef struct iya_test_tx iya_test_tx;

iya_test_provider *iya_test_provider_start(void);
void iya_test_provider_free(iya_test_provider *provider);
const char *iya_test_provider_url(iya_test_provider *provider);
char *iya_test_provider_config(iya_test_provider *provider, const char *overrides_json);
char *iya_test_provider_config_jwt(iya_test_provider *provider);
void iya_test_provider_set_par(iya_test_provider *provider, int on);
void iya_test_provider_set_corrupt(iya_test_provider *provider, int on);
void iya_test_provider_set_aud(iya_test_provider *provider, const char *aud);
void iya_test_provider_set_exp(iya_test_provider *provider, long long exp);
void iya_test_provider_set_bad_at_hash(iya_test_provider *provider, int on);
/* mode 0: no dpop_signing_alg_values_supported; 1: ES256 and RS256; 2: RS256 only. */
void iya_test_provider_set_dpop(iya_test_provider *provider, int mode);
void iya_test_provider_set_dpop_nonce(iya_test_provider *provider, int on);
void iya_test_provider_set_require_par(iya_test_provider *provider, int on);
/* The next ID token only. what: 1 drops typ, 2 drops at_hash. */
void iya_test_provider_set_omit(iya_test_provider *provider, int what);
void iya_test_provider_set_acr(iya_test_provider *provider, const char *acr);
/* The token_type of the next token response, whatever the proof says. */
void iya_test_provider_set_token_type(iya_test_provider *provider, const char *type);
void iya_test_provider_set_iat_offset(iya_test_provider *provider, long long offset);
void iya_test_provider_set_expires_in(iya_test_provider *provider, int seconds);
void iya_test_provider_set_algs(iya_test_provider *provider, const char *json_array);
void iya_test_provider_revoke_refresh(iya_test_provider *provider);
const char *iya_test_provider_note(iya_test_provider *provider, const char *name);
char *iya_test_provider_metadata(iya_test_provider *provider);

int iya_test_manual(const char *url, int *status, char *location, size_t location_len);

iya_test_tx *iya_test_tx_start(void);
void iya_test_tx_free(iya_test_tx *tx);
const char *iya_test_tx_url(iya_test_tx *tx);
int iya_test_tx_created(iya_test_tx *tx);
const char *iya_test_tx_authorization(iya_test_tx *tx);
char *iya_test_tx_deliver(iya_test_tx *tx, const char *event_type, const char *sub_json, const char *extra_json,
                          int other_key);
void iya_test_tx_set_dpop_nonce(iya_test_tx *tx, int on);
int iya_test_tx_dpop_proofs(iya_test_tx *tx);
int iya_test_tx_dpop_challenges(iya_test_tx *tx);
int iya_test_tx_ack_count(iya_test_tx *tx);
const char *iya_test_tx_ack_at(iya_test_tx *tx, int index);
const char *iya_test_tx_err(iya_test_tx *tx, const char *jti);
const char *iya_test_tx_verify_state(iya_test_tx *tx);
int iya_test_tx_verify_status(iya_test_tx *tx);

char *iya_test_sign_set(const char *payload_json, const char *header_json, int which_key);
char *iya_test_ssf_jwks(void);

/* kind: 0 absent, 1 null, 2 false, 3 true, 4 number, 5 string. path is dot-separated. */
int iya_test_lookup(const char *json, const char *path, char *out, size_t out_len, int *kind);

#ifdef __cplusplus
}
#endif

#endif
