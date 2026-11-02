// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_OIDC_H
#define IYA_OIDC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IYA_OIDC_OK 0
#define IYA_OIDC_ERR_CONFIG 1
#define IYA_OIDC_ERR_DISCOVERY 2
#define IYA_OIDC_ERR_PROTOCOL 3
#define IYA_OIDC_ERR_VALIDATION 4
#define IYA_OIDC_ERR_SIGNATURE 5
#define IYA_OIDC_ERR_SSF 6

#define IYA_OIDC_DEFAULT_SCOPES "openid profile email offline_access ssf.read ssf.manage"

typedef struct iya_oidc_error {
  int code;
  char message[4096];
  char oauth_error[256];
} iya_oidc_error;

const char *iya_oidc_error_name(int code);
const char *iya_oidc_default_scopes(void);

int iya_oidc_hash_claim(const char *value, const char *alg, char *out, size_t out_len, iya_oidc_error *err);
const char *iya_oidc_event_type(const char *name);

int iya_oidc_verify_set(const char *token, const char *jwks_json, char **payload_json, iya_oidc_error *err);
int iya_oidc_subject_of(const char *sub_json, const char *issuer, char *person, size_t person_len, char *email,
                        size_t email_len, char *idp_session, size_t idp_len, int *count, iya_oidc_error *err);

int iya_oidc_resolve_config(const char *json, const char *base_dir, char **out_json, iya_oidc_error *err);

typedef struct iya_oidc_rp iya_oidc_rp;
typedef struct iya_oidc_txn iya_oidc_txn;
typedef struct iya_oidc_login iya_oidc_login;

int iya_oidc_create(const char *config_json, iya_oidc_rp **out, iya_oidc_error *err);
int iya_oidc_open_file(const char *path, iya_oidc_rp **out, iya_oidc_error *err);
void iya_oidc_rp_free(iya_oidc_rp *rp);

int iya_oidc_authorize(iya_oidc_rp *rp, iya_oidc_txn **out, iya_oidc_error *err);
iya_oidc_txn *iya_oidc_txn_clone(const iya_oidc_txn *txn);
void iya_oidc_txn_set_state(iya_oidc_txn *txn, const char *state);
void iya_oidc_txn_set_nonce(iya_oidc_txn *txn, const char *nonce);
const char *iya_oidc_txn_url(const iya_oidc_txn *txn);
const char *iya_oidc_txn_state(const iya_oidc_txn *txn);
void iya_oidc_txn_free(iya_oidc_txn *txn);

int iya_oidc_complete(iya_oidc_rp *rp, const char *const *keys, const char *const *vals, size_t nquery,
                      const iya_oidc_txn *txn, iya_oidc_login **out, iya_oidc_error *err);
int iya_oidc_refresh(iya_oidc_rp *rp, const char *refresh_token, const char *scope, const iya_oidc_login *previous,
                     iya_oidc_login **out, iya_oidc_error *err);
int iya_oidc_client_credentials(iya_oidc_rp *rp, const char *scope, char **access_token, iya_oidc_error *err);
int iya_oidc_userinfo(iya_oidc_rp *rp, const char *access_token, const char *expected_sub, char **sub_out,
                      iya_oidc_error *err);
char *iya_oidc_end_session_url(iya_oidc_rp *rp, const char *id_token, const char *state);

const char *iya_oidc_login_subject(const iya_oidc_login *login);
const char *iya_oidc_login_issuer(const iya_oidc_login *login);
const char *iya_oidc_login_email(const iya_oidc_login *login);
const char *iya_oidc_login_preferred_username(const iya_oidc_login *login);
const char *iya_oidc_login_sid(const iya_oidc_login *login);
const char *iya_oidc_login_access_token(const iya_oidc_login *login);
const char *iya_oidc_login_id_token(const iya_oidc_login *login);
const char *iya_oidc_login_refresh_token(const iya_oidc_login *login);
void iya_oidc_login_free(iya_oidc_login *login);

typedef struct iya_oidc_receiver iya_oidc_receiver;
typedef void (*iya_oidc_on_end_fn)(const char **ids, size_t count, void *user);
typedef void (*iya_oidc_on_event_fn)(const char *type, int ended, void *user);

int iya_oidc_receiver_new(const char *transmitter, iya_oidc_on_end_fn on_end, void *user, const char *authorization,
                          int poll_interval_ms, iya_oidc_receiver **out, iya_oidc_error *err);
int iya_oidc_receiver_on(iya_oidc_receiver *rx, const char *event_type, iya_oidc_on_event_fn fn, void *user,
                         iya_oidc_error *err);
int iya_oidc_receiver_start(iya_oidc_receiver *rx, iya_oidc_error *err);
void iya_oidc_receiver_stop(iya_oidc_receiver *rx);
int iya_oidc_receiver_poll_once(iya_oidc_receiver *rx, int *more, iya_oidc_error *err);
int iya_oidc_receiver_track(iya_oidc_receiver *rx, const char *local_id, const char *person, const char *email,
                            const char *idp_session, iya_oidc_error *err);
int iya_oidc_receiver_verify(iya_oidc_receiver *rx, const char *state, iya_oidc_error *err);
const char *iya_oidc_receiver_stream_id(iya_oidc_receiver *rx);
void iya_oidc_receiver_free(iya_oidc_receiver *rx);

void iya_oidc_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
