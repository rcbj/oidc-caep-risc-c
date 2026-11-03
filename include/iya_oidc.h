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
/* iya_oidc_authorize with per-request values; NULL or "" keeps the configured one.
   redirect_uri is held to the configuration's rule (https, or http on a loopback
   host). acr_values is space-separated; the ID token's acr must be one of them. */
int iya_oidc_authorize_with(iya_oidc_rp *rp, const char *redirect_uri, const char *scope, const char *acr_values,
                            iya_oidc_txn **out, iya_oidc_error *err);
iya_oidc_txn *iya_oidc_txn_clone(const iya_oidc_txn *txn);
void iya_oidc_txn_set_state(iya_oidc_txn *txn, const char *state);
void iya_oidc_txn_set_nonce(iya_oidc_txn *txn, const char *nonce);
const char *iya_oidc_txn_url(const iya_oidc_txn *txn);
const char *iya_oidc_txn_state(const iya_oidc_txn *txn);
const char *iya_oidc_txn_acr_values(const iya_oidc_txn *txn);
void iya_oidc_txn_free(iya_oidc_txn *txn);

int iya_oidc_complete(iya_oidc_rp *rp, const char *const *keys, const char *const *vals, size_t nquery,
                      const iya_oidc_txn *txn, iya_oidc_login **out, iya_oidc_error *err);
/* iya_oidc_complete keeping the tokens in the session token cache under session_id
   (NULL or "": an identifier the library chooses, iya_oidc_login_session_id).
   iya_oidc_complete caches the same way under a chosen identifier. */
int iya_oidc_complete_session(iya_oidc_rp *rp, const char *const *keys, const char *const *vals, size_t nquery,
                              const iya_oidc_txn *txn, const char *session_id, iya_oidc_login **out,
                              iya_oidc_error *err);
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
const char *iya_oidc_login_token_type(const iya_oidc_login *login);
const char *iya_oidc_login_session_id(const iya_oidc_login *login);
const char *iya_oidc_login_acr(const iya_oidc_login *login);
void iya_oidc_login_free(iya_oidc_login *login);

/* The session token cache. A valid access token for a session: the cached one
   while it has more than 30 seconds left, otherwise one from the refresh token
   (with a DPoP proof when DPoP is in use). A failed refresh removes the entry.
   access_token and token_type (either may be NULL) are freed with
   iya_oidc_string_free. */
int iya_oidc_session_access_token(iya_oidc_rp *rp, const char *session_id, char **access_token, char **token_type,
                                  iya_oidc_error *err);
void iya_oidc_session_remove(iya_oidc_rp *rp, const char *session_id);

/* A replacement for the in-memory session store, for a store shared by several
   processes. The entry is a JSON object (access_token, token_type, refresh_token,
   id_token, scope, subject, claims_json, expires_at). get returns 1 and sets
   *tokens_json to a string allocated with malloc (the library frees it), or 0 when
   there is no entry. The callbacks may be called from several threads at once.
   NULL restores the in-memory store. */
typedef struct iya_oidc_session_store {
  void *user;
  int (*get)(void *user, const char *session_id, char **tokens_json);
  void (*put)(void *user, const char *session_id, const char *tokens_json);
  void (*remove)(void *user, const char *session_id);
} iya_oidc_session_store;
int iya_oidc_set_session_store(iya_oidc_rp *rp, const iya_oidc_session_store *store, iya_oidc_error *err);

/* A request to a resource server with an access token from this relying party:
   Authorization Bearer, or DPoP with a proof bound to the token (ath) and one
   retry when the server asks for a DPoP nonce. body and content_type may be NULL.
   *response_body is freed with iya_oidc_string_free. */
int iya_oidc_resource_request(iya_oidc_rp *rp, const char *method, const char *url, const char *access_token,
                              const char *body, const char *content_type, int *status, char **response_body,
                              iya_oidc_error *err);
/* 1 when this relying party sends DPoP proofs; the thumbprint of its DPoP key, or "". */
int iya_oidc_dpop(const iya_oidc_rp *rp);
const char *iya_oidc_dpop_jkt(const iya_oidc_rp *rp);

typedef struct iya_oidc_receiver iya_oidc_receiver;
typedef void (*iya_oidc_on_end_fn)(const char **ids, size_t count, void *user);
typedef void (*iya_oidc_on_event_fn)(const char *type, int ended, void *user);

int iya_oidc_receiver_new(const char *transmitter, iya_oidc_on_end_fn on_end, void *user, const char *authorization,
                          int poll_interval_ms, iya_oidc_receiver **out, iya_oidc_error *err);
/* A receiver whose every transmitter call carries a client-credentials token from rp
   (scope NULL or "": ssf.manage), with a DPoP proof when that token is DPoP-bound,
   and rp's tlsCa and pollIntervalMs. Ended sessions are also removed from rp's
   session token cache. rp must outlive the receiver. */
int iya_oidc_receiver_new_for_rp(const char *transmitter, iya_oidc_on_end_fn on_end, void *user, iya_oidc_rp *rp,
                                 const char *scope, iya_oidc_receiver **out, iya_oidc_error *err);
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
