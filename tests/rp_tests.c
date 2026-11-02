// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya_oidc.h"
#include "stub.h"

#include <openssl/evp.h>

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failed(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

static int contains(const char *s, const char *part) { return s && part && strstr(s, part) != NULL; }

static void b64url(const unsigned char *in, size_t n, char *out) {
  static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t o = 0;
  for (size_t i = 0; i + 2 < n; i += 3) {
    unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    out[o++] = t[(v >> 6) & 63];
    out[o++] = t[v & 63];
  }
  if (n % 3 == 1) {
    unsigned v = in[n - 1] << 16;
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
  } else if (n % 3 == 2) {
    unsigned v = (in[n - 2] << 16) | (in[n - 1] << 8);
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    out[o++] = t[(v >> 6) & 63];
  }
  out[o] = '\0';
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void pct(const char *in, char *out, size_t n) {
  size_t o = 0;
  for (size_t i = 0; in[i] && o + 1 < n; i++) {
    if (in[i] == '%' && hex_nibble(in[i + 1]) >= 0 && hex_nibble(in[i + 2]) >= 0) {
      out[o++] = (char)((hex_nibble(in[i + 1]) << 4) | hex_nibble(in[i + 2]));
      i += 2;
    } else if (in[i] == '+') {
      out[o++] = ' ';
    } else {
      out[o++] = in[i];
    }
  }
  out[o] = '\0';
}

typedef struct {
  char key[64];
  char val[4096];
} Pair;

static int query_of(const char *location, Pair *out, int max) {
  const char *q = strchr(location, '?');
  if (!q) return 0;
  q++;
  int n = 0;
  while (*q && n < max) {
    char rawk[256];
    char rawv[4096];
    size_t k = 0;
    while (*q && *q != '=' && *q != '&' && k + 1 < sizeof rawk) rawk[k++] = *q++;
    rawk[k] = '\0';
    size_t v = 0;
    if (*q == '=') q++;
    while (*q && *q != '&' && v + 1 < sizeof rawv) rawv[v++] = *q++;
    rawv[v] = '\0';
    if (*q == '&') q++;
    pct(rawk, out[n].key, sizeof out[n].key);
    pct(rawv, out[n].val, sizeof out[n].val);
    n++;
  }
  return n;
}

static const char *pair_get(Pair *pairs, int n, const char *key) {
  for (int i = 0; i < n; i++)
    if (strcmp(pairs[i].key, key) == 0) return pairs[i].val;
  return NULL;
}

static int complete_pairs(iya_oidc_rp *rp, Pair *pairs, int n, iya_oidc_txn *txn, iya_oidc_login **login,
                          iya_oidc_error *err) {
  const char *keys[16];
  const char *vals[16];
  if (n > 16) n = 16;
  for (int i = 0; i < n; i++) {
    keys[i] = pairs[i].key;
    vals[i] = pairs[i].val;
  }
  return iya_oidc_complete(rp, keys, vals, (size_t)n, txn, login, err);
}

static int sign_in(iya_oidc_rp *rp, iya_oidc_login **login, iya_oidc_txn **txn_out, Pair *query, int *nq,
                   iya_oidc_error *err) {
  iya_oidc_txn *txn = NULL;
  int rc = iya_oidc_authorize(rp, &txn, err);
  if (rc != IYA_OIDC_OK) return rc;
  int status = 0;
  char location[8192];
  location[0] = '\0';
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0 || location[0] == '\0') {
    snprintf(err->message, sizeof err->message, "the provider did not redirect (%d)", status);
    iya_oidc_txn_free(txn);
    return IYA_OIDC_ERR_PROTOCOL;
  }
  int n = query_of(location, query, 16);
  rc = complete_pairs(rp, query, n, txn, login, err);
  if (txn_out) *txn_out = txn;
  else iya_oidc_txn_free(txn);
  if (nq) *nq = n;
  return rc;
}

static int kind_is(const char *json, const char *path, int want) {
  int kind = -1;
  if (iya_test_lookup(json, path, NULL, 0, &kind) != 0) return 0;
  return kind == want;
}

static int text_is(const char *json, const char *path, const char *want) {
  char buf[4096];
  int kind = 0;
  if (iya_test_lookup(json, path, buf, sizeof buf, &kind) != 0) return 0;
  return strcmp(buf, want) == 0;
}

int TestDefaultScopesAndAtHash(void) {
  if (strcmp(iya_oidc_default_scopes(), IYA_OIDC_DEFAULT_SCOPES) != 0) return failed("scopes");
  if (strcmp(iya_oidc_default_scopes(), "openid profile email offline_access ssf.read ssf.manage") != 0)
    return failed("scope text");
  unsigned char sum[32];
  unsigned int n = 0;
  EVP_Digest("abc", 3, sum, &n, EVP_sha256(), NULL);
  char expect[64];
  b64url(sum, 16, expect);
  char got[64];
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  if (iya_oidc_hash_claim("abc", "RS256", got, sizeof got, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(got, expect) != 0) return failed(got);
  return 0;
}

int TestSignsInWithPKCE(void) {
  iya_test_provider *stub = iya_test_provider_start();
  if (!stub) return failed("provider");
  char *cfg = iya_test_provider_config(stub, NULL);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_rp *rp = NULL;
  if (iya_oidc_create(cfg, &rp, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_oidc_txn *txn = NULL;
  Pair query[16];
  int nq = 0;
  if (sign_in(rp, &login, &txn, query, &nq, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_oidc_login_subject(login), "user-1") != 0) return failed("subject");
  if (strcmp(iya_oidc_login_email(login), "user-1@example.com") != 0) return failed("email");
  if (strcmp(iya_oidc_login_sid(login), "sid-1") != 0) return failed("sid");
  if (strcmp(iya_oidc_login_issuer(login), iya_test_provider_url(stub)) != 0) return failed("issuer");
  if (strcmp(iya_oidc_login_preferred_username(login), "user-1") != 0) return failed("username");
  if (iya_oidc_login_refresh_token(login)[0] == '\0') return failed("refresh");
  const char *url = iya_oidc_txn_url(txn);
  if (!contains(url, "code_challenge=") || !contains(url, "code_challenge_method=S256") || contains(url, "client_secret"))
    return failed(url);
  char *sub = NULL;
  if (iya_oidc_userinfo(rp, iya_oidc_login_access_token(login), iya_oidc_login_subject(login), &sub, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (strcmp(sub, "user-1") != 0) return failed(sub);
  char *end = iya_oidc_end_session_url(rp, iya_oidc_login_id_token(login), "bye");
  if (!end || !contains(end, "/end-session") || !contains(end, "id_token_hint=") || !contains(end, "client_id="))
    return failed(end ? end : "end");
  iya_oidc_string_free(end);
  iya_oidc_string_free(sub);
  iya_oidc_login_free(login);
  iya_oidc_txn_free(txn);
  iya_oidc_rp_free(rp);
  iya_oidc_string_free(cfg);
  iya_test_provider_free(stub);
  return 0;
}

int TestRefusesACallbackThatIsNotThisSignIn(void) {
  iya_test_provider *stub = iya_test_provider_start();
  char *cfg = iya_test_provider_config(stub, NULL);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_rp *rp = NULL;
  if (iya_oidc_create(cfg, &rp, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_txn *txn = NULL;
  if (iya_oidc_authorize(rp, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  int status = 0;
  char location[8192];
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0) return failed("manual");
  Pair query[16];
  int n = query_of(location, query, 16);
  iya_oidc_txn *bad_state = iya_oidc_txn_clone(txn);
  iya_oidc_txn_set_state(bad_state, "nope");
  iya_oidc_login *login = NULL;
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, bad_state, &login, &err) == IYA_OIDC_OK || !contains(err.message, "state"))
    return failed(err.message);
  iya_oidc_txn *bad_nonce = iya_oidc_txn_clone(txn);
  iya_oidc_txn_set_nonce(bad_nonce, "nope");
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, bad_nonce, &login, &err) == IYA_OIDC_OK || !contains(err.message, "nonce"))
    return failed(err.message);
  for (int i = 0; i < n; i++)
    if (strcmp(query[i].key, "iss") == 0) snprintf(query[i].val, sizeof query[i].val, "%s", "https://elsewhere.example");
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, txn, &login, &err) == IYA_OIDC_OK || !contains(err.message, "iss mismatch"))
    return failed(err.message);
  for (int i = 0; i < n; i++)
    if (strcmp(query[i].key, "iss") == 0) snprintf(query[i].val, sizeof query[i].val, "%s", iya_test_provider_url(stub));
  if (n < 16) {
    snprintf(query[n].key, sizeof query[n].key, "access_token");
    snprintf(query[n].val, sizeof query[n].val, "should-not-be-here");
    n++;
  }
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, txn, &login, &err) == IYA_OIDC_OK || !contains(err.message, "access_token"))
    return failed(err.message);
  iya_oidc_txn_free(bad_state);
  iya_oidc_txn_free(bad_nonce);
  iya_oidc_txn_free(txn);
  iya_oidc_rp_free(rp);
  iya_oidc_string_free(cfg);
  iya_test_provider_free(stub);
  return 0;
}

int TestAcceptsACodeOnce(void) {
  iya_test_provider *stub = iya_test_provider_start();
  char *cfg = iya_test_provider_config(stub, NULL);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_rp *rp = NULL;
  if (iya_oidc_create(cfg, &rp, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_oidc_txn *txn = NULL;
  Pair query[16];
  int nq = 0;
  if (sign_in(rp, &login, &txn, query, &nq, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_oidc_login_subject(login), "user-1") != 0) return failed("subject");
  memset(&err, 0, sizeof err);
  iya_oidc_login *again = NULL;
  if (complete_pairs(rp, query, nq, txn, &again, &err) == IYA_OIDC_OK || !contains(err.message, "already used"))
    return failed(err.message);
  iya_oidc_login_free(login);
  iya_oidc_txn_free(txn);
  iya_oidc_rp_free(rp);
  iya_oidc_string_free(cfg);
  iya_test_provider_free(stub);
  return 0;
}

int TestRefusesBadTokens(void) {
  iya_test_provider *stub = iya_test_provider_start();
  char *cfg = iya_test_provider_config(stub, NULL);
  char *wrong_cfg = iya_test_provider_config(stub, "{\"clientSecret\":\"nope\"}");
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_rp *rp = NULL;
  iya_oidc_rp *wrong = NULL;
  if (iya_oidc_create(cfg, &rp, &err) != IYA_OIDC_OK) return failed(err.message);
  memset(&err, 0, sizeof err);
  if (iya_oidc_create(wrong_cfg, &wrong, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_txn *txn = NULL;
  if (iya_oidc_authorize(wrong, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  int status = 0;
  char location[8192];
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0) return failed("manual");
  Pair query[16];
  int n = query_of(location, query, 16);
  memset(&err, 0, sizeof err);
  iya_oidc_login *login = NULL;
  if (complete_pairs(wrong, query, n, txn, &login, &err) == IYA_OIDC_OK) return failed("expected invalid_client");
  if (strcmp(err.oauth_error, "invalid_client") != 0) return failed(err.oauth_error);
  iya_oidc_txn_free(txn);
  iya_test_provider_set_corrupt(stub, 1);
  memset(&err, 0, sizeof err);
  txn = NULL;
  if (iya_oidc_authorize(rp, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0) return failed("manual2");
  n = query_of(location, query, 16);
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, txn, &login, &err) == IYA_OIDC_OK || !contains(err.message, "signature"))
    return failed(err.message);
  iya_oidc_txn_free(txn);
  iya_test_provider_set_aud(stub, "other-client");
  memset(&err, 0, sizeof err);
  if (iya_oidc_authorize(rp, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0) return failed("manual3");
  n = query_of(location, query, 16);
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, txn, &login, &err) == IYA_OIDC_OK ||
      !(contains(err.message, "audience") || contains(err.message, "aud")))
    return failed(err.message);
  iya_oidc_txn_free(txn);
  iya_test_provider_set_exp(stub, (long long)time(NULL) - 3600);
  memset(&err, 0, sizeof err);
  if (iya_oidc_authorize(rp, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0) return failed("manual4");
  n = query_of(location, query, 16);
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, txn, &login, &err) == IYA_OIDC_OK ||
      !(contains(err.message, "exp") || contains(err.message, "timestamp") || contains(err.message, "old") ||
        contains(err.message, "iat")))
    return failed(err.message);
  iya_oidc_txn_free(txn);
  iya_test_provider_set_bad_at_hash(stub, 1);
  memset(&err, 0, sizeof err);
  if (iya_oidc_authorize(rp, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0) return failed("manual5");
  n = query_of(location, query, 16);
  memset(&err, 0, sizeof err);
  if (complete_pairs(rp, query, n, txn, &login, &err) == IYA_OIDC_OK || !contains(err.message, "at_hash"))
    return failed(err.message);
  iya_oidc_txn_free(txn);
  iya_oidc_rp_free(wrong);
  iya_oidc_rp_free(rp);
  iya_oidc_string_free(wrong_cfg);
  iya_oidc_string_free(cfg);
  iya_test_provider_free(stub);
  return 0;
}

int TestRefreshAndClientCredentials(void) {
  iya_test_provider *stub = iya_test_provider_start();
  char *cfg = iya_test_provider_config(stub, NULL);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_rp *rp = NULL;
  if (iya_oidc_create(cfg, &rp, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login *login = NULL;
  Pair query[16];
  if (sign_in(rp, &login, NULL, query, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  char previous[256];
  snprintf(previous, sizeof previous, "%s", iya_oidc_login_access_token(login));
  iya_oidc_login *refreshed = NULL;
  memset(&err, 0, sizeof err);
  if (iya_oidc_refresh(rp, iya_oidc_login_refresh_token(login), "", login, &refreshed, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (strcmp(iya_oidc_login_subject(refreshed), iya_oidc_login_subject(login)) != 0) return failed("refresh subject");
  if (strcmp(iya_oidc_login_access_token(refreshed), previous) == 0) return failed("refresh token unchanged");
  char *token = NULL;
  if (iya_oidc_client_credentials(rp, "ssf.manage", &token, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(token, "cc-token") != 0) return failed(token);
  iya_oidc_string_free(token);
  token = NULL;
  if (iya_oidc_client_credentials(rp, "ssf.manage", &token, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(token, "cc-token") != 0) return failed(token);
  iya_oidc_string_free(token);
  iya_oidc_login_free(refreshed);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  iya_oidc_string_free(cfg);
  iya_test_provider_free(stub);
  return 0;
}

int TestPAR(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_test_provider_set_par(stub, 1);
  char *cfg = iya_test_provider_config(stub, NULL);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_rp *rp = NULL;
  if (iya_oidc_create(cfg, &rp, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_oidc_txn *txn = NULL;
  Pair query[16];
  if (sign_in(rp, &login, &txn, query, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  const char *url = iya_oidc_txn_url(txn);
  if (!contains(url, "request_uri=") || contains(url, "code_challenge=") ||
      strcmp(iya_oidc_login_subject(login), "user-1") != 0)
    return failed(url);
  iya_oidc_login_free(login);
  iya_oidc_txn_free(txn);
  iya_oidc_rp_free(rp);
  iya_oidc_string_free(cfg);
  iya_test_provider_free(stub);
  return 0;
}

int TestPostAndPrivateKeyJWT(void) {
  iya_test_provider *stub = iya_test_provider_start();
  char *posted_cfg = iya_test_provider_config(stub, "{\"tokenEndpointAuthMethod\":\"client_secret_post\"}");
  char *jwt_cfg = iya_test_provider_config_jwt(stub);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_rp *posted = NULL;
  if (iya_oidc_create(posted_cfg, &posted, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login *login = NULL;
  Pair query[16];
  if (sign_in(posted, &login, NULL, query, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_oidc_login_subject(login), "user-1") != 0) return failed("post");
  iya_oidc_login_free(login);
  iya_oidc_rp_free(posted);
  memset(&err, 0, sizeof err);
  iya_oidc_rp *jwt = NULL;
  if (iya_oidc_create(jwt_cfg, &jwt, &err) != IYA_OIDC_OK) return failed(err.message);
  login = NULL;
  memset(&err, 0, sizeof err);
  if (sign_in(jwt, &login, NULL, query, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_oidc_login_subject(login), "user-1") != 0) return failed("jwt");
  iya_oidc_login_free(login);
  iya_oidc_rp_free(jwt);
  iya_oidc_string_free(posted_cfg);
  iya_oidc_string_free(jwt_cfg);
  iya_test_provider_free(stub);
  return 0;
}

static int write_file(const char *path, const char *text) {
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  fputs(text, f);
  fclose(f);
  return 0;
}

int TestReadsConfigurationFileNames(void) {
  char dir[] = "/tmp/oidc-c-XXXXXX";
  if (!mkdtemp(dir)) return failed("mkdtemp");
  char secret_path[512];
  snprintf(secret_path, sizeof secret_path, "%s/secret", dir);
  if (write_file(secret_path, "from-file\n") != 0) return failed("secret");
  setenv("OIDC_TEST_SECRET", "from-env", 1);
  char raw[1024];
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"%s\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\","
           "\"scopes\":[\"openid\",\"profile\",\"email\",\"offline_access\",\"ssf.read\",\"ssf.manage\"]}",
           "oidc-caep-risc-demo");
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  char *env = NULL;
  if (iya_oidc_resolve_config(raw, dir, &env, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!text_is(env, "clientId", "oidc-caep-risc-demo") || !text_is(env, "clientSecret", "from-env") ||
      !text_is(env, "issuer", "https://localhost:8081") ||
      !text_is(env, "scopes", "openid profile email offline_access ssf.read ssf.manage") ||
      !text_is(env, "tokenEndpointAuthMethod", "client_secret_basic"))
    return failed(env);
  iya_oidc_string_free(env);
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"file:secret\",\"redirectUri\":\"http://localhost:3000/callback\","
           "\"scopes\":[\"openid\",\"profile\",\"email\",\"offline_access\",\"ssf.read\",\"ssf.manage\"]}");
  memset(&err, 0, sizeof err);
  char *got = NULL;
  if (iya_oidc_resolve_config(raw, dir, &got, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!text_is(got, "clientSecret", "from-file")) return failed(got);
  iya_oidc_string_free(got);
  const char *chain = "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n";
  char ca_path[512];
  snprintf(ca_path, sizeof ca_path, "%s/ca.pem", dir);
  if (write_file(ca_path, chain) != 0) return failed("ca");
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\",\"tlsCa\":\"ca.pem\"}");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) != IYA_OIDC_OK || !text_is(got, "tlsCa", chain))
    return failed(err.message[0] ? err.message : got);
  iya_oidc_string_free(got);
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\",\"tlsCa\":\"file:ca.pem\"}");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) != IYA_OIDC_OK || !text_is(got, "tlsCa", chain))
    return failed(err.message[0] ? err.message : "file ca");
  iya_oidc_string_free(got);
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\","
           "\"tlsCa\":\"-----BEGIN CERTIFICATE-----\\nchain\\n-----END CERTIFICATE-----\\n\"}");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!text_is(got, "tlsCa", "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----")) return failed(got);
  iya_oidc_string_free(got);
  setenv("OIDC_TEST_CA", chain, 1);
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\",\"tlsCa\":\"env:OIDC_TEST_CA\"}");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) != IYA_OIDC_OK || !text_is(got, "tlsCa", chain))
    return failed(err.message[0] ? err.message : got);
  iya_oidc_string_free(got);
  unsetenv("OIDC_TEST_CA");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) != IYA_OIDC_OK || !kind_is(got, "tlsCa", 0))
    return failed(err.message[0] ? err.message : got);
  iya_oidc_string_free(got);
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\",\"tlsCa\":\"missing.pem\"}");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) != IYA_OIDC_OK || !kind_is(got, "tlsCa", 0))
    return failed(err.message[0] ? err.message : "missing ca");
  iya_oidc_string_free(got);
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\","
           "\"tokenEndpointAuthMethod\":\"none\"}");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) == IYA_OIDC_OK || !contains(err.message, "public client"))
    return failed(err.message);
  snprintf(raw, sizeof raw,
           "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
           "\"clientSecret\":\"env:OIDC_TEST_SECRET\",\"redirectUri\":\"http://localhost:3000/callback\","
           "\"scopes\":\"profile email\"}");
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(raw, dir, &got, &err) == IYA_OIDC_OK || !contains(err.message, "openid"))
    return failed(err.message);
  return 0;
}

int TestSignalsFlag(void) {
  char dir[] = "/tmp/oidc-s-XXXXXX";
  if (!mkdtemp(dir)) return failed("mkdtemp");
  const char *file =
      "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
      "\"clientSecret\":\"secret\",\"redirectUri\":\"http://localhost:3000/callback\","
      "\"ssf\":{\"transmitter\":\"https://localhost:8081/\",\"pollIntervalMs\":3000}}";
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  char *omitted = NULL;
  if (iya_oidc_resolve_config(file, dir, &omitted, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!text_is(omitted, "scopes", IYA_OIDC_DEFAULT_SCOPES) || !kind_is(omitted, "signals", 0)) return failed(omitted);
  if (!text_is(omitted, "ssf.transmitter", "https://localhost:8081") || !text_is(omitted, "ssf.pollIntervalMs", "3000"))
    return failed(omitted);
  iya_oidc_string_free(omitted);
  const char *explicit_src =
      "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
      "\"clientSecret\":\"secret\",\"redirectUri\":\"http://localhost:3000/callback\",\"signals\":true,"
      "\"scopes\":\"openid profile email offline_access ssf.read ssf.manage\","
      "\"ssf\":{\"transmitter\":\"https://localhost:8081/\",\"pollIntervalMs\":3000}}";
  char *explicit = NULL;
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(explicit_src, dir, &explicit, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!text_is(explicit, "scopes", IYA_OIDC_DEFAULT_SCOPES) || !kind_is(explicit, "signals", 0)) return failed(explicit);
  if (!text_is(explicit, "ssf.transmitter", "https://localhost:8081") || !text_is(explicit, "ssf.pollIntervalMs", "3000"))
    return failed(explicit);
  iya_oidc_string_free(explicit);
  const char *listed_src =
      "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
      "\"clientSecret\":\"secret\",\"redirectUri\":\"http://localhost:3000/callback\",\"signals\":false,"
      "\"scopes\":\"openid profile email offline_access ssf.read ssf.manage\","
      "\"ssf\":{\"transmitter\":\"not-a-url\"}}";
  char *listed = NULL;
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(listed_src, dir, &listed, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!kind_is(listed, "signals", 2) || !kind_is(listed, "ssf", 0) ||
      !text_is(listed, "scopes", "openid profile email offline_access"))
    return failed(listed);
  if (contains(listed, "ssf.read") || contains(listed, "ssf.manage")) return failed(listed);
  iya_oidc_string_free(listed);
  const char *defaults_src =
      "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
      "\"clientSecret\":\"secret\",\"redirectUri\":\"http://localhost:3000/callback\",\"signals\":false,"
      "\"ssf\":{\"transmitter\":\"https://localhost:8081/\",\"pollIntervalMs\":3000}}";
  char *defaults = NULL;
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(defaults_src, dir, &defaults, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!kind_is(defaults, "signals", 2) || !kind_is(defaults, "ssf", 0) ||
      !text_is(defaults, "scopes", "openid profile email offline_access") || !contains(defaults, "openid"))
    return failed(defaults);
  iya_oidc_string_free(defaults);
  const char *dropped =
      "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
      "\"clientSecret\":\"secret\",\"redirectUri\":\"http://localhost:3000/callback\",\"signals\":false,"
      "\"scopes\":\"ssf.read ssf.manage\",\"ssf\":{\"transmitter\":\"https://localhost:8081/\",\"pollIntervalMs\":3000}}";
  char *unused = NULL;
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(dropped, dir, &unused, &err) == IYA_OIDC_OK || !contains(err.message, "openid"))
    return failed(err.message);
  const char *bad =
      "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\",\"client_id\":\"oidc-caep-risc-demo\","
      "\"clientSecret\":\"secret\",\"redirectUri\":\"http://localhost:3000/callback\",\"signals\":\"no\","
      "\"ssf\":{\"transmitter\":\"https://localhost:8081/\",\"pollIntervalMs\":3000}}";
  memset(&err, 0, sizeof err);
  if (iya_oidc_resolve_config(bad, dir, &unused, &err) == IYA_OIDC_OK) return failed("signals accepted");
  if (err.code != IYA_OIDC_ERR_CONFIG || strcmp(err.message, "signals must be true or false") != 0) return failed(err.message);
  if (strcmp(iya_oidc_error_name(err.code), "config") != 0) return failed("code name");
  return 0;
}

int TestVerifiesASETAgainstTheJWKS(void) {
  char *jwks = iya_test_ssf_jwks();
  char *token = iya_test_sign_set("{\"a\":1}", NULL, 0);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  char *payload = NULL;
  if (iya_oidc_verify_set(token, jwks, &payload, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!text_is(payload, "a", "1")) return failed(payload);
  iya_oidc_string_free(payload);
  iya_oidc_string_free(token);
  char *other = iya_test_sign_set("{\"a\":1}", NULL, 1);
  memset(&err, 0, sizeof err);
  if (iya_oidc_verify_set(other, jwks, &payload, &err) == IYA_OIDC_OK || !contains(err.message, "does not verify"))
    return failed(err.message);
  iya_oidc_string_free(other);
  char *kid = iya_test_sign_set("{\"a\":1}", "{\"alg\":\"RS256\",\"kid\":\"nope\"}", 0);
  memset(&err, 0, sizeof err);
  if (iya_oidc_verify_set(kid, jwks, &payload, &err) == IYA_OIDC_OK || !contains(err.message, "kid nope"))
    return failed(err.message);
  iya_oidc_string_free(kid);
  char *none = iya_test_sign_set("{\"a\":1}", "{\"alg\":\"none\"}", 0);
  memset(&err, 0, sizeof err);
  if (iya_oidc_verify_set(none, jwks, &payload, &err) == IYA_OIDC_OK || !contains(err.message, "does not verify"))
    return failed(err.message);
  iya_oidc_string_free(none);
  iya_oidc_string_free(jwks);
  return 0;
}

int TestReadsSubjectForms(void) {
  if (strcmp(iya_oidc_event_type("sessionRevoked"),
             "https://schemas.openid.net/secevent/caep/event-type/session-revoked") != 0)
    return failed("sessionRevoked");
  if (strcmp(iya_oidc_event_type("credentialCompromise"),
             "https://schemas.openid.net/secevent/risc/event-type/credential-compromise") != 0)
    return failed("credentialCompromise");
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  char person[128], email[128], idp[128];
  int count = -1;
  const char *complex =
      "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"https://i\",\"sub\":\"urn:uuid:a\"},"
      "\"session\":{\"format\":\"opaque\",\"id\":\"S1\"}}";
  if (iya_oidc_subject_of(complex, "https://i", person, sizeof person, email, sizeof email, idp, sizeof idp, &count,
                          &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (strcmp(person, "urn:uuid:a") != 0 || strcmp(idp, "S1") != 0 || count != 2) return failed("complex");
  count = -1;
  person[0] = email[0] = idp[0] = '\0';
  if (iya_oidc_subject_of("{\"format\":\"iss_sub\",\"iss\":\"https://other\",\"sub\":\"urn:uuid:a\"}", "https://i",
                          person, sizeof person, email, sizeof email, idp, sizeof idp, &count, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (count != 0) return failed("other issuer");
  if (iya_oidc_subject_of("{\"format\":\"email\",\"email\":\"A@x.com\"}", "https://i", person, sizeof person, email,
                          sizeof email, idp, sizeof idp, &count, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (strcmp(email, "A@x.com") != 0 || count != 1) return failed(email);
  return 0;
}

typedef struct {
  pthread_mutex_t mu;
  char ended[4][64];
  int ended_n;
  int ended_len[4];
  char types[8][256];
  int ended_flag[8];
  int seen;
} Cap;

static void on_end(const char **ids, size_t count, void *user) {
  Cap *cap = user;
  pthread_mutex_lock(&cap->mu);
  if (cap->ended_n < 4) {
    cap->ended_len[cap->ended_n] = (int)count;
    if (count > 0 && ids && ids[0]) snprintf(cap->ended[cap->ended_n], sizeof cap->ended[0], "%s", ids[0]);
    cap->ended_n++;
  }
  pthread_mutex_unlock(&cap->mu);
}

static void on_event(const char *type, int ended, void *user) {
  Cap *cap = user;
  pthread_mutex_lock(&cap->mu);
  if (cap->seen < 8) {
    snprintf(cap->types[cap->seen], sizeof cap->types[0], "%s", type ? type : "");
    cap->ended_flag[cap->seen] = ended;
    cap->seen++;
  }
  pthread_mutex_unlock(&cap->mu);
}

int TestPollsAndEndsOnlyTheNamedSession(void) {
  iya_test_tx *stub = iya_test_tx_start();
  if (!stub) return failed("transmitter");
  Cap cap;
  memset(&cap, 0, sizeof cap);
  pthread_mutex_init(&cap.mu, NULL);
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  iya_oidc_receiver *rx = NULL;
  if (iya_oidc_receiver_new(iya_test_tx_url(stub), on_end, &cap, "Bearer app-token", 60000, &rx, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (iya_oidc_receiver_on(rx, "*", on_event, &cap, &err) != IYA_OIDC_OK) return failed(err.message);
  if (iya_oidc_receiver_start(rx, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_receiver_stop(rx);
  if (iya_test_tx_created(stub) != 1) return failed("created");
  if (strcmp(iya_test_tx_authorization(stub), "Bearer app-token") != 0) return failed(iya_test_tx_authorization(stub));
  if (strcmp(iya_oidc_receiver_stream_id(rx), "s1") != 0) return failed(iya_oidc_receiver_stream_id(rx));
  if (iya_oidc_receiver_track(rx, "L-a1", "urn:uuid:alice", "alice@example.com", "IDP-A1", &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (iya_oidc_receiver_track(rx, "L-a2", "urn:uuid:alice", "alice@example.com", "IDP-A2", &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (iya_oidc_receiver_track(rx, "L-b1", "urn:uuid:bob", "bob@example.com", "IDP-B1", &err) != IYA_OIDC_OK)
    return failed(err.message);
  char sub[512];
  snprintf(sub, sizeof sub,
           "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:alice\"},"
           "\"session\":{\"format\":\"opaque\",\"id\":\"IDP-A1\"}}",
           iya_test_tx_url(stub));
  char *revoked = iya_test_tx_deliver(stub, iya_oidc_event_type("sessionRevoked"), sub, NULL, 0);
  snprintf(sub, sizeof sub, "{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"urn:uuid:bob\"}", iya_test_tx_url(stub));
  iya_oidc_string_free(iya_test_tx_deliver(stub, iya_oidc_event_type("credentialChange"), sub,
                                           "{\"credential_type\":\"password\"}", 0));
  int more = 0;
  memset(&err, 0, sizeof err);
  if (iya_oidc_receiver_poll_once(rx, &more, &err) != IYA_OIDC_OK) return failed(err.message);
  if (cap.ended_n != 1 || cap.ended_len[0] != 1 || strcmp(cap.ended[0], "L-a1") != 0) return failed("ended");
  if (cap.seen != 2 || !cap.ended_flag[0] ||
      strcmp(cap.types[1], iya_oidc_event_type("credentialChange")) != 0 || cap.ended_flag[1])
    return failed("seen");
  memset(&err, 0, sizeof err);
  if (iya_oidc_receiver_poll_once(rx, &more, &err) != IYA_OIDC_OK) return failed(err.message);
  if (iya_test_tx_ack_count(stub) == 0 || strcmp(iya_test_tx_ack_at(stub, 0), revoked) != 0) return failed("acked");
  int count = 0;
  int nack = iya_test_tx_ack_count(stub);
  for (int i = 0; i < nack; i++)
    if (strcmp(iya_test_tx_ack_at(stub, i), revoked) == 0) count++;
  if (count != 1) return failed("revoked count");
  char *bad = iya_test_tx_deliver(stub, iya_oidc_event_type("accountDisabled"),
                                  "{\"format\":\"email\",\"email\":\"alice@example.com\"}", NULL, 1);
  memset(&err, 0, sizeof err);
  if (iya_oidc_receiver_poll_once(rx, &more, &err) != IYA_OIDC_OK) return failed(err.message);
  memset(&err, 0, sizeof err);
  if (iya_oidc_receiver_poll_once(rx, &more, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_tx_err(stub, bad), "invalid_key") != 0) return failed(iya_test_tx_err(stub, bad));
  memset(&err, 0, sizeof err);
  if (iya_oidc_receiver_verify(rx, "abc", &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_tx_verify_state(stub), "abc") != 0 || iya_test_tx_verify_status(stub) != 204) return failed("verify");
  iya_oidc_receiver_stop(rx);
  iya_oidc_string_free(revoked);
  iya_oidc_string_free(bad);
  iya_oidc_receiver_free(rx);
  iya_test_tx_free(stub);
  pthread_mutex_destroy(&cap.mu);
  return 0;
}

int TestOidcErrorIsExported(void) {
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  const char *bad =
      "{\"signals\":\"no\",\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\","
      "\"client_id\":\"oidc-caep-risc-demo\",\"clientSecret\":\"secret\",\"redirectUri\":\"http://localhost:3000/callback\"}";
  char *unused = NULL;
  int rc = iya_oidc_resolve_config(bad, "/tmp", &unused, &err);
  if (rc != IYA_OIDC_ERR_CONFIG) return failed("code");
  if (strcmp(err.message, "signals must be true or false") != 0) return failed(err.message);
  if (strcmp(iya_oidc_error_name(rc), "config") != 0) return failed("name");
  if (err.code != IYA_OIDC_ERR_CONFIG) return failed("struct");
  return 0;
}
