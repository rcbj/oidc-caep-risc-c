// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya_oidc.h"
#include "stub.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

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

/* Issue #15: DPoP, acr, PAR required, the ID token algorithms, typ and at_hash,
   one set of rules for every way of creating a client, and the session cache. */

static iya_oidc_rp *rp_from(iya_test_provider *stub, const char *overrides, iya_oidc_error *err) {
  char *cfg = iya_test_provider_config(stub, overrides);
  iya_oidc_rp *rp = NULL;
  memset(err, 0, sizeof *err);
  int rc = iya_oidc_create(cfg, &rp, err);
  iya_oidc_string_free(cfg);
  return rc == IYA_OIDC_OK ? rp : NULL;
}

static int sign_in_with(iya_oidc_rp *rp, const char *acr, const char *session_id, iya_oidc_login **login,
                        iya_oidc_txn **txn_out, iya_oidc_error *err) {
  iya_oidc_txn *txn = NULL;
  memset(err, 0, sizeof *err);
  int rc = iya_oidc_authorize_with(rp, NULL, NULL, acr, &txn, err);
  if (rc != IYA_OIDC_OK) return rc;
  int status = 0;
  char location[8192];
  location[0] = '\0';
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0 || location[0] == '\0') {
    snprintf(err->message, sizeof err->message, "the provider did not redirect (%d)", status);
    iya_oidc_txn_free(txn);
    return IYA_OIDC_ERR_PROTOCOL;
  }
  Pair query[16];
  int n = query_of(location, query, 16);
  const char *keys[16];
  const char *vals[16];
  for (int i = 0; i < n; i++) {
    keys[i] = query[i].key;
    vals[i] = query[i].val;
  }
  rc = iya_oidc_complete_session(rp, keys, vals, (size_t)n, txn, session_id, login, err);
  if (txn_out) *txn_out = txn;
  else iya_oidc_txn_free(txn);
  return rc;
}

static int expect_refused(int rc, const iya_oidc_error *err, const char *part) {
  if (rc == IYA_OIDC_OK) {
    fprintf(stderr, "FAIL: accepted, expected a refusal naming %s\n", part);
    return 1;
  }
  if (!contains(err->message, part)) {
    fprintf(stderr, "FAIL: refusal \"%s\" does not name %s\n", err->message, part);
    return 1;
  }
  return 0;
}

int TestDPoPProofsOnEveryRequest(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_test_provider_set_dpop(stub, 1);
  iya_test_provider_set_par(stub, 1);
  iya_oidc_error err;
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  if (iya_oidc_dpop(rp) != 1) return failed("dpop auto did not turn on");
  char jkt[128];
  snprintf(jkt, sizeof jkt, "%s", iya_oidc_dpop_jkt(rp));
  if (strlen(jkt) != 43) return failed(jkt);
  iya_oidc_login *login = NULL;
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "par.proof"), "valid") != 0) return failed(iya_test_provider_note(stub, "par.proof"));
  if (strcmp(iya_test_provider_note(stub, "par.dpop_jkt"), jkt) != 0) return failed("dpop_jkt in the PAR body");
  if (strcmp(iya_test_provider_note(stub, "authorize.pushed"), "yes") != 0) return failed("pushed");
  if (strcmp(iya_test_provider_note(stub, "token.authorization_code.proof"), "valid") != 0)
    return failed(iya_test_provider_note(stub, "token.authorization_code.proof"));
  if (strcmp(iya_test_provider_note(stub, "token.authorization_code.jkt"), jkt) != 0) return failed("token jkt");
  if (strcmp(iya_oidc_login_token_type(login), "DPoP") != 0) return failed(iya_oidc_login_token_type(login));
  char *sub = NULL;
  if (iya_oidc_userinfo(rp, iya_oidc_login_access_token(login), "user-1", &sub, &err) != IYA_OIDC_OK)
    return failed(err.message);
  iya_oidc_string_free(sub);
  if (strcmp(iya_test_provider_note(stub, "userinfo.scheme"), "DPoP") != 0) return failed("userinfo scheme");
  if (strcmp(iya_test_provider_note(stub, "userinfo.proof"), "valid") != 0)
    return failed(iya_test_provider_note(stub, "userinfo.proof"));
  /* htu leaves out the query and the fragment. */
  char url[512];
  snprintf(url, sizeof url, "%s/userinfo?x=1#frag", iya_test_provider_url(stub));
  int status = 0;
  char *body = NULL;
  if (iya_oidc_resource_request(rp, "GET", url, iya_oidc_login_access_token(login), NULL, NULL, &status, &body, &err) !=
      IYA_OIDC_OK)
    return failed(err.message);
  if (status != 200 || !contains(body, "user-1")) return failed(body);
  iya_oidc_string_free(body);
  iya_oidc_login *refreshed = NULL;
  if (iya_oidc_refresh(rp, iya_oidc_login_refresh_token(login), "", login, &refreshed, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "token.refresh_token.proof"), "valid") != 0) return failed("refresh proof");
  if (strcmp(iya_oidc_login_token_type(refreshed), "DPoP") != 0) return failed("refresh token_type");
  char *cc = NULL;
  if (iya_oidc_client_credentials(rp, "ssf.manage", &cc, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "token.client_credentials.proof"), "valid") != 0) return failed("cc proof");
  iya_oidc_string_free(cc);
  iya_oidc_login_free(refreshed);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  /* Without PAR, dpop_jkt is on the authorization URL. */
  iya_test_provider_set_par(stub, 0);
  rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  iya_oidc_txn *txn = NULL;
  if (sign_in_with(rp, NULL, NULL, &login, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!contains(iya_oidc_txn_url(txn), "dpop_jkt=")) return failed(iya_oidc_txn_url(txn));
  if (strcmp(iya_test_provider_note(stub, "authorize.dpop_jkt"), iya_oidc_dpop_jkt(rp)) != 0) return failed("url jkt");
  iya_oidc_txn_free(txn);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}

static char *p256_pem(void) {
  EVP_PKEY *key = EVP_EC_gen("P-256");
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
  char *data = NULL;
  long len = BIO_get_mem_data(bio, &data);
  char *out = malloc((size_t)len + 1);
  memcpy(out, data, (size_t)len);
  out[len] = '\0';
  BIO_free(bio);
  EVP_PKEY_free(key);
  return out;
}

static void json_escape(const char *in, char *out, size_t n) {
  size_t o = 0;
  for (size_t i = 0; in[i] && o + 3 < n; i++) {
    if (in[i] == '\n') {
      out[o++] = '\\';
      out[o++] = 'n';
    } else {
      out[o++] = in[i];
    }
  }
  out[o] = '\0';
}

int TestDPoPModes(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_oidc_error err;
  /* auto with nothing advertised: no proofs, Bearer tokens. */
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp || iya_oidc_dpop(rp) != 0 || iya_oidc_dpop_jkt(rp)[0]) return failed("auto without metadata");
  iya_oidc_login *login = NULL;
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "token.authorization_code.proof"), "none") != 0) return failed("proof sent");
  if (strcmp(iya_oidc_login_token_type(login), "Bearer") != 0) return failed("Bearer");
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  /* always fails at creation when the provider advertises nothing, or no ES256. */
  if (rp_from(stub, "{\"dpop\":\"always\"}", &err) || expect_refused(1, &err, "dpop_signing_alg_values_supported"))
    return failed("always without metadata");
  iya_test_provider_set_dpop(stub, 2);
  if (rp_from(stub, "{\"dpop\":\"always\"}", &err) || expect_refused(1, &err, "ES256")) return failed("always without ES256");
  rp = rp_from(stub, NULL, &err);
  if (!rp || iya_oidc_dpop(rp) != 0) return failed("auto without ES256");
  iya_oidc_rp_free(rp);
  /* never sends no proofs even when the provider offers DPoP. */
  iya_test_provider_set_dpop(stub, 1);
  rp = rp_from(stub, "{\"dpop\":\"never\"}", &err);
  if (!rp || iya_oidc_dpop(rp) != 0) return failed("never");
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "token.authorization_code.proof"), "none") != 0) return failed("never proofed");
  if (iya_test_provider_note(stub, "authorize.dpop_jkt")[0] != '\0') return failed("never sent dpop_jkt");
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  rp = rp_from(stub, "{\"dpop\":\"always\"}", &err);
  if (!rp || iya_oidc_dpop(rp) != 1) return failed(err.message);
  iya_oidc_rp_free(rp);
  if (rp_from(stub, "{\"dpop\":\"sometimes\"}", &err) || err.code != IYA_OIDC_ERR_CONFIG ||
      !contains(err.message, "dpop must be auto, always, or never"))
    return failed(err.message);
  /* dpopKey names a key the application keeps; two clients with it share a thumbprint. */
  char *pem = p256_pem();
  char escaped[2048];
  json_escape(pem, escaped, sizeof escaped);
  char over[2400];
  snprintf(over, sizeof over, "{\"dpopKey\":\"%s\"}", escaped);
  iya_oidc_rp *one = rp_from(stub, over, &err);
  if (!one) return failed(err.message);
  iya_oidc_rp *two = rp_from(stub, over, &err);
  if (!two) return failed(err.message);
  char first[128];
  snprintf(first, sizeof first, "%s", iya_oidc_dpop_jkt(one));
  if (strcmp(first, iya_oidc_dpop_jkt(two)) != 0) return failed("dpopKey thumbprints differ");
  rp = rp_from(stub, NULL, &err);
  if (!rp || strcmp(first, iya_oidc_dpop_jkt(rp)) == 0) return failed("a generated key equals dpopKey");
  if (sign_in_with(one, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "token.authorization_code.jkt"), first) != 0) return failed("dpopKey jkt");
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  iya_oidc_rp_free(one);
  iya_oidc_rp_free(two);
  free(pem);
  iya_test_provider_free(stub);
  return 0;
}

typedef struct {
  int ended;
} EndCount;

static void count_end(const char **ids, size_t count, void *user) {
  (void)ids;
  ((EndCount *)user)->ended += (int)count;
}

int TestDPoPNonceAndTransmitterCalls(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_test_provider_set_dpop(stub, 1);
  iya_test_provider_set_dpop_nonce(stub, 1);
  iya_oidc_error err;
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  if (sign_in_with(rp, NULL, "L-a1", &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "token.authorization_code.nonce_challenges"), "1") != 0)
    return failed("one use_dpop_nonce answer, then the retry");
  if (iya_test_provider_note(stub, "token.authorization_code.nonce")[0] == '\0') return failed("nonce in the proof");
  iya_oidc_login *refreshed = NULL;
  if (iya_oidc_refresh(rp, iya_oidc_login_refresh_token(login), "", login, &refreshed, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (iya_test_provider_note(stub, "token.refresh_token.nonce_challenges")[0] != '\0')
    return failed("the remembered nonce was not sent");
  iya_oidc_login_free(refreshed);
  /* The SSF transmitter: a DPoP-bound client-credentials token, a proof with ath on
     every call, and a 401 use_dpop_nonce answered once. */
  iya_test_tx *tx = iya_test_tx_start();
  iya_test_tx_set_dpop_nonce(tx, 1);
  EndCount ends = {0};
  iya_oidc_receiver *rx = NULL;
  if (iya_oidc_receiver_new_for_rp(iya_test_tx_url(tx), count_end, &ends, rp, NULL, &rx, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (iya_oidc_receiver_start(rx, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_receiver_stop(rx);
  if (iya_test_tx_created(tx) != 1) return failed("stream not created");
  if (iya_test_tx_dpop_challenges(tx) != 1) return failed("transmitter nonce challenge");
  if (iya_test_tx_dpop_proofs(tx) < 2) return failed("transmitter proofs");
  if (!contains(iya_test_tx_authorization(tx), "DPoP cc-token")) return failed(iya_test_tx_authorization(tx));
  /* A session-revoked for a tracked session also clears its cache entry. */
  if (iya_oidc_receiver_track(rx, "L-a1", "user-1", "user-1@example.com", "IDP-1", &err) != IYA_OIDC_OK)
    return failed(err.message);
  char *token = NULL;
  if (iya_oidc_session_access_token(rp, "L-a1", &token, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_string_free(token);
  char sub[512];
  snprintf(sub, sizeof sub,
           "{\"format\":\"complex\",\"user\":{\"format\":\"iss_sub\",\"iss\":\"%s\",\"sub\":\"user-1\"},"
           "\"session\":{\"format\":\"opaque\",\"id\":\"IDP-1\"}}",
           iya_test_tx_url(tx));
  iya_oidc_string_free(iya_test_tx_deliver(tx, iya_oidc_event_type("sessionRevoked"), sub, NULL, 0));
  int more = 0;
  if (iya_oidc_receiver_poll_once(rx, &more, &err) != IYA_OIDC_OK) return failed(err.message);
  if (ends.ended != 1) return failed("session-revoked did not end L-a1");
  memset(&err, 0, sizeof err);
  if (expect_refused(iya_oidc_session_access_token(rp, "L-a1", &token, NULL, &err), &err, "no signed-in session"))
    return 1;
  iya_oidc_receiver_free(rx);
  iya_test_tx_free(tx);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}

int TestTokenTypeMustMatchTheProof(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_test_provider_set_dpop(stub, 1);
  iya_oidc_error err;
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_test_provider_set_token_type(stub, "Bearer");
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "not DPoP")) return 1;
  iya_test_provider_set_token_type(stub, "dpop");
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  rp = rp_from(stub, "{\"dpop\":\"never\"}", &err);
  if (!rp) return failed(err.message);
  iya_test_provider_set_token_type(stub, "DPoP");
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "not Bearer")) return 1;
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}

int TestAcrIsEnforced(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_oidc_error err;
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_oidc_txn *txn = NULL;
  if (expect_refused(sign_in_with(rp, "urn:x urn:y", NULL, &login, &txn, &err), &err, "no acr")) return 1;
  if (strcmp(iya_oidc_txn_acr_values(txn), "urn:x urn:y") != 0) return failed("acr_values kept in the transaction");
  if (strcmp(iya_test_provider_note(stub, "authorize.acr_values"), "urn:x urn:y") != 0) return failed("acr_values sent");
  iya_oidc_txn_free(txn);
  iya_test_provider_set_acr(stub, "urn:z");
  if (expect_refused(sign_in_with(rp, "urn:x urn:y", NULL, &login, NULL, &err), &err, "not one of the requested"))
    return 1;
  iya_test_provider_set_acr(stub, "urn:y");
  if (sign_in_with(rp, "urn:x urn:y", NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_oidc_login_acr(login), "urn:y") != 0) return failed("acr");
  /* The refresh path does not check acr again. */
  iya_test_provider_set_acr(stub, "");
  iya_oidc_login *refreshed = NULL;
  if (iya_oidc_refresh(rp, iya_oidc_login_refresh_token(login), "", login, &refreshed, &err) != IYA_OIDC_OK)
    return failed(err.message);
  iya_oidc_login_free(refreshed);
  iya_oidc_login_free(login);
  /* Not requested: no acr is fine. */
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  /* The setting, as a list. */
  rp = rp_from(stub, "{\"acrValues\":[\"urn:gold\"]}", &err);
  if (!rp) return failed(err.message);
  iya_test_provider_set_acr(stub, "urn:silver");
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "not one of the requested")) return 1;
  iya_test_provider_set_acr(stub, "urn:gold");
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}

int TestPARRequiredByTheProvider(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_test_provider_set_require_par(stub, 1);
  iya_oidc_error err;
  if (rp_from(stub, NULL, &err) || expect_refused(1, &err, "pushed_authorization_request_endpoint"))
    return failed("required without an endpoint");
  iya_test_provider_set_par(stub, 1);
  if (rp_from(stub, "{\"par\":\"never\"}", &err) || expect_refused(1, &err, "par is never"))
    return failed("par never while required");
  char *meta = iya_test_provider_metadata(stub);
  if (!kind_is(meta, "require_pushed_authorization_requests", 3)) return failed(meta);
  iya_oidc_string_free(meta);
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_oidc_txn *txn = NULL;
  if (sign_in_with(rp, NULL, NULL, &login, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!contains(iya_oidc_txn_url(txn), "request_uri=") || contains(iya_oidc_txn_url(txn), "code_challenge"))
    return failed(iya_oidc_txn_url(txn));
  iya_oidc_txn_free(txn);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}

int TestIdTokenAlgorithms(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_oidc_error err;
  memset(&err, 0, sizeof err);
  char *resolved = NULL;
  if (iya_oidc_resolve_config("{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\","
                              "\"client_id\":\"c\",\"clientSecret\":\"s\",\"redirectUri\":\"http://localhost:3000/cb\"}",
                              "/tmp", &resolved, &err) != IYA_OIDC_OK)
    return failed(err.message);
  if (!text_is(resolved, "idTokenSigningAlgs", "[\"RS256\"]") || !text_is(resolved, "dpop", "auto") ||
      !text_is(resolved, "par", "auto") || !kind_is(resolved, "requireIdTokenTypAndAtHash", 3) ||
      !text_is(resolved, "clockToleranceSec", "30") || !text_is(resolved, "maxIdTokenAgeSec", "600"))
    return failed(resolved);
  iya_oidc_string_free(resolved);
  /* RS256 only by default: a provider that does not advertise it cannot be used. */
  iya_test_provider_set_algs(stub, "[\"ES256\",\"PS256\"]");
  if (rp_from(stub, NULL, &err) || expect_refused(1, &err, "none of the accepted ID token algorithms (RS256)"))
    return failed("RS256 not advertised");
  /* The list is narrowed to what the provider advertises; empty fails, and a pin
     the provider does not advertise fails. */
  iya_test_provider_set_algs(stub, "[\"RS256\",\"HS256\"]");
  iya_oidc_rp *narrowed = rp_from(stub, "{\"idTokenSigningAlgs\":[\"RS256\",\"ES256\"]}", &err);
  if (!narrowed) return failed(err.message);
  iya_oidc_login *ok_login = NULL;
  if (sign_in_with(narrowed, NULL, NULL, &ok_login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(ok_login);
  iya_oidc_rp_free(narrowed);
  if (rp_from(stub, "{\"idTokenSigningAlgs\":[\"ES256\",\"PS256\"]}", &err) ||
      expect_refused(1, &err, "none of the accepted ID token algorithms"))
    return failed("nothing left");
  if (rp_from(stub, "{\"idTokenSignedResponseAlg\":\"ES256\"}", &err) ||
      expect_refused(1, &err, "does not advertise id_token alg ES256"))
    return failed("pinned ES256");
  /* none is never accepted, as the list or as the pin. */
  if (rp_from(stub, "{\"idTokenSigningAlgs\":[\"none\"]}", &err) || expect_refused(1, &err, "none is never accepted"))
    return failed("none listed");
  if (rp_from(stub, "{\"idTokenSignedResponseAlg\":\"none\"}", &err) || expect_refused(1, &err, "none is never accepted"))
    return failed("none pinned");
  /* A symmetric algorithm only when named; RS256 tokens are then refused. */
  iya_oidc_rp *rp = rp_from(stub, "{\"idTokenSigningAlgs\":[\"HS256\"]}", &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "signed with RS256")) return 1;
  iya_oidc_rp_free(rp);
  /* The default accepts the provider's RS256 tokens although HS256 is advertised. */
  rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  rp = rp_from(stub, "{\"idTokenSigningAlgs\":[\"HS256\",\"RS256\"],\"idTokenSignedResponseAlg\":\"RS256\"}", &err);
  if (!rp) return failed(err.message);
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}

int TestTypAndAtHashAreRequired(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_oidc_error err;
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_test_provider_set_omit(stub, 1);
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "typ")) return 1;
  iya_test_provider_set_omit(stub, 2);
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "no at_hash")) return 1;
  iya_oidc_rp_free(rp);
  rp = rp_from(stub, "{\"requireIdTokenTypAndAtHash\":false}", &err);
  if (!rp) return failed(err.message);
  iya_test_provider_set_omit(stub, 3);
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  /* Relaxed still checks them when present. */
  iya_test_provider_set_bad_at_hash(stub, 1);
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "at_hash")) return 1;
  iya_oidc_rp_free(rp);
  if (rp_from(stub, "{\"requireIdTokenTypAndAtHash\":\"yes\"}", &err) ||
      expect_refused(1, &err, "requireIdTokenTypAndAtHash must be true or false"))
    return failed("setting type");
  iya_test_provider_free(stub);
  return 0;
}

int TestCreateAppliesTheSameRules(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_oidc_error err;
  /* No defaults in the configuration: iya_oidc_create supplies them. */
  const char *bare = "{\"par\":null,\"clockToleranceSec\":null,\"maxIdTokenAgeSec\":null,\"privateKeyAlg\":null}";
  iya_oidc_rp *rp = rp_from(stub, bare, &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  iya_test_provider_set_iat_offset(stub, 20);
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  iya_test_provider_set_iat_offset(stub, 120);
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "iat is in the future")) return 1;
  iya_test_provider_set_exp(stub, (long long)time(NULL) - 1200);
  if (expect_refused(sign_in_with(rp, NULL, NULL, &login, NULL, &err), &err, "exp")) return 1;
  /* A per-request redirect URI is held to the rule. */
  iya_oidc_txn *txn = NULL;
  memset(&err, 0, sizeof err);
  if (expect_refused(iya_oidc_authorize_with(rp, "http://app.example/cb", NULL, NULL, &txn, &err), &err,
                     "must use https"))
    return 1;
  if (iya_oidc_authorize_with(rp, "http://[::1]:8080/cb", NULL, NULL, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  if (!contains(iya_oidc_txn_url(txn), "8080")) return failed(iya_oidc_txn_url(txn));
  iya_oidc_txn_free(txn);
  if (iya_oidc_authorize_with(rp, "https://app.example/cb", NULL, NULL, &txn, &err) != IYA_OIDC_OK)
    return failed(err.message);
  iya_oidc_txn_free(txn);
  iya_oidc_rp_free(rp);
  /* The configured redirect URI too, allowInsecure or not. */
  if (rp_from(stub, "{\"redirectUri\":\"http://app.example/cb\"}", &err) || expect_refused(1, &err, "must use https"))
    return failed("http redirect");
  rp = rp_from(stub, "{\"redirectUri\":\"http://localhost:3000/cb\"}", &err);
  if (!rp) return failed(err.message);
  iya_oidc_rp_free(rp);
  /* Embedded metadata is validated like discovered metadata. */
  if (rp_from(stub, "{\"metadataUrl\":null,\"metadata\":{\"issuer\":\"https://op.example\"}}", &err) ||
      expect_refused(1, &err, "metadata is missing"))
    return failed("embedded metadata");
  char *meta = iya_test_provider_metadata(stub);
  char over[8192];
  snprintf(over, sizeof over, "{\"metadataUrl\":null,\"metadata\":%s}", meta);
  iya_oidc_string_free(meta);
  rp = rp_from(stub, over, &err);
  if (!rp) return failed(err.message);
  if (sign_in_with(rp, NULL, NULL, &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}

/* A store an application supplies, here an array of eight entries. */
typedef struct {
  pthread_mutex_t mu;
  char ids[8][64];
  char *docs[8];
  int puts;
  int removes;
} CStore;

static int store_get(void *user, const char *id, char **out) {
  CStore *st = user;
  int found = 0;
  pthread_mutex_lock(&st->mu);
  for (int i = 0; i < 8; i++) {
    if (st->docs[i] && strcmp(st->ids[i], id) == 0) {
      *out = strdup(st->docs[i]);
      found = 1;
    }
  }
  pthread_mutex_unlock(&st->mu);
  return found;
}

static void store_put(void *user, const char *id, const char *doc) {
  CStore *st = user;
  pthread_mutex_lock(&st->mu);
  st->puts++;
  int slot = -1;
  for (int i = 0; i < 8; i++)
    if (st->docs[i] && strcmp(st->ids[i], id) == 0) slot = i;
  for (int i = 0; i < 8 && slot < 0; i++)
    if (!st->docs[i]) slot = i;
  if (slot >= 0) {
    free(st->docs[slot]);
    snprintf(st->ids[slot], sizeof st->ids[slot], "%s", id);
    st->docs[slot] = strdup(doc);
  }
  pthread_mutex_unlock(&st->mu);
}

static void store_remove(void *user, const char *id) {
  CStore *st = user;
  pthread_mutex_lock(&st->mu);
  st->removes++;
  for (int i = 0; i < 8; i++) {
    if (st->docs[i] && strcmp(st->ids[i], id) == 0) {
      free(st->docs[i]);
      st->docs[i] = NULL;
    }
  }
  pthread_mutex_unlock(&st->mu);
}

int TestSessionTokenCache(void) {
  iya_test_provider *stub = iya_test_provider_start();
  iya_test_provider_set_dpop(stub, 1);
  iya_oidc_error err;
  iya_oidc_rp *rp = rp_from(stub, NULL, &err);
  if (!rp) return failed(err.message);
  iya_oidc_login *login = NULL;
  if (sign_in_with(rp, NULL, "S1", &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_oidc_login_session_id(login), "S1") != 0) return failed("session id");
  char *token = NULL;
  char *type = NULL;
  if (iya_oidc_session_access_token(rp, "S1", &token, &type, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(token, iya_oidc_login_access_token(login)) != 0 || strcmp(type, "DPoP") != 0)
    return failed("the cached token was not returned");
  iya_oidc_string_free(token);
  iya_oidc_string_free(type);
  iya_oidc_login_free(login);
  /* 30 seconds or less left: refreshed, with a DPoP proof, and cached. */
  iya_test_provider_set_expires_in(stub, 20);
  if (sign_in_with(rp, NULL, "S2", &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (iya_oidc_session_access_token(rp, "S2", &token, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(token, iya_oidc_login_access_token(login)) == 0) return failed("not refreshed");
  if (strcmp(iya_test_provider_note(stub, "token.refresh_token.proof"), "valid") != 0) return failed("refresh proof");
  if (strcmp(iya_test_provider_note(stub, "token.refresh_token.issued"), "1") != 0) return failed("one refresh");
  iya_test_provider_set_expires_in(stub, 300);
  char *again = NULL;
  if (iya_oidc_session_access_token(rp, "S2", &again, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(iya_test_provider_note(stub, "token.refresh_token.issued"), "2") != 0) return failed("second refresh");
  char *cached = NULL;
  if (iya_oidc_session_access_token(rp, "S2", &cached, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(cached, again) != 0 || strcmp(iya_test_provider_note(stub, "token.refresh_token.issued"), "2") != 0)
    return failed("the refreshed token was not cached");
  iya_oidc_string_free(token);
  iya_oidc_string_free(again);
  iya_oidc_string_free(cached);
  iya_oidc_login_free(login);
  /* A handle the library chose. */
  memset(&err, 0, sizeof err);
  iya_oidc_txn *txn = NULL;
  if (iya_oidc_authorize(rp, &txn, &err) != IYA_OIDC_OK) return failed(err.message);
  int status = 0;
  char location[8192];
  if (iya_test_manual(iya_oidc_txn_url(txn), &status, location, sizeof location) != 0) return failed("manual");
  Pair query[16];
  int n = query_of(location, query, 16);
  if (complete_pairs(rp, query, n, txn, &login, &err) != IYA_OIDC_OK) return failed(err.message);
  char handle[128];
  snprintf(handle, sizeof handle, "%s", iya_oidc_login_session_id(login));
  if (strlen(handle) < 20) return failed("no handle");
  if (iya_oidc_session_access_token(rp, handle, &token, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_string_free(token);
  iya_oidc_txn_free(txn);
  iya_oidc_login_free(login);
  /* Sign-out removes the entry. */
  iya_oidc_session_remove(rp, "S1");
  if (expect_refused(iya_oidc_session_access_token(rp, "S1", &token, NULL, &err), &err, "no signed-in session")) return 1;
  /* A failed refresh removes the entry and is refused. */
  iya_test_provider_set_expires_in(stub, 5);
  if (sign_in_with(rp, NULL, "S3", &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  iya_test_provider_revoke_refresh(stub);
  memset(&err, 0, sizeof err);
  if (iya_oidc_session_access_token(rp, "S3", &token, NULL, &err) == IYA_OIDC_OK ||
      strcmp(err.oauth_error, "invalid_grant") != 0)
    return failed(err.message);
  if (expect_refused(iya_oidc_session_access_token(rp, "S3", &token, NULL, &err), &err, "no signed-in session")) return 1;
  /* A store the application supplies. */
  iya_test_provider_set_expires_in(stub, 300);
  CStore store;
  memset(&store, 0, sizeof store);
  pthread_mutex_init(&store.mu, NULL);
  iya_oidc_session_store hooks = {&store, store_get, store_put, store_remove};
  if (iya_oidc_set_session_store(rp, &hooks, &err) != IYA_OIDC_OK) return failed(err.message);
  if (sign_in_with(rp, NULL, "C1", &login, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (store.puts != 1 || !store.docs[0] || !contains(store.docs[0], "\"access_token\"") ||
      !contains(store.docs[0], "\"refresh_token\""))
    return failed("put");
  if (iya_oidc_session_access_token(rp, "C1", &token, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  if (strcmp(token, iya_oidc_login_access_token(login)) != 0) return failed("get");
  iya_oidc_string_free(token);
  iya_oidc_session_remove(rp, "C1");
  if (store.removes != 1 || store.docs[0]) return failed("remove");
  iya_oidc_session_store partial = {&store, store_get, NULL, store_remove};
  if (iya_oidc_set_session_store(rp, &partial, &err) == IYA_OIDC_OK) return failed("partial store accepted");
  if (iya_oidc_set_session_store(rp, NULL, &err) != IYA_OIDC_OK) return failed(err.message);
  iya_oidc_login_free(login);
  pthread_mutex_destroy(&store.mu);
  iya_oidc_rp_free(rp);
  iya_test_provider_free(stub);
  return 0;
}
