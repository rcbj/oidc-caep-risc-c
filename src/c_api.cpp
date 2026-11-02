// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya_oidc.h"

#include "iya/oidc.hpp"

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace {

int CodeOf(const std::string &code) {
  if (code == "config") return IYA_OIDC_ERR_CONFIG;
  if (code == "discovery") return IYA_OIDC_ERR_DISCOVERY;
  if (code == "protocol") return IYA_OIDC_ERR_PROTOCOL;
  if (code == "validation") return IYA_OIDC_ERR_VALIDATION;
  if (code == "signature") return IYA_OIDC_ERR_SIGNATURE;
  if (code == "ssf") return IYA_OIDC_ERR_SSF;
  return IYA_OIDC_ERR_PROTOCOL;
}

void Fill(iya_oidc_error *err, int code, const std::string &message, const std::string &oauth) {
  if (!err) return;
  err->code = code;
  std::snprintf(err->message, sizeof err->message, "%s", message.c_str());
  std::snprintf(err->oauth_error, sizeof err->oauth_error, "%s", oauth.c_str());
}

int FailOidc(iya_oidc_error *err, const iya::OidcError &e) {
  int code = CodeOf(e.code);
  Fill(err, code, e.what(), e.oauth_error);
  std::fprintf(stderr, "oidc: %s: %s\n", e.code.c_str(), e.what());
  return code;
}

int FailOther(iya_oidc_error *err, const std::exception &e) {
  Fill(err, IYA_OIDC_ERR_PROTOCOL, e.what(), "");
  std::fprintf(stderr, "oidc: protocol: %s\n", e.what());
  return IYA_OIDC_ERR_PROTOCOL;
}

char *Dup(const std::string &s) {
  char *out = new char[s.size() + 1];
  std::memcpy(out, s.data(), s.size());
  out[s.size()] = '\0';
  return out;
}

struct RpWrap {
  std::unique_ptr<iya::RelyingParty> rp;
};

struct TxnWrap {
  iya::Transaction txn;
};

struct LoginWrap {
  iya::Login login;
};

struct EventSink {
  iya_oidc_on_event_fn fn = nullptr;
  void *user = nullptr;
};

struct RxWrap {
  std::unique_ptr<iya::SignalsReceiver> rx;
  std::string stream_id;
  iya_oidc_on_end_fn on_end = nullptr;
  void *on_end_user = nullptr;
  std::vector<EventSink> sinks;
};

}  // namespace

extern "C" {

const char *iya_oidc_error_name(int code) {
  switch (code) {
    case IYA_OIDC_OK:
      return "ok";
    case IYA_OIDC_ERR_CONFIG:
      return "config";
    case IYA_OIDC_ERR_DISCOVERY:
      return "discovery";
    case IYA_OIDC_ERR_PROTOCOL:
      return "protocol";
    case IYA_OIDC_ERR_VALIDATION:
      return "validation";
    case IYA_OIDC_ERR_SIGNATURE:
      return "signature";
    case IYA_OIDC_ERR_SSF:
      return "ssf";
    default:
      return "protocol";
  }
}

const char *iya_oidc_default_scopes(void) { return iya::DefaultScopes(); }

int iya_oidc_hash_claim(const char *value, const char *alg, char *out, size_t out_len, iya_oidc_error *err) {
  try {
    std::string got = iya::HashClaim(value ? value : "", alg ? alg : "");
    if (out && out_len) std::snprintf(out, out_len, "%s", got.c_str());
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

const char *iya_oidc_event_type(const char *name) { return iya::EventURI(name); }

int iya_oidc_verify_set(const char *token, const char *jwks_json, char **payload_json, iya_oidc_error *err) {
  try {
    std::string payload = iya::VerifyCompactJWSPayload(token ? token : "", jwks_json ? jwks_json : "");
    if (payload_json) *payload_json = Dup(payload);
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_subject_of(const char *sub_json, const char *issuer, char *person, size_t person_len, char *email,
                        size_t email_len, char *idp_session, size_t idp_len, int *count, iya_oidc_error *err) {
  try {
    iya::SubjectFields got = iya::SubjectOfJSON(sub_json ? sub_json : "", issuer ? issuer : "");
    if (person && person_len) std::snprintf(person, person_len, "%s", got.person.c_str());
    if (email && email_len) std::snprintf(email, email_len, "%s", got.email.c_str());
    if (idp_session && idp_len) std::snprintf(idp_session, idp_len, "%s", got.idp_session.c_str());
    if (count) *count = got.count;
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_resolve_config(const char *json, const char *base_dir, char **out_json, iya_oidc_error *err) {
  try {
    std::string resolved = iya::ResolveConfigJSON(json ? json : "", base_dir ? base_dir : "");
    if (out_json) *out_json = Dup(resolved);
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_create(const char *config_json, iya_oidc_rp **out, iya_oidc_error *err) {
  try {
    auto rp = iya::RelyingParty::Create(config_json ? config_json : "");
    if (out) {
      auto *wrap = new RpWrap();
      wrap->rp = std::move(rp);
      *out = reinterpret_cast<iya_oidc_rp *>(wrap);
    }
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_open_file(const char *path, iya_oidc_rp **out, iya_oidc_error *err) {
  try {
    auto rp = iya::RelyingParty::FromFile(path ? path : "");
    if (out) {
      auto *wrap = new RpWrap();
      wrap->rp = std::move(rp);
      *out = reinterpret_cast<iya_oidc_rp *>(wrap);
    }
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

void iya_oidc_rp_free(iya_oidc_rp *rp) { delete reinterpret_cast<RpWrap *>(rp); }

int iya_oidc_authorize(iya_oidc_rp *rp, iya_oidc_txn **out, iya_oidc_error *err) {
  try {
    auto *wrap = reinterpret_cast<RpWrap *>(rp);
    if (!wrap || !wrap->rp) {
      iya::OidcError e("config", "relying party is null");
      return FailOidc(err, e);
    }
    iya::Transaction txn = wrap->rp->Authorize();
    if (out) {
      auto *held = new TxnWrap();
      held->txn = std::move(txn);
      *out = reinterpret_cast<iya_oidc_txn *>(held);
    }
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

iya_oidc_txn *iya_oidc_txn_clone(const iya_oidc_txn *txn) {
  if (!txn) return nullptr;
  auto *src = reinterpret_cast<const TxnWrap *>(txn);
  auto *held = new TxnWrap();
  held->txn = src->txn;
  return reinterpret_cast<iya_oidc_txn *>(held);
}

void iya_oidc_txn_set_state(iya_oidc_txn *txn, const char *state) {
  if (!txn) return;
  reinterpret_cast<TxnWrap *>(txn)->txn.state = state ? state : "";
}

void iya_oidc_txn_set_nonce(iya_oidc_txn *txn, const char *nonce) {
  if (!txn) return;
  reinterpret_cast<TxnWrap *>(txn)->txn.nonce = nonce ? nonce : "";
}

const char *iya_oidc_txn_url(const iya_oidc_txn *txn) {
  if (!txn) return "";
  return reinterpret_cast<const TxnWrap *>(txn)->txn.url.c_str();
}

const char *iya_oidc_txn_state(const iya_oidc_txn *txn) {
  if (!txn) return "";
  return reinterpret_cast<const TxnWrap *>(txn)->txn.state.c_str();
}

void iya_oidc_txn_free(iya_oidc_txn *txn) { delete reinterpret_cast<TxnWrap *>(txn); }

int iya_oidc_complete(iya_oidc_rp *rp, const char *const *keys, const char *const *vals, size_t nquery,
                      const iya_oidc_txn *txn, iya_oidc_login **out, iya_oidc_error *err) {
  try {
    auto *wrap = reinterpret_cast<RpWrap *>(rp);
    auto *held = reinterpret_cast<const TxnWrap *>(txn);
    if (!wrap || !wrap->rp || !held) {
      iya::OidcError e("validation", "relying party or transaction is null");
      return FailOidc(err, e);
    }
    std::map<std::string, std::string> query;
    for (size_t i = 0; i < nquery; i++) {
      const char *key = keys && keys[i] ? keys[i] : "";
      const char *val = vals && vals[i] ? vals[i] : "";
      query[key] = val;
    }
    iya::Login login = wrap->rp->Complete(query, held->txn);
    if (out) {
      auto *box = new LoginWrap();
      box->login = std::move(login);
      *out = reinterpret_cast<iya_oidc_login *>(box);
    }
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_refresh(iya_oidc_rp *rp, const char *refresh_token, const char *scope, const iya_oidc_login *previous,
                     iya_oidc_login **out, iya_oidc_error *err) {
  try {
    auto *wrap = reinterpret_cast<RpWrap *>(rp);
    if (!wrap || !wrap->rp) {
      iya::OidcError e("protocol", "relying party is null");
      return FailOidc(err, e);
    }
    const iya::Login *prev = nullptr;
    if (previous) prev = &reinterpret_cast<const LoginWrap *>(previous)->login;
    iya::Login login = wrap->rp->Refresh(refresh_token ? refresh_token : "", scope ? scope : "", prev);
    if (out) {
      auto *box = new LoginWrap();
      box->login = std::move(login);
      *out = reinterpret_cast<iya_oidc_login *>(box);
    }
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_client_credentials(iya_oidc_rp *rp, const char *scope, char **access_token, iya_oidc_error *err) {
  try {
    auto *wrap = reinterpret_cast<RpWrap *>(rp);
    if (!wrap || !wrap->rp) {
      iya::OidcError e("protocol", "relying party is null");
      return FailOidc(err, e);
    }
    iya::Access access = wrap->rp->ClientCredentials(scope ? scope : "");
    if (access_token) *access_token = Dup(access.access_token);
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_userinfo(iya_oidc_rp *rp, const char *access_token, const char *expected_sub, char **sub_out,
                      iya_oidc_error *err) {
  try {
    auto *wrap = reinterpret_cast<RpWrap *>(rp);
    if (!wrap || !wrap->rp) {
      iya::OidcError e("validation", "relying party is null");
      return FailOidc(err, e);
    }
    std::string sub = wrap->rp->UserInfoSubject(access_token ? access_token : "", expected_sub ? expected_sub : "");
    if (sub_out) *sub_out = Dup(sub);
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

char *iya_oidc_end_session_url(iya_oidc_rp *rp, const char *id_token, const char *state) {
  auto *wrap = reinterpret_cast<RpWrap *>(rp);
  if (!wrap || !wrap->rp) return nullptr;
  iya::EndSessionOptions opts;
  opts.id_token = id_token ? id_token : "";
  opts.state = state ? state : "";
  return Dup(wrap->rp->EndSessionURL(opts));
}

const char *iya_oidc_login_subject(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.subject.c_str();
}
const char *iya_oidc_login_issuer(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.issuer.c_str();
}
const char *iya_oidc_login_email(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.email.c_str();
}
const char *iya_oidc_login_preferred_username(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.preferred_username.c_str();
}
const char *iya_oidc_login_sid(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.sid.c_str();
}
const char *iya_oidc_login_access_token(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.access_token.c_str();
}
const char *iya_oidc_login_id_token(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.id_token.c_str();
}
const char *iya_oidc_login_refresh_token(const iya_oidc_login *login) {
  if (!login) return "";
  return reinterpret_cast<const LoginWrap *>(login)->login.refresh_token.c_str();
}

void iya_oidc_login_free(iya_oidc_login *login) { delete reinterpret_cast<LoginWrap *>(login); }

int iya_oidc_receiver_new(const char *transmitter, iya_oidc_on_end_fn on_end, void *user, const char *authorization,
                          int poll_interval_ms, iya_oidc_receiver **out, iya_oidc_error *err) {
  try {
    auto *box = new RxWrap();
    box->on_end = on_end;
    box->on_end_user = user;
    iya::SignalsReceiver::Options opts;
    opts.poll_interval_ms = poll_interval_ms;
    if (authorization && authorization[0]) {
      std::string header = authorization;
      opts.headers = [header] { return std::map<std::string, std::string>{{"Authorization", header}}; };
    }
    box->rx = iya::SignalsReceiver::New(
        transmitter ? transmitter : "",
        [box](const std::vector<std::string> &ids, const iya::SignalEvent &) {
          if (!box->on_end) return;
          std::vector<const char *> ptrs;
          ptrs.reserve(ids.size());
          for (const auto &id : ids) ptrs.push_back(id.c_str());
          box->on_end(ptrs.empty() ? nullptr : ptrs.data(), ptrs.size(), box->on_end_user);
        },
        opts);
    if (out) *out = reinterpret_cast<iya_oidc_receiver *>(box);
    else delete box;
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_receiver_on(iya_oidc_receiver *rx, const char *event_type, iya_oidc_on_event_fn fn, void *user,
                         iya_oidc_error *err) {
  try {
    auto *box = reinterpret_cast<RxWrap *>(rx);
    if (!box || !box->rx) {
      iya::OidcError e("config", "receiver is null");
      return FailOidc(err, e);
    }
    box->sinks.push_back(EventSink{fn, user});
    size_t index = box->sinks.size() - 1;
    box->rx->On(event_type ? event_type : "", [box, index](const iya::SignalEvent &event) {
      EventSink &sink = box->sinks[index];
      if (sink.fn) sink.fn(event.type.c_str(), event.ended ? 1 : 0, sink.user);
    });
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_receiver_start(iya_oidc_receiver *rx, iya_oidc_error *err) {
  try {
    auto *box = reinterpret_cast<RxWrap *>(rx);
    if (!box || !box->rx) {
      iya::OidcError e("ssf", "receiver is null");
      return FailOidc(err, e);
    }
    box->rx->Start();
    box->stream_id = box->rx->stream_id();
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

void iya_oidc_receiver_stop(iya_oidc_receiver *rx) {
  auto *box = reinterpret_cast<RxWrap *>(rx);
  if (!box || !box->rx) return;
  box->rx->Stop();
}

int iya_oidc_receiver_poll_once(iya_oidc_receiver *rx, int *more, iya_oidc_error *err) {
  try {
    auto *box = reinterpret_cast<RxWrap *>(rx);
    if (!box || !box->rx) {
      iya::OidcError e("ssf", "receiver is null");
      return FailOidc(err, e);
    }
    bool again = box->rx->PollOnce();
    if (more) *more = again ? 1 : 0;
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_receiver_track(iya_oidc_receiver *rx, const char *local_id, const char *person, const char *email,
                            const char *idp_session, iya_oidc_error *err) {
  try {
    auto *box = reinterpret_cast<RxWrap *>(rx);
    if (!box || !box->rx) {
      iya::OidcError e("ssf", "receiver is null");
      return FailOidc(err, e);
    }
    box->rx->Track(local_id ? local_id : "", person ? person : "", email ? email : "", idp_session ? idp_session : "");
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

int iya_oidc_receiver_verify(iya_oidc_receiver *rx, const char *state, iya_oidc_error *err) {
  try {
    auto *box = reinterpret_cast<RxWrap *>(rx);
    if (!box || !box->rx) {
      iya::OidcError e("ssf", "receiver is null");
      return FailOidc(err, e);
    }
    box->rx->Verify(state ? state : "");
    return IYA_OIDC_OK;
  } catch (const iya::OidcError &e) {
    return FailOidc(err, e);
  } catch (const std::exception &e) {
    return FailOther(err, e);
  }
}

const char *iya_oidc_receiver_stream_id(iya_oidc_receiver *rx) {
  auto *box = reinterpret_cast<RxWrap *>(rx);
  if (!box) return "";
  if (box->rx) box->stream_id = box->rx->stream_id();
  return box->stream_id.c_str();
}

void iya_oidc_receiver_free(iya_oidc_receiver *rx) { delete reinterpret_cast<RxWrap *>(rx); }

void iya_oidc_string_free(char *s) { delete[] s; }

}  // extern "C"
