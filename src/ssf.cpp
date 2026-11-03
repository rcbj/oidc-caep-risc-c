// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/oidc.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <initializer_list>
#include <mutex>
#include <thread>
#include <utility>

#include "b64.hpp"
#include "crypto.hpp"
#include "http.hpp"
#include "json.hpp"
#include "util.hpp"

namespace iya {
namespace {

const char *kCaep = "https://schemas.openid.net/secevent/caep/event-type/";
const char *kRisc = "https://schemas.openid.net/secevent/risc/event-type/";
const char *kSsf = "https://schemas.openid.net/secevent/ssf/event-type/";
const char *kPoll = "urn:ietf:rfc:8936";

struct EventName {
  const char *name;
  const char *uri;
};

const EventName kEvents[] = {
    {"sessionRevoked", "https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
    {"tokenClaimsChange", "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"},
    {"credentialChange", "https://schemas.openid.net/secevent/caep/event-type/credential-change"},
    {"assuranceLevelChange", "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"},
    {"deviceComplianceChange", "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"},
    {"sessionEstablished", "https://schemas.openid.net/secevent/caep/event-type/session-established"},
    {"sessionPresented", "https://schemas.openid.net/secevent/caep/event-type/session-presented"},
    {"riskLevelChange", "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"},
    {"accountCredentialChangeRequired",
     "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"},
    {"accountPurged", "https://schemas.openid.net/secevent/risc/event-type/account-purged"},
    {"accountDisabled", "https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
    {"accountEnabled", "https://schemas.openid.net/secevent/risc/event-type/account-enabled"},
    {"identifierChanged", "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"},
    {"identifierRecycled", "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"},
    {"credentialCompromise", "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"},
    {"optIn", "https://schemas.openid.net/secevent/risc/event-type/opt-in"},
    {"optOutInitiated", "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"},
    {"optOutCancelled", "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"},
    {"optOutEffective", "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"},
    {"recoveryActivated", "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"},
    {"recoveryInformationChanged", "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"},
    {"sessionsRevoked", "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"},
    {"verification", "https://schemas.openid.net/secevent/ssf/event-type/verification"},
    {"streamUpdated", "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"},
};

const char *EventByName(const char *name) {
  if (!name) return nullptr;
  for (const EventName &one : kEvents)
    if (std::strcmp(one.name, name) == 0) return one.uri;
  return nullptr;
}

std::vector<std::string> DefaultRequested() {
  const char *names[] = {"sessionRevoked", "credentialChange", "assuranceLevelChange", "tokenClaimsChange",
                         "accountDisabled", "accountEnabled", "accountPurged", "credentialCompromise",
                         "sessionsRevoked", "accountCredentialChangeRequired"};
  std::vector<std::string> out;
  for (const char *name : names) out.emplace_back(EventByName(name));
  return out;
}

std::vector<std::string> DefaultEnding() {
  const char *names[] = {"sessionRevoked", "accountDisabled", "accountPurged", "credentialCompromise",
                         "sessionsRevoked"};
  std::vector<std::string> out;
  for (const char *name : names) out.emplace_back(EventByName(name));
  return out;
}

std::string Clip(const std::string &s, size_t n) {
  if (s.size() <= n) return s;
  return s.substr(0, n);
}

std::string CompactOf(const J &doc) {
  if (doc.type == JType::String) return doc.s;
  if (doc.type == JType::Null) return {};
  return Stringify(doc);
}

const J *Present(const J &doc, std::initializer_list<const char *> names) {
  if (doc.type != JType::Object) return nullptr;
  for (const char *name : names) {
    const J *v = doc.find(name);
    if (v && v->type != JType::Null) return v;
  }
  return nullptr;
}

struct Simple {
  std::string sub;
  std::string email;
  std::string opaque;
};

Simple SimpleSubject(const J *identifier, const std::string &issuer) {
  Simple out;
  if (!identifier || identifier->type != JType::Object) return out;
  std::string fmt = Sprint(Present(*identifier, {"format", "subject_type"}));
  if (fmt == "iss_sub") {
    const J *sub = identifier->find("sub");
    const J *iss = identifier->find("iss");
    if (sub && sub->type == JType::String && (!iss || iss->type == JType::Null || Sprint(iss) == issuer))
      out.sub = sub->s;
  } else if (fmt == "email") {
    const J *email = identifier->find("email");
    if (email && email->type == JType::String) out.email = email->s;
  } else if (fmt == "opaque") {
    const J *id = identifier->find("id");
    if (id && id->type == JType::String) out.opaque = id->s;
  } else if (fmt == "aliases") {
    const J *list = identifier->find("identifiers");
    if (!list || list->type != JType::Array) return out;
    for (const J &one : list->a) {
      if (one.type != JType::Object) continue;
      Simple part = SimpleSubject(&one, issuer);
      if (!part.sub.empty()) out.sub = part.sub;
      if (!part.email.empty()) out.email = part.email;
      if (!part.opaque.empty()) out.opaque = part.opaque;
    }
  }
  return out;
}

SubjectFields SubjectOfValue(const J *sub_id, const std::string &issuer) {
  SubjectFields out;
  if (!sub_id || sub_id->type != JType::Object) return out;
  std::string fmt = Sprint(Present(*sub_id, {"format", "subject_type"}));
  const J *user = sub_id->find("user");
  const J *session = sub_id->find("session");
  bool complex = fmt == "complex" || (fmt.empty() && ((user && user->type != JType::Null) || (session && session->type != JType::Null)));
  if (complex) {
    Simple person = SimpleSubject(user && user->type == JType::Object ? user : nullptr, issuer);
    Simple sess = SimpleSubject(session && session->type == JType::Object ? session : nullptr, issuer);
    if (!person.sub.empty()) out.person = person.sub;
    if (!person.email.empty()) out.email = person.email;
    std::string session_id = !sess.opaque.empty() ? sess.opaque : sess.sub;
    if (!session_id.empty()) out.idp_session = session_id;
  } else {
    Simple one = SimpleSubject(sub_id, issuer);
    if (!one.sub.empty()) out.person = one.sub;
    if (!one.email.empty()) out.email = one.email;
  }
  out.count = 0;
  if (!out.person.empty()) out.count++;
  if (!out.email.empty()) out.count++;
  if (!out.idp_session.empty()) out.count++;
  return out;
}

std::vector<std::string> WellKnown(const std::string &issuer, const std::string &suffix) {
  URL u;
  if (!ParseURL(issuer, u)) return {};
  std::string path = u.path;
  while (!path.empty() && path.back() == '/') path.pop_back();
  std::string origin = u.origin();
  std::string inserted = origin + "/.well-known/" + suffix + path;
  std::string appended = origin + path + "/.well-known/" + suffix;
  if (inserted == appended) return {inserted};
  return {inserted, appended};
}

std::string JoinComma(const std::vector<std::string> &parts) {
  std::string out;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i) out += ", ";
    out += parts[i];
  }
  return out;
}

bool Overlaps(const std::vector<std::string> &got, const std::vector<std::string> &want) {
  for (const auto &one : got)
    if (ContainsString(want, one)) return true;
  return false;
}

std::vector<std::string> AudList(const J *value) {
  std::vector<std::string> out;
  if (!value || value->type == JType::Null) return out;
  if (value->type == JType::Array) {
    for (const J &item : value->a) out.push_back(Sprint(item));
    return out;
  }
  std::string text = Sprint(value);
  if (!text.empty()) out.push_back(text);
  return out;
}

struct Verified {
  J header;
  J payload;
};

Verified VerifyToken(const std::string &token, const std::vector<J> &keys) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (start <= token.size()) {
    auto at = token.find('.', start);
    if (at == std::string::npos) {
      parts.push_back(token.substr(start));
      break;
    }
    parts.push_back(token.substr(start, at - start));
    start = at + 1;
  }
  if (parts.size() != 3 || parts[0].empty() || parts[1].empty() || parts[2].empty())
    throw OidcError("signature", "the SET is not a compact JWS");
  std::vector<uint8_t> header_raw;
  std::vector<uint8_t> payload_raw;
  try {
    header_raw = B64URLDecode(parts[0], "header");
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the SET's header is not base64url: ") + e.what());
  }
  try {
    payload_raw = B64URLDecode(parts[1], "payload");
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the SET's payload is not base64url: ") + e.what());
  }
  J header;
  J payload;
  try {
    header = Parse(std::string(header_raw.begin(), header_raw.end()));
    payload = Parse(std::string(payload_raw.begin(), payload_raw.end()));
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the SET's header or payload is not JSON: ") + e.what());
  }
  if (header.type != JType::Object || payload.type != JType::Object)
    throw OidcError("signature", "the SET's header or payload is not a JSON object");
  std::string alg = Sprint(header.find("alg"));
  const AlgSpec *spec = LookupAlg(alg);
  if (!spec || std::strcmp(spec->mode, "hmac") == 0) {
    std::string shown = alg.empty() ? "(no alg)" : alg;
    throw OidcError("signature", "the SET is signed with " + shown + ", which this receiver does not verify (" +
                                     JoinComma(SupportedJWSAlgs()) + ")");
  }
  const J *crit = header.find("crit");
  if (crit && crit->type != JType::Null)
    throw OidcError("signature", "the SET's header has a crit member this receiver does not understand");
  std::string kid;
  const J *kidv = header.find("kid");
  if (kidv && kidv->type == JType::String) kid = kidv->s;
  std::vector<const J *> matched;
  for (const J &jwk : keys) {
    if (!kid.empty() && Sprint(jwk.find("kid")) != kid) continue;
    if (Sprint(jwk.find("kty")) != spec->kty) continue;
    const J *use = jwk.find("use");
    if (use && use->type != JType::Null && !Sprint(use).empty() && Sprint(use) != "sig") continue;
    const J *named = jwk.find("alg");
    if (named && named->type != JType::Null && !Sprint(named).empty() && Sprint(named) != alg) continue;
    matched.push_back(&jwk);
  }
  if (matched.empty()) {
    std::string suffix;
    if (!kid.empty()) suffix = " with kid " + kid;
    throw OidcError("signature", std::string("the transmitter publishes no ") + spec->kty + " signing key" + suffix);
  }
  std::vector<uint8_t> signature;
  try {
    signature = B64URLDecode(parts[2], "signature");
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the SET's signature is not base64url: ") + e.what());
  }
  std::string data = parts[0] + "." + parts[1];
  for (const J *jwk : matched) {
    EVP_PKEY *key = nullptr;
    try {
      key = PublicKeyFromJWK(*jwk);
    } catch (const OidcError &) {
      throw;
    } catch (const std::exception &e) {
      throw OidcError("signature", e.what());
    }
    bool ok = VerifySignature(key, alg, reinterpret_cast<const uint8_t *>(data.data()), data.size(), signature.data(),
                              signature.size());
    FreeKey(key);
    if (ok) return Verified{std::move(header), std::move(payload)};
  }
  throw OidcError("signature", "the SET's signature does not verify against the transmitter's keys");
}

struct SessionIndex {
  int max = 100000;
  std::vector<std::string> order;
  std::vector<std::pair<std::string, J>> sessions;
  std::mutex mu;

  J *Find(const std::string &id) {
    for (auto &kv : sessions)
      if (kv.first == id) return &kv.second;
    return nullptr;
  }

  void Add(J session) {
    std::lock_guard<std::mutex> lock(mu);
    std::string local_id = Sprint(session.find("local_id"));
    if (static_cast<int>(sessions.size()) >= max && !Find(local_id)) {
      double now = NowSec();
      std::vector<std::string> kept;
      for (const auto &key : order) {
        J *value = Find(key);
        if (!value) continue;
        double exp = 0;
        if (AsFloat(value->find("expires_at"), exp) && exp <= now) {
          sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                        [&](const std::pair<std::string, J> &kv) { return kv.first == key; }),
                         sessions.end());
          continue;
        }
        kept.push_back(key);
      }
      order.swap(kept);
      while (static_cast<int>(sessions.size()) >= max && !order.empty()) {
        std::string oldest = order.front();
        order.erase(order.begin());
        sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                      [&](const std::pair<std::string, J> &kv) { return kv.first == oldest; }),
                       sessions.end());
      }
    }
    const J *email = session.find("email");
    if (email && email->type == JType::String && !email->s.empty()) session.set("email", J::str(ToLower(email->s)));
    bool exists = Find(local_id) != nullptr;
    if (!exists) order.push_back(local_id);
    if (exists) {
      for (auto &kv : sessions)
        if (kv.first == local_id) kv.second = std::move(session);
    } else {
      sessions.emplace_back(local_id, std::move(session));
    }
  }

  void Remove(const std::string &local_id) {
    std::lock_guard<std::mutex> lock(mu);
    bool found = false;
    for (const auto &kv : sessions)
      if (kv.first == local_id) found = true;
    if (!found) return;
    sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                  [&](const std::pair<std::string, J> &kv) { return kv.first == local_id; }),
                   sessions.end());
    std::vector<std::string> kept;
    for (const auto &key : order)
      if (key != local_id) kept.push_back(key);
    order.swap(kept);
  }

  std::vector<std::string> FindIf(const std::function<bool(const J &)> &match) {
    std::lock_guard<std::mutex> lock(mu);
    double now = NowSec();
    std::vector<std::string> out;
    std::vector<std::string> kept;
    for (const auto &key : order) {
      J *value = Find(key);
      if (!value) continue;
      double exp = 0;
      if (AsFloat(value->find("expires_at"), exp) && exp <= now) {
        sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
                                      [&](const std::pair<std::string, J> &kv) { return kv.first == key; }),
                       sessions.end());
        continue;
      }
      kept.push_back(key);
      if (match(*value)) out.push_back(key);
    }
    order.swap(kept);
    return out;
  }
};

struct ErrDoc {
  std::string err;
  std::string description;
};

struct Flight {
  bool finished = false;
  bool result = false;
  std::exception_ptr err;
};

struct Answer {
  int status = 0;
  J doc;
  std::string raw;
};

}  // namespace

const char *EventURI(const char *name) { return EventByName(name); }

std::string VerifyCompactJWSPayload(const std::string &token, const std::string &jwks_json) {
  J doc;
  try {
    doc = Parse(jwks_json);
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the SET's header or payload is not JSON: ") + e.what());
  }
  std::vector<J> keys;
  const J *list = doc.type == JType::Object ? doc.find("keys") : nullptr;
  if (list && list->type == JType::Array) {
    for (const J &item : list->a) {
      if (item.type == JType::Object) keys.push_back(item);
    }
  }
  return Stringify(VerifyToken(token, keys).payload);
}

SubjectFields SubjectOfJSON(const std::string &sub_id_json, const std::string &issuer) {
  if (sub_id_json.empty()) return {};
  J doc;
  try {
    doc = Parse(sub_id_json);
  } catch (const std::exception &e) {
    throw OidcError("validation", std::string("the subject is not JSON: ") + e.what());
  }
  return SubjectOfValue(doc.type == JType::Object ? &doc : nullptr, issuer);
}

struct SignalsReceiver::Impl : std::enable_shared_from_this<Impl> {
  std::string transmitter;
  std::function<void(const std::vector<std::string> &, const SignalEvent &)> on_end;
  std::function<std::map<std::string, std::string>()> headers;
  std::function<std::map<std::string, std::string>(const std::string &, const std::string &)> request_headers;
  std::function<bool(const std::string &, int, const std::string &, const std::string &)> on_response;
  std::vector<std::string> events_requested;
  std::vector<std::string> end_on;
  std::string description;
  std::string tls_ca;
  int poll_ms = 5000;
  int max_events = 50;
  SessionIndex index;

  std::mutex mu;
  std::condition_variable cv;
  J config;
  bool have_config = false;
  J stream;
  bool have_stream = false;
  std::vector<J> keys;
  double keys_at = 0;
  bool running = false;
  bool stop = false;
  bool loop_exited = true;
  std::vector<std::string> ack;
  std::vector<std::pair<std::string, ErrDoc>> errs;
  std::map<std::string, std::vector<std::function<void(const SignalEvent &)>>> handlers;
  std::shared_ptr<Flight> inflight;

  // One transmitter call. request_headers is asked again for each attempt, so a
  // DPoP proof is fresh and carries the nonce the transmitter last gave; on_response
  // decides whether a challenge is answered with one more attempt.
  Answer Call(const std::string &method, const std::string &url, const J *body) {
    std::string payload;
    const std::string *sent = nullptr;
    if (body) {
      payload = Stringify(*body);
      sent = &payload;
    }
    HttpResult res;
    for (int attempt = 0;; attempt++) {
      std::vector<std::pair<std::string, std::string>> hdrs = {{"accept", "application/json"}};
      if (headers) {
        auto extra = headers();
        for (const auto &kv : extra) hdrs.emplace_back(kv.first, kv.second);
      }
      if (request_headers) {
        auto extra = request_headers(method, url);
        for (const auto &kv : extra) hdrs.emplace_back(kv.first, kv.second);
      }
      if (body) hdrs.emplace_back("content-type", "application/json");
      res = Send(url, method, hdrs, sent, tls_ca, "ssf");
      bool again = on_response && on_response(url, res.status, res.header("WWW-Authenticate"), res.header("DPoP-Nonce"));
      if (!again || attempt > 0) break;
    }
    Answer out;
    out.status = res.status;
    out.raw = res.body;
    if (!res.body.empty()) {
      try {
        out.doc = Parse(res.body);
      } catch (const std::exception &) {
        out.doc = J::str(res.body);
      }
    }
    return out;
  }

  J Discover() {
    auto urls = WellKnown(transmitter, "ssf-configuration");
    OidcError last("ssf", "no transmitter configuration at " + JoinComma(urls));
    for (size_t i = 0; i < urls.size(); i++) {
      Answer answer = Call("GET", urls[i], nullptr);
      if (answer.status == 404 && i + 1 != urls.size()) continue;
      bool usable = answer.status == 200 && answer.doc.type == JType::Object &&
                    !Sprint(answer.doc.find("configuration_endpoint")).empty() &&
                    !Sprint(answer.doc.find("jwks_uri")).empty();
      if (!usable) {
        last = OidcError("ssf", Fmt("%s answered %d without a usable transmitter configuration", urls[i].c_str(),
                                    answer.status));
        continue;
      }
      std::vector<std::string> methods;
      if (AsStringList(answer.doc.find("delivery_methods_supported"), methods) && !methods.empty() &&
          !ContainsString(methods, kPoll))
        throw OidcError("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
      return answer.doc;
    }
    throw last;
  }

  std::vector<J> Jwks(bool force) {
    {
      std::lock_guard<std::mutex> lock(mu);
      if (!force && !keys.empty() && NowSec() - keys_at < 3600) return keys;
    }
    std::string uri;
    {
      std::lock_guard<std::mutex> lock(mu);
      if (have_config) uri = Sprint(config.find("jwks_uri"));
    }
    Answer answer = Call("GET", uri, nullptr);
    const J *list = answer.doc.type == JType::Object ? answer.doc.find("keys") : nullptr;
    if (answer.status != 200 || !list || list->type != JType::Array)
      throw OidcError("ssf", Fmt("the transmitter's JWKS answered %d", answer.status));
    std::vector<J> got;
    for (const J &item : list->a) {
      if (item.type != JType::Object) throw OidcError("ssf", Fmt("the transmitter's JWKS answered %d", answer.status));
      got.push_back(item);
    }
    std::lock_guard<std::mutex> lock(mu);
    keys = got;
    keys_at = NowSec();
    return keys;
  }

  J EnsureStream() {
    std::string endpoint;
    {
      std::lock_guard<std::mutex> lock(mu);
      endpoint = Sprint(config.find("configuration_endpoint"));
    }
    Answer answer = Call("GET", endpoint, nullptr);
    if (answer.status == 200) {
      std::vector<const J *> all;
      if (answer.doc.type == JType::Array) {
        for (const J &item : answer.doc.a) all.push_back(&item);
      } else if (answer.doc.type != JType::Null) {
        all.push_back(&answer.doc);
      }
      for (const J *item : all) {
        if (!item || item->type != JType::Object) continue;
        const J *delivery = item->find("delivery");
        if (delivery && delivery->type == JType::Object && Sprint(delivery->find("method")) == kPoll &&
            !Sprint(item->find("stream_id")).empty())
          return *item;
      }
    } else if (answer.status != 404) {
      throw OidcError("ssf", Fmt("listing the streams at %s answered %d: %s", endpoint.c_str(), answer.status,
                                 Clip(CompactOf(answer.doc), 300).c_str()));
    }
    J body = J::obj();
    J delivery = J::obj();
    delivery.set("method", J::str(kPoll));
    body.set("delivery", delivery);
    J requested = J::arr();
    for (const auto &one : events_requested) requested.a.push_back(J::str(one));
    body.set("events_requested", requested);
    if (!description.empty()) body.set("description", J::str(description));
    Answer created = Call("POST", endpoint, &body);
    if ((created.status != 200 && created.status != 201) || created.doc.type != JType::Object ||
        Sprint(created.doc.find("stream_id")).empty())
      throw OidcError("ssf", Fmt("creating a stream at %s answered %d: %s", endpoint.c_str(), created.status,
                                 Clip(CompactOf(created.doc), 300).c_str()));
    return created.doc;
  }

  void Restore(const std::vector<std::string> &old_ack, const std::vector<std::pair<std::string, ErrDoc>> &old_errs) {
    std::lock_guard<std::mutex> lock(mu);
    std::vector<std::string> merged = old_ack;
    merged.insert(merged.end(), ack.begin(), ack.end());
    ack.swap(merged);
    for (const auto &kv : old_errs) {
      bool have = false;
      for (const auto &cur : errs)
        if (cur.first == kv.first) have = true;
      if (!have) errs.push_back(kv);
    }
  }

  std::vector<std::string> SessionsFor(const std::string &event_type, const SubjectFields &subject) {
    if (event_type == EventByName("verification") || event_type == EventByName("streamUpdated")) return {};
    if (!subject.idp_session.empty()) {
      auto found = index.FindIf([&](const J &session) { return Sprint(session.find("idp_session")) == subject.idp_session; });
      if (!found.empty() || event_type == EventByName("sessionRevoked")) return found;
    }
    if (!subject.person.empty())
      return index.FindIf([&](const J &session) { return Sprint(session.find("person")) == subject.person; });
    if (!subject.email.empty()) {
      std::string wanted = ToLower(subject.email);
      return index.FindIf([&](const J &session) { return Sprint(session.find("email")) == wanted; });
    }
    return {};
  }

  void Handle(const std::string &jti, const std::string &token) {
    auto keys_now = Jwks(false);
    J header;
    J payload;
    try {
      Verified got = VerifyToken(token, keys_now);
      header = std::move(got.header);
      payload = std::move(got.payload);
    } catch (const OidcError &e) {
      if (e.code == "signature" && (Contains(e.what(), "publishes no") || Contains(e.what(), "does not verify"))) {
        keys_now = Jwks(true);
        Verified got = VerifyToken(token, keys_now);
        header = std::move(got.header);
        payload = std::move(got.payload);
      } else {
        throw;
      }
    }
    const J *typ = header.find("typ");
    if (typ && typ->type != JType::Null && ToLower(Sprint(typ)) != "secevent+jwt")
      throw OidcError("validation", "the SET's typ is " + Sprint(typ));
    std::string issuer;
    J stream_copy;
    {
      std::lock_guard<std::mutex> lock(mu);
      issuer = Sprint(config.find("issuer"));
      stream_copy = stream;
    }
    if (Sprint(payload.find("iss")) != issuer)
      throw OidcError("validation", "the SET was issued by " + Sprint(payload.find("iss")) + ", not " + issuer);
    auto want = AudList(stream_copy.find("aud"));
    auto got_aud = AudList(payload.find("aud"));
    if (!want.empty() && !Overlaps(got_aud, want))
      throw OidcError("validation", "the SET is for " + JoinComma(got_aud) + ", not this stream");
    const J *pjti = payload.find("jti");
    if (pjti && pjti->type != JType::Null && Sprint(pjti) != jti)
      throw OidcError("validation", "the SET's jti is not the one it was delivered under");
    const J *events = payload.find("events");
    if (!events || events->type != JType::Object || events->o.empty())
      throw OidcError("validation", "the SET carries no events");
    for (const auto &ev : events->o) {
      const J *body = &ev.second;
      const J *subject_src = nullptr;
      const J *sub_id = payload.find("sub_id");
      if (sub_id && sub_id->type != JType::Null) {
        if (sub_id->type == JType::Object) subject_src = sub_id;
      } else if (body && body->type == JType::Object) {
        const J *subject = body->find("subject");
        if (subject && subject->type == JType::Object) subject_src = subject;
      }
      SubjectFields subject = SubjectOfValue(subject_src, issuer);
      auto sessions = SessionsFor(ev.first, subject);
      bool ends = ContainsString(end_on, ev.first) && !sessions.empty();
      SignalEvent event;
      event.type = ev.first;
      event.jti = jti;
      event.sessions = sessions;
      event.ended = ends;
      if (!subject.person.empty()) event.subject["person"] = subject.person;
      if (!subject.email.empty()) event.subject["email"] = subject.email;
      if (!subject.idp_session.empty()) event.subject["idpSession"] = subject.idp_session;
      if (ends) {
        try {
          if (on_end) on_end(event.sessions, event);
        } catch (const std::exception &) {
          event.ended = false;
        }
        if (event.ended) {
          for (const auto &local_id : sessions) index.Remove(local_id);
        }
      }
      std::vector<std::function<void(const SignalEvent &)>> handlers_now;
      std::vector<std::function<void(const SignalEvent &)>> star;
      {
        std::lock_guard<std::mutex> lock(mu);
        auto it = handlers.find(ev.first);
        if (it != handlers.end()) handlers_now = it->second;
        auto sit = handlers.find("*");
        if (sit != handlers.end()) star = sit->second;
      }
      handlers_now.insert(handlers_now.end(), star.begin(), star.end());
      for (const auto &handler : handlers_now) {
        try {
          handler(event);
        } catch (const std::exception &) {
        }
      }
    }
  }

  bool PollNow() {
    std::vector<std::string> ack_now;
    std::vector<std::pair<std::string, ErrDoc>> errs_now;
    J stream_copy;
    {
      std::lock_guard<std::mutex> lock(mu);
      stream_copy = stream;
      ack_now.swap(ack);
      errs_now.swap(errs);
    }
    const J *delivery = stream_copy.find("delivery");
    std::string endpoint = delivery && delivery->type == JType::Object ? Sprint(delivery->find("endpoint_url")) : "";
    J body = J::obj();
    body.set("maxEvents", J::integer(max_events));
    body.set("returnImmediately", J::boolean(true));
    if (!ack_now.empty()) {
      J list = J::arr();
      for (const auto &one : ack_now) list.a.push_back(J::str(one));
      body.set("ack", list);
    }
    if (!errs_now.empty()) {
      J obj = J::obj();
      for (const auto &kv : errs_now) {
        J one = J::obj();
        one.set("err", J::str(kv.second.err));
        one.set("description", J::str(kv.second.description));
        obj.set(kv.first, one);
      }
      body.set("setErrs", obj);
    }
    Answer answer;
    try {
      answer = Call("POST", endpoint, &body);
    } catch (...) {
      Restore(ack_now, errs_now);
      throw;
    }
    if (answer.status != 200) {
      Restore(ack_now, errs_now);
      throw OidcError("ssf", Fmt("the poll answered %d: %s", answer.status, Clip(CompactOf(answer.doc), 300).c_str()));
    }
    const J *sets = answer.doc.type == JType::Object ? answer.doc.find("sets") : nullptr;
    if (sets && sets->type == JType::Object) {
      for (const auto &kv : sets->o) {
        std::string token = kv.second.type == JType::String ? kv.second.s : Sprint(&kv.second);
        try {
          Handle(kv.first, token);
        } catch (const std::exception &e) {
          std::string description = e.what();
          std::string code = "invalid_request";
          if (const auto *oe = dynamic_cast<const OidcError *>(&e)) {
            if (oe->code == "signature") code = "invalid_key";
          }
          std::lock_guard<std::mutex> lock(mu);
          errs.emplace_back(kv.first, ErrDoc{code, description});
          continue;
        }
        std::lock_guard<std::mutex> lock(mu);
        ack.push_back(kv.first);
      }
    }
    return IsExactTrue(answer.doc.type == JType::Object ? answer.doc.find("moreAvailable") : nullptr);
  }

  void Loop() {
    auto self = shared_from_this();
    while (true) {
      int interval = 0;
      {
        std::lock_guard<std::mutex> lock(mu);
        if (!running) break;
        interval = poll_ms;
      }
      int delay = interval;
      try {
        bool more = PollOnceBody();
        if (more) delay = 0;
      } catch (const std::exception &) {
        int backoff = interval * 4;
        if (backoff > 60000) backoff = 60000;
        delay = backoff;
      }
      std::unique_lock<std::mutex> lock(mu);
      if (!running) break;
      cv.wait_for(lock, std::chrono::milliseconds(delay), [&] { return stop || !running; });
      if (!running || stop) break;
    }
    std::lock_guard<std::mutex> lock(mu);
    loop_exited = true;
    running = false;
    cv.notify_all();
  }

  bool PollOnceBody() {
    std::shared_ptr<Flight> flight;
    {
      std::unique_lock<std::mutex> lock(mu);
      if (!inflight || inflight->finished) {
        inflight = std::make_shared<Flight>();
        auto self = shared_from_this();
        auto current = inflight;
        std::thread([self, current] {
          bool result = false;
          std::exception_ptr err;
          try {
            result = self->PollNow();
          } catch (...) {
            err = std::current_exception();
          }
          {
            std::lock_guard<std::mutex> lk(self->mu);
            current->result = result;
            current->err = err;
            current->finished = true;
          }
          self->cv.notify_all();
        }).detach();
      }
      flight = inflight;
      cv.wait(lock, [&] { return flight->finished; });
      if (flight->err) std::rethrow_exception(flight->err);
      return flight->result;
    }
  }
};

SignalsReceiver::SignalsReceiver(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}

SignalsReceiver::~SignalsReceiver() { Stop(); }

std::unique_ptr<SignalsReceiver> SignalsReceiver::New(
    const std::string &transmitter, std::function<void(const std::vector<std::string> &, const SignalEvent &)> on_end,
    Options opts) {
  if (!on_end) throw OidcError("config", "onEndSessions is required");
  if (transmitter.empty() || (!StartsWith(transmitter, "http://") && !StartsWith(transmitter, "https://")))
    throw OidcError("config", "transmitter must be an http(s) URL");
  auto impl = std::make_shared<Impl>();
  impl->transmitter = TrimRightSlash(transmitter);
  impl->on_end = std::move(on_end);
  impl->headers = std::move(opts.headers);
  impl->request_headers = std::move(opts.request_headers);
  impl->on_response = std::move(opts.on_response);
  impl->events_requested = opts.events_requested.empty() ? DefaultRequested() : opts.events_requested;
  impl->end_on = opts.end_on.empty() ? DefaultEnding() : opts.end_on;
  impl->description = opts.description;
  impl->tls_ca = opts.tls_ca;
  impl->poll_ms = opts.poll_interval_ms > 0 ? opts.poll_interval_ms : 5000;
  return std::unique_ptr<SignalsReceiver>(new SignalsReceiver(impl));
}

void SignalsReceiver::On(const std::string &event_type, std::function<void(const SignalEvent &)> handler) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->handlers[event_type].push_back(std::move(handler));
}

void SignalsReceiver::Start() {
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    if (impl_->running) return;
  }
  J cfg = impl_->Discover();
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->config = std::move(cfg);
    impl_->have_config = true;
  }
  impl_->Jwks(true);
  J stream = impl_->EnsureStream();
  const J *delivery = stream.find("delivery");
  if (!delivery || delivery->type != JType::Object || Sprint(delivery->find("endpoint_url")).empty())
    throw OidcError("ssf", "the stream has no poll endpoint_url");
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->stream = std::move(stream);
    impl_->have_stream = true;
    if (impl_->running) return;
    impl_->running = true;
    impl_->stop = false;
    impl_->loop_exited = false;
  }
  auto self = impl_;
  std::thread([self] { self->Loop(); }).detach();
}

void SignalsReceiver::Stop() {
  if (!impl_) return;
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->running = false;
    impl_->stop = true;
    impl_->cv.notify_all();
  }
  std::unique_lock<std::mutex> lock(impl_->mu);
  impl_->cv.wait_for(lock, std::chrono::seconds(20), [&] { return impl_->loop_exited; });
}

bool SignalsReceiver::PollOnce() { return impl_->PollOnceBody(); }

void SignalsReceiver::Track(const std::string &local_id, const std::string &person, const std::string &email,
                            const std::string &idp_session) {
  J session = J::obj();
  session.set("local_id", J::str(local_id));
  session.set("person", J::str(person));
  if (!email.empty()) session.set("email", J::str(email));
  if (!idp_session.empty()) session.set("idp_session", J::str(idp_session));
  impl_->index.Add(std::move(session));
}

void SignalsReceiver::Untrack(const std::string &local_id) { impl_->index.Remove(local_id); }

void SignalsReceiver::Verify(const std::string &state) {
  std::string endpoint;
  std::string stream_id;
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    if (impl_->have_config) endpoint = Sprint(impl_->config.find("verification_endpoint"));
    stream_id = Sprint(impl_->stream.find("stream_id"));
  }
  if (endpoint.empty()) throw OidcError("ssf", "the transmitter publishes no verification_endpoint");
  J body = J::obj();
  body.set("stream_id", J::str(stream_id));
  if (!state.empty()) body.set("state", J::str(state));
  Answer answer = impl_->Call("POST", endpoint, &body);
  if (answer.status != 200 && answer.status != 204)
    throw OidcError("ssf", Fmt("verification answered %d", answer.status));
}

std::string SignalsReceiver::stream_id() const {
  std::lock_guard<std::mutex> lock(impl_->mu);
  return Sprint(impl_->stream.find("stream_id"));
}

}  // namespace iya
