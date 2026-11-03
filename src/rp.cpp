// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/oidc.hpp"

#include <openssl/evp.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <optional>
#include <utility>

#include "b64.hpp"
#include "crypto.hpp"
#include "http.hpp"
#include "json.hpp"
#include "util.hpp"

namespace iya {
namespace {

const char *kDefaultScopes = "openid profile email offline_access ssf.read ssf.manage";
const char *kFront[] = {"access_token", "id_token", "refresh_token", "token_type"};
const char *kNotID[] = {"at+jwt", "application/at+jwt", "logout+jwt", "secevent+jwt", "dpop+jwt",
                        "token-introspection+jwt", "software-statement+jwt", "jwt-bearer"};
const char *kAuthMethods[] = {"client_secret_basic", "client_secret_post", "private_key_jwt"};
const char *kRequiredMeta[] = {"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
                               "response_types_supported", "subject_types_supported",
                               "id_token_signing_alg_values_supported"};

struct Checks {
  std::string issuer;
  std::string client_id;
  std::string client_secret;
  std::string access_token;
  std::string code;
  std::vector<std::string> algorithms;
  std::vector<J> jwks;
  double clock_tolerance = 0;
  bool has_max_id_age = false;
  double max_id_age = 0;
  bool has_nonce = false;
  std::string nonce;
  bool has_previous = false;
  std::string previous_sub;
  bool has_max_age = false;
  double max_age = 0;
  // requireIdTokenTypAndAtHash: typ must be present, and at_hash whenever an access
  // token came with the ID token. A signed UserInfo response is not an ID token
  // from the token endpoint and sets relax_typ.
  bool require_typ = true;
  bool require_at_hash = true;
  bool relax_typ = false;
  std::vector<std::string> acr_values;
};

struct TokenResp {
  std::string access;
  std::string type;
  std::string id_token;
  std::string refresh;
  std::string scope;
  bool has_expires = false;
  double expires_in = 0;
};

bool EndsWith(const std::string &s, const std::string &suffix) {
  return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string FirstString(const J &raw, std::initializer_list<const char *> keys) {
  for (const char *key : keys) {
    const J *v = raw.find(key);
    if (v && v->type != JType::Null) return Sprint(v);
  }
  return {};
}

void AddField(std::vector<std::pair<std::string, std::string>> &fields, const std::string &k, const std::string &v) {
  for (auto &kv : fields) {
    if (kv.first == k) {
      kv.second = v;
      return;
    }
  }
  fields.emplace_back(k, v);
}

J StringArray(const std::vector<std::string> &list) {
  J a = J::arr();
  for (const auto &s : list) a.a.push_back(J::str(s));
  return a;
}

std::string MustURL(const J *value, const char *name) {
  if (!value || value->type != JType::String || value->s.empty())
    throw OidcError("discovery", std::string("OpenID Provider metadata ") + name + " is missing");
  URL u;
  if (!ParseURL(value->s, u) || u.host.empty())
    throw OidcError("discovery", std::string("OpenID Provider metadata ") + name + " is not a valid URL");
  if (std::string(name) == "issuer" && (!u.query.empty() || !u.fragment.empty()))
    throw OidcError("discovery", "issuer must not contain a query or fragment");
  return value->s;
}

std::string IssuerFromMetadataURL(const std::string &metadata_url) {
  URL u;
  if (!ParseURL(metadata_url, u) || u.host.empty())
    throw OidcError("config", Fmt("metadataUrl is not a URL: %s", metadata_url.c_str()));
  const std::string marker = "/.well-known/openid-configuration";
  auto at = u.path.find(marker);
  if (at == std::string::npos)
    throw OidcError("config", Fmt("metadataUrl must be the openid-configuration URL, not %s", metadata_url.c_str()));
  std::string prefix = u.path.substr(0, at);
  while (!prefix.empty() && prefix.back() == '/') prefix.pop_back();
  return u.origin() + prefix;
}

J ValidateProviderMetadata(const J &raw, const std::string &expected) {
  if (raw.type != JType::Object) throw OidcError("discovery", "OpenID Provider metadata must be a JSON object");
  std::vector<std::string> missing;
  for (const char *key : kRequiredMeta)
    if (!raw.has(key)) missing.push_back(key);
  if (!missing.empty()) {
    std::string joined;
    for (size_t i = 0; i < missing.size(); i++) {
      if (i) joined += ", ";
      joined += missing[i];
    }
    throw OidcError("discovery", "OpenID Provider metadata is missing " + joined);
  }
  J metadata = J::obj();
  for (const char *key : {"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"})
    metadata.set(key, J::str(MustURL(raw.find(key), key)));
  for (const char *key : {"userinfo_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint",
                          "revocation_endpoint"}) {
    const J *v = raw.find(key);
    if (v && v->type != JType::Null) metadata.set(key, J::str(MustURL(v, key)));
  }
  for (const char *key : {"token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "scopes_supported",
                          "grant_types_supported", "dpop_signing_alg_values_supported"}) {
    const J *v = raw.find(key);
    if (!v || v->type == JType::Null) continue;
    std::vector<std::string> list;
    if (!AsStringList(v, list)) throw OidcError("discovery", Fmt("%s must be an array", key));
    metadata.set(key, StringArray(list));
  }
  const J *iss_param = raw.find("authorization_response_iss_parameter_supported");
  if (iss_param && iss_param->type != JType::Null)
    metadata.set("authorization_response_iss_parameter_supported", J::boolean(IsExactTrue(iss_param)));
  const J *require_par = raw.find("require_pushed_authorization_requests");
  if (require_par && require_par->type != JType::Null)
    metadata.set("require_pushed_authorization_requests", J::boolean(IsExactTrue(require_par)));
  std::vector<std::string> response_types;
  if (!AsStringList(raw.find("response_types_supported"), response_types) ||
      !ContainsString(response_types, "code"))
    throw OidcError("discovery", "OpenID Provider does not support response_type=code");
  metadata.set("response_types_supported", StringArray(response_types));
  std::vector<std::string> subjects;
  if (!AsStringList(raw.find("subject_types_supported"), subjects))
    throw OidcError("discovery", "subject_types_supported must be an array");
  metadata.set("subject_types_supported", StringArray(subjects));
  std::vector<std::string> algs;
  if (!AsStringList(raw.find("id_token_signing_alg_values_supported"), algs))
    throw OidcError("discovery", "id_token_signing_alg_values_supported must be an array");
  metadata.set("id_token_signing_alg_values_supported", StringArray(algs));
  if (!expected.empty() && Sprint(metadata.find("issuer")) != expected)
    throw OidcError("discovery", Fmt("issuer mismatch: expected \"%s\", got \"%s\"", expected.c_str(),
                                     Sprint(metadata.find("issuer")).c_str()));
  return metadata;
}

std::string JoinCommaList(const std::vector<std::string> &list) {
  std::string out;
  for (size_t i = 0; i < list.size(); i++) {
    if (i) out += ", ";
    out += list[i];
  }
  return out;
}

// The ID token algorithms this client accepts. idTokenSignedResponseAlg pins one,
// and the provider must advertise it. Otherwise idTokenSigningAlgs (default RS256)
// is narrowed to what the provider advertises, and creation fails only when nothing
// is left. none is never accepted, and a symmetric (HS*) algorithm only because it
// was named here.
std::vector<std::string> IDTokenAlgorithms(const std::vector<std::string> &advertised, const std::string &pinned,
                                           const std::vector<std::string> &listed) {
  std::vector<std::string> wanted;
  if (!pinned.empty()) wanted = {pinned};
  else if (!listed.empty()) wanted = listed;
  else wanted = {"RS256"};
  std::vector<std::string> allowed;
  for (const auto &alg : wanted) {
    if (ToLower(alg) == "none") throw OidcError("config", "the ID token algorithm none is never accepted");
    if (!LookupAlg(alg)) throw OidcError("config", Fmt("this client cannot verify ID tokens signed with %s", alg.c_str()));
    if (ContainsString(advertised, alg)) allowed.push_back(alg);
  }
  if (!pinned.empty() && allowed.empty())
    throw OidcError("discovery", Fmt("the provider does not advertise id_token alg %s", pinned.c_str()));
  if (allowed.empty())
    throw OidcError("discovery", "the provider advertises none of the accepted ID token algorithms (" +
                                     JoinCommaList(wanted) + ")");
  return allowed;
}

std::string JoinComma(const std::vector<std::string> &list) {
  std::string out;
  for (size_t i = 0; i < list.size(); i++) {
    if (i) out += ", ";
    out += list[i];
  }
  return out;
}

J DiscoverProvider(const std::string &metadata_url, const std::string &ca) {
  std::string expected = IssuerFromMetadataURL(metadata_url);
  HttpResult answer = Send(metadata_url, "GET", {{"accept", "application/json"}}, nullptr, ca, "discovery");
  if (answer.status != 200) throw OidcError("discovery", Fmt("%s answered %d", metadata_url.c_str(), answer.status));
  J body;
  try {
    body = Parse(answer.body);
  } catch (const std::exception &) {
    throw OidcError("discovery", metadata_url + " did not answer JSON");
  }
  if (body.type != JType::Object) throw OidcError("discovery", "OpenID Provider metadata must be a JSON object");
  return ValidateProviderMetadata(body, expected);
}

std::vector<J> FetchJWKS(const std::string &uri, const std::string &ca) {
  HttpResult answer = Send(uri, "GET", {{"accept", "application/json"}}, nullptr, ca, "discovery");
  if (answer.status != 200) throw OidcError("discovery", Fmt("the JWKS at %s answered %d", uri.c_str(), answer.status));
  J body;
  try {
    body = Parse(answer.body);
  } catch (const std::exception &) {
    throw OidcError("discovery", "the JWKS at " + uri + " is not JSON");
  }
  const J *keys = body.type == JType::Object ? body.find("keys") : nullptr;
  if (!keys || keys->type != JType::Array) throw OidcError("discovery", Fmt("the JWKS at %s has no keys", uri.c_str()));
  std::vector<J> out;
  for (const J &item : keys->a) {
    if (item.type != JType::Object) throw OidcError("discovery", Fmt("the JWKS at %s has no keys", uri.c_str()));
    out.push_back(item);
  }
  return out;
}

std::string SecretValue(const std::string &raw, const std::string &base, const std::string &what) {
  if (StartsWith(raw, "env:")) {
    std::string name = raw.substr(4);
    const char *v = std::getenv(name.c_str());
    if (!v || !*v)
      throw OidcError("config", Fmt("%s reads %s, and that variable is empty", what.c_str(), name.c_str()));
    return v;
  }
  if (StartsWith(raw, "file:")) {
    std::string path = JoinPath(base, raw.substr(5));
    try {
      return Trim(ReadFile(path));
    } catch (const std::exception &e) {
      throw OidcError("config", std::string("could not read ") + what + " at " + path + ": " + e.what());
    }
  }
  return raw;
}

std::string KeyValue(const std::string &raw, const std::string &base, const std::string &what) {
  if (StartsWith(raw, "env:") || StartsWith(raw, "file:") || raw.find("-----BEGIN") != std::string::npos)
    return SecretValue(raw, base, what);
  std::string path = JoinPath(base, raw);
  try {
    return Trim(ReadFile(path));
  } catch (const std::exception &e) {
    throw OidcError("config", std::string("could not read ") + what + " at " + path + ": " + e.what());
  }
}

bool ReadTrust(const J *raw, const std::string &base, std::string &out) {
  if (!raw || raw->type == JType::Null) return false;
  std::string value = Trim(Sprint(raw));
  if (value.empty()) return false;
  if (value.find("-----BEGIN") != std::string::npos) {
    out = value;
    return true;
  }
  if (StartsWith(value, "env:")) {
    const char *got = std::getenv(value.substr(4).c_str());
    if (!got || !*got) return false;
    out = got;
    return true;
  }
  std::string path = value;
  if (StartsWith(value, "file:")) path = value.substr(5);
  if (path.empty()) return false;
  path = JoinPath(base, path);
  try {
    out = ReadFile(path);
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

bool SignalsOn(const J *value, bool present) {
  if (!present || !value || value->type == JType::Null || (value->type == JType::Bool && value->b)) return true;
  if (value->type == JType::Bool) return value->b;
  throw OidcError("config", "signals must be true or false");
}

// A redirect URI is https, or http on a loopback host (localhost, 127.0.0.1, [::1]).
// allowInsecure is for a development provider and does not widen this.
std::string CheckRedirect(const std::string &value, const std::string &name) {
  URL u;
  if (!ParseURL(value, u) || u.host.empty())
    throw OidcError("config", Fmt("%s is not a URL: %s", name.c_str(), value.c_str()));
  if (u.scheme == "https") return value;
  if (u.scheme == "http" && IsLoopback(u.hostname())) return value;
  throw OidcError("config", Fmt("%s must use https, or http on loopback: %s", name.c_str(), value.c_str()));
}

std::string JoinSpace(const std::vector<std::string> &parts) {
  std::string out;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i) out.push_back(' ');
    out += parts[i];
  }
  return out;
}

J Resolve(const J &raw, const std::string &base) {
  if (raw.type != JType::Object) throw OidcError("config", "the configuration must be a JSON object");
  std::string client_id = Trim(FirstString(raw, {"clientId", "client_id"}));
  if (client_id.empty()) throw OidcError("config", "client_id is required");
  std::string method = Sprint(raw.find("tokenEndpointAuthMethod"));
  if (method.empty()) method = "client_secret_basic";
  if (method == "none")
    throw OidcError("config",
                    "tokenEndpointAuthMethod \"none\" is a public client; this library authenticates a confidential client");
  if (!ContainsString({kAuthMethods[0], kAuthMethods[1], kAuthMethods[2]}, method))
    throw OidcError("config", Fmt("tokenEndpointAuthMethod must be %s, %s, %s, not %s", kAuthMethods[0], kAuthMethods[1],
                                  kAuthMethods[2], method.c_str()));
  std::string redirect = Trim(FirstString(raw, {"redirectUri", "redirect_uri"}));
  if (redirect.empty()) throw OidcError("config", "redirectUri is required");
  bool allow = IsExactTrue(raw.find("allowInsecure"));
  bool signals_present = raw.has("signals");
  bool signals = SignalsOn(raw.find("signals"), signals_present);
  std::string scopes;
  const J *scopes_v = raw.find("scopes");
  if (!scopes_v || scopes_v->type == JType::Null) {
    scopes = Trim(kDefaultScopes);
  } else {
    std::vector<std::string> list;
    if (AsStringList(scopes_v, list)) {
      std::vector<std::string> parts;
      for (auto item : list) {
        item = Trim(item);
        if (!item.empty()) parts.push_back(item);
      }
      scopes = JoinSpace(parts);
    } else {
      scopes = Trim(Sprint(scopes_v));
    }
  }
  if (!signals) {
    std::vector<std::string> kept;
    for (const auto &part : Fields(scopes))
      if (part != "ssf.read" && part != "ssf.manage") kept.push_back(part);
    scopes = JoinSpace(kept);
  }
  if (!ContainsString(Fields(scopes), "openid")) throw OidcError("config", "scopes must include openid");
  std::string par = "auto";
  const J *par_v = raw.find("par");
  if (par_v && par_v->type != JType::Null) par = Sprint(par_v);
  if (par != "auto" && par != "always" && par != "never")
    throw OidcError("config", "par must be auto, always, or never");
  std::string dpop = "auto";
  const J *dpop_v = raw.find("dpop");
  if (dpop_v && dpop_v->type != JType::Null) dpop = Sprint(dpop_v);
  if (dpop != "auto" && dpop != "always" && dpop != "never")
    throw OidcError("config", "dpop must be auto, always, or never");
  bool require_typ = true;
  const J *rt_v = raw.find("requireIdTokenTypAndAtHash");
  if (rt_v && rt_v->type != JType::Null) {
    if (rt_v->type != JType::Bool) throw OidcError("config", "requireIdTokenTypAndAtHash must be true or false");
    require_typ = rt_v->b;
  }
  std::vector<std::string> signing_algs;
  const J *algs_v = raw.find("idTokenSigningAlgs");
  if (algs_v && algs_v->type != JType::Null) {
    std::vector<std::string> list;
    if (algs_v->type == JType::Array) {
      if (!AsStringList(algs_v, list)) throw OidcError("config", "idTokenSigningAlgs must be a list of algorithm names");
    } else if (algs_v->type == JType::String) {
      list = Fields(algs_v->s);
    } else {
      throw OidcError("config", "idTokenSigningAlgs must be a list of algorithm names");
    }
    for (auto item : list) {
      item = Trim(item);
      if (item.empty()) continue;
      if (ToLower(item) == "none") throw OidcError("config", "the ID token algorithm none is never accepted");
      if (!LookupAlg(item)) throw OidcError("config", Fmt("this client cannot verify ID tokens signed with %s", item.c_str()));
      if (!ContainsString(signing_algs, item)) signing_algs.push_back(item);
    }
    if (signing_algs.empty()) throw OidcError("config", "idTokenSigningAlgs must name at least one algorithm");
  }
  std::string acr_values;
  const J *acr_v = raw.find("acrValues");
  if (acr_v && acr_v->type != JType::Null) {
    std::vector<std::string> list;
    if (acr_v->type == JType::Array) {
      if (!AsStringList(acr_v, list)) throw OidcError("config", "acrValues must be a string or a list of strings");
    } else if (acr_v->type == JType::String) {
      list = Fields(acr_v->s);
    } else {
      throw OidcError("config", "acrValues must be a string or a list of strings");
    }
    std::vector<std::string> kept;
    for (auto item : list) {
      item = Trim(item);
      if (!item.empty()) kept.push_back(item);
    }
    acr_values = JoinSpace(kept);
  }
  std::string issuer;
  const J *issuer_v = raw.find("issuer");
  if (issuer_v && issuer_v->type != JType::Null && !Trim(Sprint(issuer_v)).empty()) issuer = Trim(Sprint(issuer_v));
  std::string metadata_url;
  const J *mu = raw.find("metadataUrl");
  if (mu && mu->type != JType::Null && !Trim(Sprint(mu)).empty()) metadata_url = Trim(Sprint(mu));
  if (!metadata_url.empty()) {
    std::string from_url = IssuerFromMetadataURL(metadata_url);
    if (!issuer.empty() && issuer != from_url)
      throw OidcError("config", Fmt("issuer %s is not the issuer of %s (%s)", issuer.c_str(), metadata_url.c_str(),
                                    from_url.c_str()));
    issuer = from_url;
  }
  J metadata;
  bool has_metadata = false;
  const J *embedded = raw.find("metadata");
  const J *mf = raw.find("metadataFile");
  if (embedded && embedded->type == JType::Object) {
    // Metadata given in the configuration is held to the same rules as discovered metadata.
    metadata = ValidateProviderMetadata(*embedded, issuer);
    has_metadata = true;
    issuer = Sprint(metadata.find("issuer"));
  } else if (embedded && embedded->type != JType::Null) {
    throw OidcError("config", "metadata must be a JSON object");
  } else if (mf && mf->type != JType::Null && !Sprint(mf).empty()) {
    std::string full = JoinPath(base, Sprint(mf));
    std::string body;
    try {
      body = ReadFile(full);
    } catch (const std::exception &e) {
      throw OidcError("config", std::string("could not read metadata at ") + full + ": " + e.what());
    }
    J parsed;
    try {
      parsed = Parse(body);
    } catch (const std::exception &e) {
      throw OidcError("config", std::string("could not read metadata at ") + full + ": " + e.what());
    }
    if (parsed.type != JType::Object)
      throw OidcError("config", "could not read metadata at " + full + ": not an object");
    metadata = ValidateProviderMetadata(parsed, issuer);
    has_metadata = true;
    issuer = Sprint(metadata.find("issuer"));
  }
  if (metadata_url.empty() && !has_metadata) throw OidcError("config", "metadataUrl or metadataFile is required");
  bool needs_secret = method != "private_key_jwt";
  std::string client_secret;
  const J *cs = raw.find("clientSecret");
  if (cs && cs->type != JType::Null && !Sprint(cs).empty())
    client_secret = SecretValue(Sprint(cs), base, "the client secret");
  if (needs_secret && client_secret.empty()) throw OidcError("config", Fmt("%s needs clientSecret", method.c_str()));
  std::string private_key;
  const J *pk = raw.find("privateKey");
  if (!pk || pk->type == JType::Null || Sprint(pk).empty()) pk = raw.find("privateKeyPem");
  if (pk && pk->type != JType::Null && !Sprint(pk).empty())
    private_key = KeyValue(Sprint(pk), base, "the private key");
  std::string dpop_key;
  const J *dk = raw.find("dpopKey");
  if (!dk || dk->type == JType::Null || Sprint(dk).empty()) dk = raw.find("dpopKeyPem");
  if (dk && dk->type != JType::Null && !Sprint(dk).empty()) dpop_key = KeyValue(Sprint(dk), base, "the DPoP key");
  if (method == "private_key_jwt" && private_key.empty())
    throw OidcError("config", "private_key_jwt needs privateKey");
  std::string tls_ca;
  bool has_ca = ReadTrust(raw.find("tlsCa"), base, tls_ca);
  std::string post = Trim(FirstString(raw, {"postLogoutRedirectUri", "post_logout_redirect_uri"}));
  J ssf;
  bool has_ssf = false;
  if (signals) {
    const J *doc = raw.find("ssf");
    if (doc && doc->type == JType::Object) {
      const J *tr = doc->find("transmitter");
      std::string transmitter = tr ? Trim(Sprint(tr)) : std::string();
      if (tr && tr->type != JType::Null && !transmitter.empty()) {
        transmitter = TrimRightSlash(transmitter);
        if (!StartsWith(transmitter, "http://") && !StartsWith(transmitter, "https://"))
          throw OidcError("config", "ssf.transmitter must be an http(s) URL");
        ssf = J::obj();
        ssf.set("transmitter", J::str(transmitter));
        const J *poll = doc->find("pollIntervalMs");
        if (Truthy(poll)) ssf.set("pollIntervalMs", *poll);
        has_ssf = true;
      }
    }
  }
  std::string checked_redirect = CheckRedirect(redirect, "redirectUri");
  J out = J::obj();
  if (!issuer.empty()) out.set("issuer", J::str(issuer));
  if (!metadata_url.empty()) out.set("metadataUrl", J::str(metadata_url));
  if (has_metadata) out.set("metadata", metadata);
  out.set("clientId", J::str(client_id));
  if (!client_secret.empty()) out.set("clientSecret", J::str(client_secret));
  if (!private_key.empty()) out.set("privateKeyPem", J::str(private_key));
  const J *pka = raw.find("privateKeyAlg");
  if (pka && pka->type != JType::Null && !Sprint(pka).empty()) out.set("privateKeyAlg", *pka);
  else out.set("privateKeyAlg", J::str("RS256"));
  out.set("tokenEndpointAuthMethod", J::str(method));
  out.set("redirectUri", J::str(checked_redirect));
  if (!post.empty()) out.set("postLogoutRedirectUri", J::str(CheckRedirect(post, "postLogoutRedirectUri")));
  out.set("scopes", J::str(scopes));
  const J *pin = raw.find("idTokenSignedResponseAlg");
  if (pin && pin->type != JType::Null && !Sprint(pin).empty()) {
    std::string pinned = Trim(Sprint(pin));
    if (ToLower(pinned) == "none") throw OidcError("config", "the ID token algorithm none is never accepted");
    if (!LookupAlg(pinned))
      throw OidcError("config", Fmt("this client cannot verify ID tokens signed with %s", pinned.c_str()));
    out.set("idTokenSignedResponseAlg", J::str(pinned));
  }
  out.set("idTokenSigningAlgs", StringArray(signing_algs.empty() ? std::vector<std::string>{"RS256"} : signing_algs));
  out.set("requireIdTokenTypAndAtHash", J::boolean(require_typ));
  if (!acr_values.empty()) out.set("acrValues", J::str(acr_values));
  out.set("par", J::str(par));
  out.set("dpop", J::str(dpop));
  if (!dpop_key.empty()) out.set("dpopKeyPem", J::str(dpop_key));
  const J *tol = raw.find("clockToleranceSec");
  if (!tol || tol->type == JType::Null) out.set("clockToleranceSec", J::integer(30));
  else out.set("clockToleranceSec", *tol);
  const J *age = raw.find("maxIdTokenAgeSec");
  if (!age || age->type == JType::Null) out.set("maxIdTokenAgeSec", J::integer(600));
  else out.set("maxIdTokenAgeSec", *age);
  out.set("allowInsecure", J::boolean(allow));
  if (has_ca) out.set("tlsCa", J::str(tls_ca));
  if (!signals) out.set("signals", J::boolean(false));
  if (has_ssf) out.set("ssf", ssf);
  return out;
}

std::string CaOf(const J &config) {
  const J *v = config.find("tlsCa");
  if (v && v->type == JType::String) return v->s;
  return {};
}

std::vector<std::string> SplitToken(const std::string &token) {
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
  return parts;
}

J DecodePart(const std::string &token, int index) {
  auto parts = SplitToken(token);
  if (parts.size() != 3 || parts[0].empty() || parts[1].empty() || parts[2].empty())
    throw OidcError("signature", "the ID token is not a compact JWS: not a compact JWS");
  std::vector<uint8_t> raw;
  try {
    raw = B64URLDecode(parts[static_cast<size_t>(index)], index == 0 ? "header" : "payload");
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the ID token is not a compact JWS: ") + e.what());
  }
  J parsed;
  try {
    parsed = Parse(std::string(raw.begin(), raw.end()));
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the ID token is not a compact JWS: ") + e.what());
  }
  if (parsed.type != JType::Object)
    throw OidcError("signature", "the ID token is not a compact JWS: not a JSON object");
  return parsed;
}

std::string KidOf(const J &header) {
  const J *kid = header.find("kid");
  if (kid && kid->type == JType::String) return kid->s;
  return {};
}

std::vector<const J *> Candidates(const std::vector<J> &jwks, const std::string &alg, const std::string &kid) {
  const AlgSpec *spec = LookupAlg(alg);
  if (!spec) return {};
  std::vector<const J *> found;
  for (const J &jwk : jwks) {
    if (!kid.empty() && Sprint(jwk.find("kid")) != kid) continue;
    if (Sprint(jwk.find("kty")) != spec->kty) continue;
    const J *use = jwk.find("use");
    if (use && use->type != JType::Null && !Sprint(use).empty() && Sprint(use) != "sig") continue;
    const J *named = jwk.find("alg");
    if (named && named->type != JType::Null && !Sprint(named).empty() && Sprint(named) != alg) continue;
    found.push_back(&jwk);
  }
  return found;
}

bool SignatureOK(const std::string &token, const std::string &alg, const Checks &checks) {
  auto parts = SplitToken(token);
  if (parts.size() != 3) throw OidcError("signature", "the ID token is not a compact JWS: not a compact JWS");
  std::vector<uint8_t> sig;
  try {
    sig = B64URLDecode(parts[2], "signature");
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the ID token is not a compact JWS: ") + e.what());
  }
  std::string signing = parts[0] + "." + parts[1];
  auto *bytes = reinterpret_cast<const uint8_t *>(signing.data());
  if (StartsWith(alg, "HS")) return VerifyHMAC(checks.client_secret, alg, bytes, signing.size(), sig.data(), sig.size());
  J header = DecodePart(token, 0);
  auto keys = Candidates(checks.jwks, alg, KidOf(header));
  if (keys.empty()) throw OidcError("signature", "signature verification failed: no applicable key");
  for (const J *jwk : keys) {
    EVP_PKEY *key = nullptr;
    try {
      key = PublicKeyFromJWK(*jwk);
    } catch (const std::exception &) {
      continue;
    }
    bool good = VerifySignature(key, alg, bytes, signing.size(), sig.data(), sig.size());
    FreeKey(key);
    if (good) return true;
  }
  return false;
}

void CheckHash(const J *claim, const std::string &value, const std::string &alg, const std::string &name) {
  if (!claim || claim->type == JType::Null) return;
  if (claim->type != JType::String || !SameText(claim->s, HashClaim(value, alg)))
    throw OidcError("validation", "the ID token's " + name + " does not match");
}

J ValidateIDToken(const std::string &token, const Checks &checks) {
  J header = DecodePart(token, 0);
  std::string alg = Sprint(header.find("alg"));
  if (!ContainsString(checks.algorithms, alg)) {
    std::string shown = alg.empty() ? "(no alg)" : alg;
    throw OidcError("signature", "the ID token is signed with " + shown + ", which this client does not accept");
  }
  const J *crit = header.find("crit");
  if (crit && crit->type != JType::Null)
    throw OidcError("validation", "the ID token has a crit header this client does not understand");
  std::string typ;
  const J *typv = header.find("typ");
  if (typv && typv->type != JType::Null) typ = ToLower(Sprint(typv));
  bool banned = false;
  for (const char *name : kNotID)
    if (typ == name) banned = true;
  if (!typ.empty() && ((typ != "jwt" && typ != "application/jwt") || banned))
    throw OidcError("validation", "the ID token typ is " + Sprint(typv) + ", not an ID token");
  if (typ.empty() && checks.require_typ && !checks.relax_typ)
    throw OidcError("validation", "the ID token has no typ header (JWT or application/jwt is required)");
  if (StartsWith(alg, "HS") && checks.client_secret.empty())
    throw OidcError("config", alg + " ID tokens need the client secret");
  J payload = DecodePart(token, 1);
  bool ok = false;
  try {
    ok = SignatureOK(token, alg, checks);
  } catch (const OidcError &) {
    throw;
  } catch (const std::exception &e) {
    throw OidcError("signature", std::string("the ID token was refused: signature: ") + e.what());
  }
  if (!ok) throw OidcError("signature", "the ID token was refused: signature verification failed");
  const J *iss = payload.find("iss");
  if (!iss || iss->type != JType::String || iss->s != checks.issuer)
    throw OidcError("validation", "the ID token was refused: issuer mismatch");
  std::vector<std::string> audiences;
  const J *aud = payload.find("aud");
  if (aud && aud->type == JType::Array) {
    for (const J &item : aud->a) audiences.push_back(Sprint(item));
  } else if (!aud || aud->type == JType::Null) {
    audiences.emplace_back("");
  } else {
    audiences.push_back(Sprint(aud));
  }
  if (!ContainsString(audiences, checks.client_id))
    throw OidcError("validation", "the ID token audience does not include this client");
  double now = NowSec();
  double exp = 0;
  if (!AsFloat(payload.find("exp"), exp)) throw OidcError("validation", "the ID token was refused: exp is missing");
  if (exp + checks.clock_tolerance < now) throw OidcError("validation", "the ID token was refused: exp expired");
  double nbf = 0;
  if (AsFloat(payload.find("nbf"), nbf) && nbf - checks.clock_tolerance > now)
    throw OidcError("validation", "the ID token was refused: nbf is in the future");
  double issued = 0;
  if (AsFloat(payload.find("iat"), issued) && issued - checks.clock_tolerance > now)
    throw OidcError("validation", "the ID token was refused: iat is in the future");
  if (checks.has_max_id_age) {
    double iat = 0;
    if (!AsFloat(payload.find("iat"), iat)) throw OidcError("validation", "the ID token was refused: iat is missing");
    if ((now - iat) - checks.clock_tolerance > checks.max_id_age)
      throw OidcError("validation", "the ID token was refused: iat is too old");
  }
  const J *sub = payload.find("sub");
  if (!sub || sub->type != JType::String || sub->s.empty()) throw OidcError("validation", "the ID token has no sub");
  if (audiences.size() > 1 && Sprint(payload.find("azp")) != checks.client_id)
    throw OidcError("validation", "an ID token with several audiences must name this client as azp");
  const J *azp = payload.find("azp");
  if (azp && azp->type != JType::Null && Sprint(azp) != checks.client_id)
    throw OidcError("validation", Fmt("the ID token azp is %s, not %s", Sprint(azp).c_str(), checks.client_id.c_str()));
  if (checks.has_nonce) {
    const J *nonce = payload.find("nonce");
    if (!nonce || nonce->type != JType::String || !SameText(nonce->s, checks.nonce))
      throw OidcError("validation", "the ID token nonce does not match this sign-in");
  }
  if (checks.has_previous && Sprint(payload.find("sub")) != checks.previous_sub)
    throw OidcError("validation", "the refreshed ID token is for a different subject");
  if (!checks.access_token.empty()) {
    const J *at_hash = payload.find("at_hash");
    if ((!at_hash || at_hash->type == JType::Null) && checks.require_at_hash)
      throw OidcError("validation", "the ID token has no at_hash, and the token response carried an access token");
    CheckHash(at_hash, checks.access_token, alg, "at_hash");
  }
  if (!checks.code.empty()) CheckHash(payload.find("c_hash"), checks.code, alg, "c_hash");
  if (!checks.acr_values.empty()) {
    const J *acr = payload.find("acr");
    if (!acr || acr->type != JType::String || acr->s.empty())
      throw OidcError("validation", "acr_values was requested and the ID token has no acr");
    if (!ContainsString(checks.acr_values, acr->s))
      throw OidcError("validation", "the ID token acr " + acr->s + " is not one of the requested acr_values");
  }
  if (checks.has_max_age) {
    double auth_time = 0;
    if (!AsFloat(payload.find("auth_time"), auth_time))
      throw OidcError("validation", "max_age was requested and the ID token has no auth_time");
    if (auth_time < static_cast<double>(std::time(nullptr)) - checks.max_age - checks.clock_tolerance)
      throw OidcError("validation", "the ID token auth_time is older than max_age");
  }
  return payload;
}

std::string ClaimString(const J &claims, const char *name) {
  const J *v = claims.find(name);
  if (!v || v->type != JType::String || v->s.empty()) return {};
  return v->s;
}

Login LoginFrom(const TokenResp &tokens, const J &claims) {
  Login login;
  login.subject = Sprint(claims.find("sub"));
  login.issuer = Sprint(claims.find("iss"));
  login.claims_json = Stringify(claims);
  login.access_token = tokens.access;
  login.id_token = tokens.id_token;
  login.token_type = tokens.type;
  login.email = ClaimString(claims, "email");
  login.name = ClaimString(claims, "name");
  login.preferred_username = ClaimString(claims, "preferred_username");
  login.sid = ClaimString(claims, "sid");
  login.acr = ClaimString(claims, "acr");
  login.refresh_token = tokens.refresh;
  if (tokens.has_expires) {
    login.expires_at = NowSec() + tokens.expires_in;
    login.has_expires = true;
  }
  login.scope = tokens.scope;
  return login;
}

std::string WithQuery(const std::string &base, const std::vector<std::pair<std::string, std::string>> &params,
                      const std::vector<std::string> &order) {
  URL u;
  if (!ParseURL(base, u)) return base;
  if (u.path.empty()) u.path = "/";
  u.query = FormBody(params, order);
  u.fragment.clear();
  return u.str();
}

std::string TrimFloat(double v) {
  char buf[64];
  std::snprintf(buf, sizeof buf, "%.16g", v);
  std::string text = buf;
  if (text.empty() || text == "-") return "0";
  return text;
}

}  // namespace

OidcError::OidcError(std::string code_in, std::string message, std::string oauth)
    : std::runtime_error(std::move(message)), code(std::move(code_in)), oauth_error(std::move(oauth)) {}

const char *DefaultScopes() { return kDefaultScopes; }

std::string HashClaim(const std::string &value, const std::string &alg) {
  const EVP_MD *md = EVP_sha256();
  if (alg == "EdDSA" || alg == "Ed25519" || alg.find("512") != std::string::npos) md = EVP_sha512();
  else if (alg.find("384") != std::string::npos) md = EVP_sha384();
  unsigned char sum[EVP_MAX_MD_SIZE];
  unsigned int n = 0;
  EVP_Digest(value.data(), value.size(), sum, &n, md, nullptr);
  return B64URLEncode(sum, n / 2);
}

std::string ResolveConfigJSON(const std::string &raw_json, const std::string &base_dir) {
  J parsed;
  try {
    parsed = Parse(raw_json);
  } catch (const std::exception &e) {
    throw OidcError("config", std::string("could not read configuration: ") + e.what());
  }
  if (parsed.type != JType::Object) throw OidcError("config", "the configuration must be a JSON object");
  return Stringify(Resolve(parsed, base_dir));
}

SessionStore::~SessionStore() = default;

struct MemorySessionStore::Impl {
  std::mutex mu;
  std::map<std::string, SessionTokens> entries;
};

MemorySessionStore::MemorySessionStore() : impl_(std::make_unique<Impl>()) {}
MemorySessionStore::~MemorySessionStore() = default;

bool MemorySessionStore::Get(const std::string &session_id, SessionTokens &out) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  auto it = impl_->entries.find(session_id);
  if (it == impl_->entries.end()) return false;
  out = it->second;
  return true;
}

void MemorySessionStore::Put(const std::string &session_id, const SessionTokens &tokens) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->entries[session_id] = tokens;
}

void MemorySessionStore::Remove(const std::string &session_id) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->entries.erase(session_id);
}

std::string ResourceResponse::header(const std::string &name) const {
  std::string want = ToLower(name);
  for (const auto &kv : headers)
    if (ToLower(kv.first) == want) return kv.second;
  return {};
}

namespace {

// The seconds a cached session access token must still have left to be handed out.
constexpr double kSessionMargin = 30;

bool AsksForNonce(int status, const std::string &www_authenticate) {
  if (status != 401) return false;
  std::string lower = ToLower(www_authenticate);
  return lower.find("dpop") != std::string::npos && lower.find("use_dpop_nonce") != std::string::npos;
}

SessionTokens TokensOf(const Login &login) {
  SessionTokens tokens;
  tokens.access_token = login.access_token;
  tokens.token_type = login.token_type;
  tokens.refresh_token = login.refresh_token;
  tokens.id_token = login.id_token;
  tokens.scope = login.scope;
  tokens.subject = login.subject;
  tokens.claims_json = login.claims_json;
  tokens.expires_at = login.expires_at;
  tokens.has_expires = login.has_expires;
  return tokens;
}

}  // namespace

struct RelyingParty::Impl {
  J config;
  J metadata;
  EVP_PKEY *key = nullptr;
  EVP_PKEY *dpop_key = nullptr;
  J dpop_jwk;
  std::string dpop_jkt;
  std::vector<std::string> algs;
  std::mutex mu;
  std::vector<J> jwks;
  bool jwks_set = false;
  std::map<std::string, double> used;
  std::map<std::string, std::string> nonces;
  std::string cc_scope;
  Access cc_token;
  double cc_until = 0;
  bool cc_set = false;
  std::shared_ptr<SessionStore> sessions = std::make_shared<MemorySessionStore>();
  std::mutex refresh_mu;

  ~Impl() {
    FreeKey(key);
    FreeKey(dpop_key);
  }

  std::string Ca() const { return CaOf(config); }

  std::shared_ptr<SessionStore> Sessions() {
    std::lock_guard<std::mutex> lock(mu);
    return sessions;
  }

  std::vector<J> Keys(bool force) {
    {
      std::lock_guard<std::mutex> lock(mu);
      if (!force && jwks_set) return jwks;
    }
    auto fetched = FetchJWKS(Sprint(metadata.find("jwks_uri")), Ca());
    std::lock_guard<std::mutex> lock(mu);
    jwks = fetched;
    jwks_set = true;
    return jwks;
  }

  Checks BuildChecks(const Checks &extra) {
    Checks checks = extra;
    checks.issuer = Sprint(metadata.find("issuer"));
    checks.client_id = Sprint(config.find("clientId"));
    if (extra.algorithms.empty()) checks.algorithms = algs;
    std::string secret = Sprint(config.find("clientSecret"));
    if (!secret.empty()) checks.client_secret = secret;
    double tol = 0;
    if (AsFloat(config.find("clockToleranceSec"), tol)) checks.clock_tolerance = tol;
    const J *maxv = config.find("maxIdTokenAgeSec");
    if (maxv && maxv->type != JType::Null) {
      double age = 0;
      if (AsFloat(maxv, age)) {
        checks.has_max_id_age = true;
        checks.max_id_age = age;
      }
    }
    const J *strict = config.find("requireIdTokenTypAndAtHash");
    bool require = !(strict && strict->type == JType::Bool && !strict->b);
    checks.require_typ = require;
    checks.require_at_hash = require;
    try {
      checks.jwks = Keys(false);
    } catch (const std::exception &) {
    }
    return checks;
  }

  J IdToken(const std::string &token, const Checks &extra) {
    Checks checks = BuildChecks(extra);
    try {
      return ValidateIDToken(token, checks);
    } catch (const OidcError &e) {
      if (e.code != "signature") throw;
      {
        std::lock_guard<std::mutex> lock(mu);
        jwks_set = false;
      }
      try {
        checks.jwks = Keys(true);
      } catch (const std::exception &) {
        throw e;
      }
      return ValidateIDToken(token, checks);
    }
  }

  // The origin a DPoP nonce belongs to: the server that issued it.
  static std::string OriginOf(const std::string &url) {
    URL u;
    if (!ParseURL(url, u)) return url;
    return u.origin();
  }

  void RememberNonce(const std::string &url, const std::string &nonce) {
    if (nonce.empty()) return;
    std::lock_guard<std::mutex> lock(mu);
    nonces[OriginOf(url)] = nonce;
  }

  // A DPoP proof (RFC 9449 section 4.2) for one request. ath is set for a resource
  // request made with an access token.
  std::string Proof(const std::string &method, const std::string &url, const std::string &access_token) {
    URL u;
    if (!ParseURL(url, u)) throw OidcError("protocol", "a DPoP proof needs an http(s) URL, not " + url);
    std::string htu = u.origin() + (u.path.empty() ? "/" : u.path);
    std::string nonce;
    {
      std::lock_guard<std::mutex> lock(mu);
      auto it = nonces.find(u.origin());
      if (it != nonces.end()) nonce = it->second;
    }
    J header = J::obj();
    header.set("typ", J::str("dpop+jwt"));
    header.set("alg", J::str("ES256"));
    header.set("jwk", dpop_jwk);
    J claims = J::obj();
    claims.set("jti", J::str(Uuid4()));
    claims.set("htm", J::str(method));
    claims.set("htu", J::str(htu));
    claims.set("iat", J::integer(static_cast<std::int64_t>(std::time(nullptr))));
    if (!nonce.empty()) claims.set("nonce", J::str(nonce));
    if (!access_token.empty()) claims.set("ath", J::str(SHA256B64URL(access_token)));
    std::string signing = B64URLEncode(Stringify(header)) + "." + B64URLEncode(Stringify(claims));
    auto sig = SignJWS(dpop_key, "ES256", reinterpret_cast<const uint8_t *>(signing.data()), signing.size());
    return signing + "." + B64URLEncode(sig.data(), sig.size());
  }

  void ApplyClientAuth(std::vector<std::pair<std::string, std::string>> &fields,
                       std::vector<std::pair<std::string, std::string>> &headers) {
    std::string method = Sprint(config.find("tokenEndpointAuthMethod"));
    std::string client_id = Sprint(config.find("clientId"));
    std::string audience = Sprint(metadata.find("issuer"));
    if (method == "client_secret_basic") {
      std::string raw = FormEncode(client_id) + ":" + FormEncode(Sprint(config.find("clientSecret")));
      headers.emplace_back("Authorization", "Basic " + B64StdEncode(reinterpret_cast<const uint8_t *>(raw.data()), raw.size()));
      return;
    }
    if (method == "client_secret_post") {
      AddField(fields, "client_id", client_id);
      AddField(fields, "client_secret", Sprint(config.find("clientSecret")));
      return;
    }
    if (!key) throw OidcError("config", "private_key_jwt has no signing key");
    std::string alg = Sprint(config.find("privateKeyAlg"));
    if (alg.empty()) alg = "RS256";
    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    J header = J::obj();
    header.set("alg", J::str(alg));
    header.set("typ", J::str("JWT"));
    J claims = J::obj();
    claims.set("iss", J::str(client_id));
    claims.set("sub", J::str(client_id));
    claims.set("aud", J::str(audience));
    claims.set("jti", J::str(Uuid4()));
    claims.set("iat", J::integer(now));
    claims.set("exp", J::integer(now + 60));
    std::string hb = Stringify(header);
    std::string pb = Stringify(claims);
    std::string signing = B64URLEncode(hb) + "." + B64URLEncode(pb);
    auto sig = SignJWS(key, alg, reinterpret_cast<const uint8_t *>(signing.data()), signing.size());
    std::string assertion = signing + "." + B64URLEncode(sig.data(), sig.size());
    AddField(fields, "client_id", client_id);
    AddField(fields, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    AddField(fields, "client_assertion", assertion);
  }

  // POST to the PAR or token endpoint. With DPoP every attempt carries a fresh
  // proof (and a fresh client assertion), and a 400 use_dpop_nonce is answered
  // once with the nonce it gave. proofed says whether a proof was sent.
  J PostForm(const std::string &endpoint, const std::vector<std::pair<std::string, std::string>> &fields_in,
             const std::vector<std::string> &order_in, bool *proofed = nullptr) {
    for (int attempt = 0;; attempt++) {
      auto fields = fields_in;
      auto order = order_in;
      std::vector<std::pair<std::string, std::string>> headers = {
          {"accept", "application/json"}, {"content-type", "application/x-www-form-urlencoded"}};
      ApplyClientAuth(fields, headers);
      bool sent = false;
      if (dpop_key) {
        headers.emplace_back("DPoP", Proof("POST", endpoint, ""));
        sent = true;
      }
      for (const auto &kv : fields) {
        if (!ContainsString(order, kv.first)) order.push_back(kv.first);
      }
      std::string encoded = FormBody(fields, order);
      HttpResult answer = Send(endpoint, "POST", headers, &encoded, Ca(), "protocol");
      std::string nonce = answer.header("DPoP-Nonce");
      RememberNonce(endpoint, nonce);
      J doc = J::obj();
      if (!answer.body.empty()) {
        try {
          J parsed = Parse(answer.body);
          if (parsed.type == JType::Object) doc = std::move(parsed);
        } catch (const std::exception &) {
          throw OidcError("protocol", endpoint + " answered " + std::to_string(answer.status) + " with no JSON");
        }
      }
      if (answer.status != 200 && answer.status != 201) {
        std::string oauth;
        const J *err = doc.find("error");
        if (err && err->type == JType::String) oauth = err->s;
        if (sent && attempt == 0 && oauth == "use_dpop_nonce" && !nonce.empty()) continue;
        std::string description;
        const J *ed = doc.find("error_description");
        if (ed && ed->type == JType::String) description = ed->s;
        std::string message = endpoint + " answered " + std::to_string(answer.status);
        if (!oauth.empty()) message += ": " + oauth;
        if (!description.empty()) message += ": " + description;
        throw OidcError("protocol", message, oauth);
      }
      if (proofed) *proofed = sent;
      return doc;
    }
  }

  TokenResp Token(std::vector<std::pair<std::string, std::string>> body, std::vector<std::string> order) {
    bool proofed = false;
    J parsed = PostForm(Sprint(metadata.find("token_endpoint")), body, order, &proofed);
    const J *access = parsed.find("access_token");
    const J *ttype = parsed.find("token_type");
    if (!access || access->type != JType::String || access->s.empty())
      throw OidcError("protocol", "the token response has no access_token");
    if (!ttype || ttype->type != JType::String || ttype->s.empty())
      throw OidcError("protocol", "the token response has no token_type");
    // RFC 9449 section 5: a proof asks for a DPoP-bound token, and its absence for a Bearer one.
    std::string want = proofed ? "dpop" : "bearer";
    if (ToLower(ttype->s) != want) {
      if (proofed)
        throw OidcError("protocol", "the token request carried a DPoP proof and the token_type is " + ttype->s +
                                        ", not DPoP");
      throw OidcError("protocol", "the token request carried no DPoP proof and the token_type is " + ttype->s +
                                      ", not Bearer");
    }
    TokenResp out;
    out.access = access->s;
    out.type = ttype->s;
    if (const J *id = parsed.find("id_token"); id && id->type == JType::String) out.id_token = id->s;
    if (const J *rt = parsed.find("refresh_token"); rt && rt->type == JType::String) out.refresh = rt->s;
    double exp = 0;
    if (AsFloat(parsed.find("expires_in"), exp)) {
      out.has_expires = true;
      out.expires_in = exp;
    }
    if (const J *sc = parsed.find("scope"); sc && sc->type == JType::String) out.scope = sc->s;
    return out;
  }

  std::map<std::string, std::string> ResourceHeaders(const std::string &method, const std::string &url,
                                                     const std::string &access_token) {
    std::map<std::string, std::string> out;
    if (dpop_key) {
      out["Authorization"] = "DPoP " + access_token;
      out["DPoP"] = Proof(method, url, access_token);
    } else {
      out["Authorization"] = "Bearer " + access_token;
    }
    return out;
  }

  bool ResourceChallenge(const std::string &url, int status, const std::string &www, const std::string &nonce) {
    RememberNonce(url, nonce);
    return dpop_key && !nonce.empty() && AsksForNonce(status, www);
  }

  ResourceResponse Resource(const std::string &method, const std::string &url, const std::string &access_token,
                            const std::vector<std::pair<std::string, std::string>> &extra, const std::string *body,
                            const std::string &code) {
    for (int attempt = 0;; attempt++) {
      std::vector<std::pair<std::string, std::string>> headers = extra;
      for (const auto &kv : ResourceHeaders(method, url, access_token)) headers.emplace_back(kv.first, kv.second);
      HttpResult answer = Send(url, method, headers, body, Ca(), code);
      bool again = ResourceChallenge(url, answer.status, answer.header("WWW-Authenticate"), answer.header("DPoP-Nonce"));
      if (again && attempt == 0) continue;
      ResourceResponse out;
      out.status = answer.status;
      out.content_type = answer.content_type;
      out.body = answer.body;
      out.headers = answer.headers;
      return out;
    }
  }

  void Remember(const std::string &code) {
    double now = NowSec();
    unsigned char sum[32];
    unsigned int n = 0;
    EVP_Digest(code.data(), code.size(), sum, &n, EVP_sha256(), nullptr);
    std::string key = HexEncode(sum, n);
    std::lock_guard<std::mutex> lock(mu);
    double cutoff = now - 10 * 60;
    for (auto it = used.begin(); it != used.end();) {
      if (it->second < cutoff) it = used.erase(it);
      else ++it;
    }
    if (used.count(key)) throw OidcError("validation", "this authorization code was already used");
    used[key] = now;
  }
};

RelyingParty::RelyingParty(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
RelyingParty::~RelyingParty() = default;

// Every way of creating a relying party resolves the configuration first, so the
// defaults, the redirect rule and the metadata checks are the same for all of them.
std::unique_ptr<RelyingParty> RelyingParty::Create(const std::string &config_json) {
  J config;
  try {
    config = Parse(config_json);
  } catch (const std::exception &e) {
    throw OidcError("config", std::string("the configuration must be a JSON object: ") + e.what());
  }
  if (config.type != JType::Object) throw OidcError("config", "the configuration must be a JSON object");
  return Make(Stringify(Resolve(config, "")));
}

std::unique_ptr<RelyingParty> RelyingParty::Make(const std::string &resolved_json) {
  J config = Parse(resolved_json);
  std::string method = Sprint(config.find("tokenEndpointAuthMethod"));
  if (method == "private_key_jwt" && Sprint(config.find("privateKeyPem")).empty())
    throw OidcError("config", "private_key_jwt needs a private key");
  if (method != "private_key_jwt" && Sprint(config.find("clientSecret")).empty())
    throw OidcError("config", Fmt("%s needs a client secret", method.c_str()));
  bool allow = IsExactTrue(config.find("allowInsecure"));
  std::string issuer = Sprint(config.find("issuer"));
  if (!allow && !issuer.empty() && SchemeOf(issuer) == "http")
    throw OidcError("config", "issuer must use https (set allowInsecure for a development provider)");
  J metadata;
  const J *embedded = config.find("metadata");
  if (embedded && embedded->type == JType::Object) {
    metadata = *embedded;
  } else {
    std::string metadata_url = Sprint(config.find("metadataUrl"));
    if (metadata_url.empty()) throw OidcError("config", "metadataUrl or metadata is required");
    if (!allow && SchemeOf(metadata_url) != "https")
      throw OidcError("config", "metadataUrl must use https (set allowInsecure for a development provider)");
    metadata = DiscoverProvider(metadata_url, CaOf(config));
  }
  if (!allow) {
    for (const auto &kv : metadata.o) {
      if (kv.second.type != JType::String || !StartsWith(kv.second.s, "http:")) continue;
      if (EndsWith(kv.first, "endpoint") || kv.first == "jwks_uri" || kv.first == "issuer")
        throw OidcError("discovery", Fmt("%s must use https: %s", kv.first.c_str(), kv.second.s.c_str()));
    }
  }
  std::vector<std::string> methods;
  if (AsStringList(metadata.find("token_endpoint_auth_methods_supported"), methods) && !methods.empty() &&
      !ContainsString(methods, method))
    throw OidcError("discovery", Fmt("the provider does not advertise %s", method.c_str()));
  std::vector<std::string> challenges;
  if (AsStringList(metadata.find("code_challenge_methods_supported"), challenges) && !challenges.empty() &&
      !ContainsString(challenges, "S256"))
    throw OidcError("discovery", "the provider does not advertise PKCE S256");
  std::string par = Sprint(config.find("par"));
  bool par_required = IsExactTrue(metadata.find("require_pushed_authorization_requests"));
  bool has_par = !Sprint(metadata.find("pushed_authorization_request_endpoint")).empty();
  if (par_required && par == "never")
    throw OidcError("config", "the provider requires pushed authorization requests, and par is never");
  if ((par_required || par == "always") && !has_par)
    throw OidcError("discovery", "pushed authorization requests are required, and the provider has no "
                                 "pushed_authorization_request_endpoint");
  auto impl = std::make_unique<Impl>();
  std::string pem = Sprint(config.find("privateKeyPem"));
  if (!pem.empty()) {
    std::string alg = Sprint(config.find("privateKeyAlg"));
    if (alg.empty()) alg = "RS256";
    impl->key = LoadPrivateKey(pem, alg);
  }
  std::string pinned = Sprint(config.find("idTokenSignedResponseAlg"));
  std::vector<std::string> listed;
  AsStringList(config.find("idTokenSigningAlgs"), listed);
  std::vector<std::string> advertised;
  AsStringList(metadata.find("id_token_signing_alg_values_supported"), advertised);
  impl->algs = IDTokenAlgorithms(advertised, pinned, listed);
  std::string dpop = Sprint(config.find("dpop"));
  if (dpop.empty()) dpop = "auto";
  std::vector<std::string> dpop_algs;
  AsStringList(metadata.find("dpop_signing_alg_values_supported"), dpop_algs);
  bool es256 = ContainsString(dpop_algs, "ES256");
  if (dpop == "always" && dpop_algs.empty())
    throw OidcError("discovery", "dpop is always, and the provider does not advertise dpop_signing_alg_values_supported");
  if (dpop == "always" && !es256)
    throw OidcError("discovery", "dpop is always, and the provider does not advertise ES256 for DPoP proofs");
  if (dpop != "never" && es256) {
    std::string dpop_pem = Sprint(config.find("dpopKeyPem"));
    impl->dpop_key = dpop_pem.empty() ? GenerateP256() : LoadPrivateKey(dpop_pem, "ES256");
    impl->dpop_jwk = PublicJWKOfP256(impl->dpop_key);
    impl->dpop_jkt = JWKThumbprint(impl->dpop_jwk);
  }
  impl->config = std::move(config);
  impl->metadata = std::move(metadata);
  return std::unique_ptr<RelyingParty>(new RelyingParty(std::move(impl)));
}

std::unique_ptr<RelyingParty> RelyingParty::FromFile(const std::string &path) {
  std::string body;
  try {
    body = ReadFile(path);
  } catch (const std::exception &e) {
    throw OidcError("config", e.what());
  }
  J parsed;
  try {
    parsed = Parse(body);
  } catch (const std::exception &e) {
    throw OidcError("config", std::string("could not read ") + path + ": " + e.what());
  }
  if (parsed.type != JType::Object) throw OidcError("config", "the configuration must be a JSON object");
  std::filesystem::path abs = std::filesystem::absolute(path);
  J resolved = Resolve(parsed, abs.parent_path().string());
  return Make(Stringify(resolved));
}

Transaction RelyingParty::Authorize() { return Authorize(AuthorizeOptions{}); }

Transaction RelyingParty::Authorize(const AuthorizeOptions &opts) {
  std::string redirect = Sprint(impl_->config.find("redirectUri"));
  if (!opts.redirect_uri.empty())
    redirect = CheckRedirect(opts.redirect_uri, "redirect_uri");
  std::string scope = opts.scope.empty() ? Sprint(impl_->config.find("scopes")) : opts.scope;
  std::string acr_values = JoinSpace(Fields(opts.acr_values.empty() ? Sprint(impl_->config.find("acrValues"))
                                                                     : opts.acr_values));
  Transaction txn;
  try {
    txn.state = RandomToken();
    txn.nonce = RandomToken();
    txn.code_verifier = RandomToken();
  } catch (const std::exception &e) {
    throw OidcError("protocol", e.what());
  }
  txn.redirect_uri = redirect;
  txn.has_max_age = opts.has_max_age;
  txn.max_age = opts.max_age;
  txn.expected_sub = opts.expected_sub;
  txn.acr_values = acr_values;
  std::vector<std::pair<std::string, std::string>> params = {
      {"response_type", "code"},
      {"client_id", Sprint(impl_->config.find("clientId"))},
      {"redirect_uri", redirect},
      {"scope", scope},
      {"state", txn.state},
      {"nonce", txn.nonce},
      {"code_challenge", CodeChallengeS256(txn.code_verifier)},
      {"code_challenge_method", "S256"},
  };
  std::vector<std::string> order = {"response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
                                    "code_challenge", "code_challenge_method"};
  if (!opts.prompt.empty()) {
    params.emplace_back("prompt", opts.prompt);
    order.push_back("prompt");
  }
  if (!opts.login_hint.empty()) {
    params.emplace_back("login_hint", opts.login_hint);
    order.push_back("login_hint");
  }
  if (opts.has_max_age) {
    params.emplace_back("max_age", TrimFloat(opts.max_age));
    order.push_back("max_age");
  }
  if (!acr_values.empty()) {
    params.emplace_back("acr_values", acr_values);
    order.push_back("acr_values");
  }
  if (impl_->dpop_key) {
    // RFC 9449 section 10: binds the authorization code to this client's DPoP key.
    params.emplace_back("dpop_jkt", impl_->dpop_jkt);
    order.push_back("dpop_jkt");
  }
  std::string par_endpoint = Sprint(impl_->metadata.find("pushed_authorization_request_endpoint"));
  std::string mode = Sprint(impl_->config.find("par"));
  bool required = IsExactTrue(impl_->metadata.find("require_pushed_authorization_requests"));
  bool use_par = mode == "always" || required || (mode == "auto" && !par_endpoint.empty());
  if (use_par && par_endpoint.empty())
    throw OidcError("discovery", "pushed authorization requests are required, and the provider has no pushed "
                                 "authorization endpoint");
  if (use_par) {
    J pushed = impl_->PostForm(par_endpoint, params, order);
    const J *request_uri = pushed.find("request_uri");
    if (!request_uri || request_uri->type != JType::String || request_uri->s.empty())
      throw OidcError("protocol", "the pushed authorization response has no request_uri");
    txn.url = WithQuery(Sprint(impl_->metadata.find("authorization_endpoint")),
                        {{"client_id", Sprint(impl_->config.find("clientId"))}, {"request_uri", request_uri->s}},
                        {"client_id", "request_uri"});
    return txn;
  }
  txn.url = WithQuery(Sprint(impl_->metadata.find("authorization_endpoint")), params, order);
  return txn;
}

Login RelyingParty::Complete(const std::map<std::string, std::string> &query, const Transaction &txn) {
  return Complete(query, txn, std::string());
}

Login RelyingParty::Complete(const std::map<std::string, std::string> &query, const Transaction &txn,
                             const std::string &session_id) {
  for (const char *name : kFront) {
    if (query.count(name))
      throw OidcError("validation", Fmt("%s was returned on the redirect, and a code-flow client refuses it", name));
  }
  auto eit = query.find("error");
  if (eit != query.end() && !eit->second.empty()) {
    std::string message = eit->second;
    auto dit = query.find("error_description");
    if (dit != query.end() && !dit->second.empty()) message += ": " + dit->second;
    throw OidcError("protocol", message, eit->second);
  }
  std::string state = query.count("state") ? query.at("state") : "";
  if (txn.state.empty() || !SameText(state, txn.state))
    throw OidcError("validation", "the callback state does not match this sign-in");
  if (query.count("iss")) {
    if (query.at("iss") != Sprint(impl_->metadata.find("issuer")))
      throw OidcError("validation", Fmt("iss mismatch in the callback: %s", query.at("iss").c_str()));
  } else if (IsExactTrue(impl_->metadata.find("authorization_response_iss_parameter_supported"))) {
    throw OidcError("validation", "iss is missing from the callback, and the provider requires it");
  }
  std::string code = query.count("code") ? query.at("code") : "";
  if (code.empty()) throw OidcError("validation", "the callback has no code");
  impl_->Remember(code);
  TokenResp tokens = impl_->Token({{"grant_type", "authorization_code"},
                                   {"code", code},
                                   {"redirect_uri", txn.redirect_uri},
                                   {"code_verifier", txn.code_verifier}},
                                  {"grant_type", "code", "redirect_uri", "code_verifier"});
  if (tokens.id_token.empty()) throw OidcError("protocol", "the token response has no id_token");
  Checks extra;
  extra.has_nonce = true;
  extra.nonce = txn.nonce;
  extra.access_token = tokens.access;
  extra.code = code;
  extra.acr_values = Fields(txn.acr_values);
  if (txn.has_max_age) {
    extra.has_max_age = true;
    extra.max_age = txn.max_age;
  }
  J claims = impl_->IdToken(tokens.id_token, extra);
  if (!txn.expected_sub.empty() && Sprint(claims.find("sub")) != txn.expected_sub)
    throw OidcError("validation", "the provider signed in a different account from the one requested");
  Login login = LoginFrom(tokens, claims);
  login.session_id = session_id.empty() ? RandomToken() : session_id;
  impl_->Sessions()->Put(login.session_id, TokensOf(login));
  return login;
}

Login RelyingParty::Refresh(const std::string &refresh_token, const std::string &scope, const Login *previous) {
  if (refresh_token.empty()) throw OidcError("protocol", "there is no refresh token");
  std::vector<std::pair<std::string, std::string>> body = {{"grant_type", "refresh_token"}, {"refresh_token", refresh_token}};
  std::vector<std::string> order = {"grant_type", "refresh_token"};
  if (!scope.empty()) {
    body.emplace_back("scope", scope);
    order.push_back("scope");
  }
  TokenResp tokens = impl_->Token(body, order);
  J claims;
  bool have_claims = false;
  std::string id_token = tokens.id_token;
  if (previous) {
    try {
      claims = Parse(previous->claims_json);
      have_claims = claims.type == JType::Object;
    } catch (const std::exception &) {
    }
    if (id_token.empty()) id_token = previous->id_token;
  }
  if (!tokens.id_token.empty()) {
    if (!previous)
      throw OidcError("validation", "the refresh returned an ID token and there is no previous sign-in to check it against");
    // acr is not checked again on a refresh.
    Checks extra;
    extra.access_token = tokens.access;
    extra.has_previous = true;
    extra.previous_sub = previous->subject;
    claims = impl_->IdToken(tokens.id_token, extra);
    have_claims = true;
    id_token = tokens.id_token;
  }
  if (!have_claims || id_token.empty() || (previous == nullptr && tokens.id_token.empty()))
    throw OidcError("protocol", "the refresh returned no ID token and no previous sign-in was given");
  if (tokens.refresh.empty()) tokens.refresh = refresh_token;
  tokens.id_token = id_token;
  Login login = LoginFrom(tokens, claims);
  if (previous) login.session_id = previous->session_id;
  return login;
}

Access RelyingParty::ClientCredentials(const std::string &scope_in) {
  std::string scope = scope_in.empty() ? "ssf.manage" : scope_in;
  double now = NowSec();
  {
    std::lock_guard<std::mutex> lock(impl_->mu);
    if (impl_->cc_set && impl_->cc_scope == scope && impl_->cc_until > now) return impl_->cc_token;
  }
  TokenResp tokens = impl_->Token({{"grant_type", "client_credentials"}, {"scope", scope}}, {"grant_type", "scope"});
  Access token;
  token.access_token = tokens.access;
  token.token_type = tokens.type;
  token.scope = tokens.scope;
  double until = now + 60;
  if (tokens.has_expires) {
    token.expires_at = NowSec() + tokens.expires_in;
    token.has_expires = true;
    until = token.expires_at - 30;
  }
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->cc_scope = scope;
  impl_->cc_token = token;
  impl_->cc_until = until;
  impl_->cc_set = true;
  return token;
}

std::string RelyingParty::UserInfoSubject(const std::string &access_token, const std::string &expected_sub) {
  if (expected_sub.empty()) throw OidcError("validation", "userinfo needs the subject to check the response against");
  std::string endpoint = Sprint(impl_->metadata.find("userinfo_endpoint"));
  if (endpoint.empty()) throw OidcError("discovery", "the provider has no userinfo_endpoint");
  ResourceResponse answer =
      impl_->Resource("GET", endpoint, access_token, {{"accept", "application/json, application/jwt"}}, nullptr, "protocol");
  if (answer.status == 401) throw OidcError("protocol", "userinfo refused the access token", "invalid_token");
  if (answer.status != 200) throw OidcError("protocol", Fmt("userinfo answered %d", answer.status));
  if (ToLower(answer.content_type).find("application/jwt") != std::string::npos) {
    Checks extra;
    extra.algorithms = impl_->algs;
    extra.relax_typ = true;
    J claims = impl_->IdToken(Trim(answer.body), extra);
    if (Sprint(claims.find("sub")) != expected_sub)
      throw OidcError("validation", "userinfo sub does not match the ID token sub");
    return Sprint(claims.find("sub"));
  }
  J body;
  try {
    body = Parse(answer.body);
  } catch (const std::exception &) {
    throw OidcError("protocol", "userinfo did not answer JSON");
  }
  if (body.type != JType::Object) throw OidcError("validation", "userinfo did not answer a JSON object");
  if (Sprint(body.find("sub")) != expected_sub)
    throw OidcError("validation", "userinfo sub does not match the ID token sub");
  return Sprint(body.find("sub"));
}

std::string RelyingParty::EndSessionURL(const EndSessionOptions &opts) {
  std::string endpoint = Sprint(impl_->metadata.find("end_session_endpoint"));
  if (endpoint.empty()) return {};
  std::string redirect = opts.post_logout_set ? opts.post_logout : Sprint(impl_->config.find("postLogoutRedirectUri"));
  std::vector<std::pair<std::string, std::string>> query;
  std::vector<std::string> order;
  if (!opts.id_token.empty()) {
    query.emplace_back("id_token_hint", opts.id_token);
    order.push_back("id_token_hint");
  }
  if (!redirect.empty()) {
    query.emplace_back("post_logout_redirect_uri", redirect);
    order.push_back("post_logout_redirect_uri");
  }
  query.emplace_back("client_id", Sprint(impl_->config.find("clientId")));
  order.push_back("client_id");
  if (!opts.logout_hint.empty()) {
    query.emplace_back("logout_hint", opts.logout_hint);
    order.push_back("logout_hint");
  }
  if (!opts.state.empty()) {
    query.emplace_back("state", opts.state);
    order.push_back("state");
  }
  return WithQuery(endpoint, query, order);
}

Access RelyingParty::SessionAccessToken(const std::string &session_id) {
  if (session_id.empty()) throw OidcError("validation", "a session identifier is required");
  auto store = impl_->Sessions();
  auto fresh = [](const SessionTokens &tokens, Access &out) {
    if (tokens.access_token.empty()) return false;
    if (tokens.has_expires && tokens.expires_at - NowSec() <= kSessionMargin) return false;
    out.access_token = tokens.access_token;
    out.token_type = tokens.token_type;
    out.scope = tokens.scope;
    out.expires_at = tokens.expires_at;
    out.has_expires = tokens.has_expires;
    return true;
  };
  SessionTokens tokens;
  if (!store->Get(session_id, tokens)) throw OidcError("validation", "there is no signed-in session " + session_id);
  Access access;
  if (fresh(tokens, access)) return access;
  // One refresh at a time, so a rotated refresh token is not spent twice; a
  // caller that waited finds the entry the first one wrote.
  std::lock_guard<std::mutex> lock(impl_->refresh_mu);
  if (!store->Get(session_id, tokens)) throw OidcError("validation", "there is no signed-in session " + session_id);
  if (fresh(tokens, access)) return access;
  if (tokens.refresh_token.empty()) {
    store->Remove(session_id);
    throw OidcError("protocol", "the session's access token expired and there is no refresh token", "invalid_grant");
  }
  Login previous;
  previous.subject = tokens.subject;
  previous.claims_json = tokens.claims_json;
  previous.id_token = tokens.id_token;
  previous.session_id = session_id;
  Login renewed;
  try {
    renewed = Refresh(tokens.refresh_token, "", &previous);
  } catch (...) {
    store->Remove(session_id);
    throw;
  }
  store->Put(session_id, TokensOf(renewed));
  access.access_token = renewed.access_token;
  access.token_type = renewed.token_type;
  access.scope = renewed.scope;
  access.expires_at = renewed.expires_at;
  access.has_expires = renewed.has_expires;
  return access;
}

void RelyingParty::RemoveSession(const std::string &session_id) {
  if (session_id.empty()) return;
  impl_->Sessions()->Remove(session_id);
}

void RelyingParty::SetSessionStore(std::shared_ptr<SessionStore> store) {
  std::lock_guard<std::mutex> lock(impl_->mu);
  impl_->sessions = store ? std::move(store) : std::make_shared<MemorySessionStore>();
}

ResourceResponse RelyingParty::ResourceRequest(const std::string &method, const std::string &url,
                                               const std::string &access_token,
                                               const std::vector<std::pair<std::string, std::string>> &headers,
                                               const std::string *body) {
  if (access_token.empty()) throw OidcError("protocol", "a resource request needs an access token");
  return impl_->Resource(method.empty() ? "GET" : method, url, access_token, headers, body, "protocol");
}

std::map<std::string, std::string> RelyingParty::ResourceHeaders(const std::string &method, const std::string &url,
                                                                 const std::string &access_token) {
  return impl_->ResourceHeaders(method.empty() ? "GET" : method, url, access_token);
}

bool RelyingParty::ResourceChallenge(const std::string &url, int status, const std::string &www_authenticate,
                                     const std::string &dpop_nonce) {
  return impl_->ResourceChallenge(url, status, www_authenticate, dpop_nonce);
}

bool RelyingParty::dpop() const { return impl_->dpop_key != nullptr; }
std::string RelyingParty::dpop_jkt() const { return impl_->dpop_jkt; }

bool RelyingParty::signals_off() const {
  const J *s = impl_->config.find("signals");
  return s && s->type == JType::Bool && !s->b;
}

std::string RelyingParty::client_id() const { return Sprint(impl_->config.find("clientId")); }
std::string RelyingParty::issuer() const { return Sprint(impl_->metadata.find("issuer")); }
std::string RelyingParty::tls_ca() const { return impl_->Ca(); }

std::string RelyingParty::ssf_transmitter() const {
  const J *ssf = impl_->config.find("ssf");
  if (!ssf || ssf->type != JType::Object) return {};
  return Sprint(ssf->find("transmitter"));
}

int RelyingParty::poll_interval_ms() const {
  const J *ssf = impl_->config.find("ssf");
  if (!ssf || ssf->type != JType::Object) return 0;
  double v = 0;
  if (!AsFloat(ssf->find("pollIntervalMs"), v)) return 0;
  return static_cast<int>(v);
}

SignalsReceiver::Options SignalsOptionsFor(RelyingParty &rp, const std::string &scope_in) {
  std::string scope = scope_in.empty() ? "ssf.manage" : scope_in;
  SignalsReceiver::Options opts;
  RelyingParty *party = &rp;
  opts.request_headers = [party, scope](const std::string &method, const std::string &url) {
    Access access = party->ClientCredentials(scope);
    return party->ResourceHeaders(method, url, access.access_token);
  };
  opts.on_response = [party](const std::string &url, int status, const std::string &www, const std::string &nonce) {
    return party->ResourceChallenge(url, status, www, nonce);
  };
  opts.tls_ca = rp.tls_ca();
  opts.poll_interval_ms = rp.poll_interval_ms();
  return opts;
}

}  // namespace iya
