// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_OIDC_HPP
#define IYA_OIDC_HPP

#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace iya {

// Public failure. what() is the message. code is config, discovery, protocol,
// validation, signature, or ssf. oauth_error is set when the provider named one.
class OidcError : public std::runtime_error {
 public:
  std::string code;
  std::string oauth_error;
  OidcError(std::string code, std::string message, std::string oauth_error = {});
};

const char *DefaultScopes();

std::string HashClaim(const std::string &value, const std::string &alg);
const char *EventURI(const char *name);

// payload JSON of a compact JWS verified against a JWKS document {"keys":[...]}.
std::string VerifyCompactJWSPayload(const std::string &token, const std::string &jwks_json);

struct SubjectFields {
  std::string person;
  std::string email;
  std::string idp_session;
  int count = 0;
};

SubjectFields SubjectOfJSON(const std::string &sub_id_json, const std::string &issuer);

// Resolved configuration JSON. signals is omitted when CAEP/RISC stay on.
std::string ResolveConfigJSON(const std::string &raw_json, const std::string &base_dir);

struct Transaction {
  std::string state;
  std::string nonce;
  std::string code_verifier;
  std::string redirect_uri;
  std::string url;
  bool has_max_age = false;
  double max_age = 0;
  std::string expected_sub;
};

struct AuthorizeOptions {
  std::string redirect_uri;
  std::string scope;
  std::string prompt;
  std::string login_hint;
  bool has_max_age = false;
  double max_age = 0;
  std::string acr_values;
  std::string expected_sub;
};

struct Login {
  std::string subject;
  std::string issuer;
  std::string email;
  std::string name;
  std::string preferred_username;
  std::string sid;
  std::string access_token;
  std::string id_token;
  std::string refresh_token;
  std::string token_type;
  std::string scope;
  std::string claims_json;
  double expires_at = 0;
  bool has_expires = false;
};

struct Access {
  std::string access_token;
  std::string token_type;
  std::string scope;
  double expires_at = 0;
  bool has_expires = false;
};

struct EndSessionOptions {
  std::string id_token;
  bool post_logout_set = false;
  std::string post_logout;
  std::string state;
  std::string logout_hint;
};

class RelyingParty {
 public:
  ~RelyingParty();
  static std::unique_ptr<RelyingParty> Create(const std::string &config_json);
  static std::unique_ptr<RelyingParty> FromFile(const std::string &path);

  Transaction Authorize();
  Transaction Authorize(const AuthorizeOptions &opts);
  Login Complete(const std::map<std::string, std::string> &query, const Transaction &txn);
  Login Refresh(const std::string &refresh_token, const std::string &scope, const Login *previous);
  Access ClientCredentials(const std::string &scope);
  std::string UserInfoSubject(const std::string &access_token, const std::string &expected_sub);
  std::string EndSessionURL(const EndSessionOptions &opts);

  bool signals_off() const;
  std::string client_id() const;
  std::string issuer() const;
  std::string tls_ca() const;
  std::string ssf_transmitter() const;
  int poll_interval_ms() const;

 private:
  struct Impl;
  explicit RelyingParty(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

struct SignalEvent {
  std::string type;
  std::string jti;
  bool ended = false;
  std::vector<std::string> sessions;
  std::map<std::string, std::string> subject;
};

class SignalsReceiver {
 public:
  struct Options {
    std::function<std::map<std::string, std::string>()> headers;
    int poll_interval_ms = 0;
    std::string description;
    std::string tls_ca;
    std::vector<std::string> events_requested;
    std::vector<std::string> end_on;
  };

  ~SignalsReceiver();
  static std::unique_ptr<SignalsReceiver> New(
      const std::string &transmitter,
      std::function<void(const std::vector<std::string> &, const SignalEvent &)> on_end,
      Options opts);

  void On(const std::string &event_type, std::function<void(const SignalEvent &)> handler);
  void Start();
  void Stop();
  bool PollOnce();
  void Track(const std::string &local_id, const std::string &person, const std::string &email,
             const std::string &idp_session);
  void Untrack(const std::string &local_id);
  void Verify(const std::string &state);
  std::string stream_id() const;

 private:
  struct Impl;
  explicit SignalsReceiver(std::shared_ptr<Impl> impl);
  std::shared_ptr<Impl> impl_;
};

}  // namespace iya

#endif
