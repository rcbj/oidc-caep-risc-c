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
  // The acr_values this sign-in asked for (space-separated). When it is not empty,
  // Complete requires the ID token's acr to be one of them.
  std::string acr_values;
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
  // The key of this sign-in's entry in the session token cache: the one the
  // application passed to Complete, or one the library chose.
  std::string session_id;
  std::string acr;
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

// The tokens of one completed sign-in, as the session token cache keeps them.
struct SessionTokens {
  std::string access_token;
  std::string token_type;
  std::string refresh_token;
  std::string id_token;
  std::string scope;
  std::string subject;
  std::string claims_json;
  double expires_at = 0;
  bool has_expires = false;
};

// Where the session token cache lives. The default is MemorySessionStore; an
// application that runs several processes supplies one over a shared store.
// Every method may be called from several threads at once.
class SessionStore {
 public:
  virtual ~SessionStore();
  virtual bool Get(const std::string &session_id, SessionTokens &out) = 0;
  virtual void Put(const std::string &session_id, const SessionTokens &tokens) = 0;
  virtual void Remove(const std::string &session_id) = 0;
};

class MemorySessionStore : public SessionStore {
 public:
  MemorySessionStore();
  ~MemorySessionStore() override;
  bool Get(const std::string &session_id, SessionTokens &out) override;
  void Put(const std::string &session_id, const SessionTokens &tokens) override;
  void Remove(const std::string &session_id) override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// The answer to a resource request made with an access token.
struct ResourceResponse {
  int status = 0;
  std::string content_type;
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string header(const std::string &name) const;
};

class RelyingParty {
 public:
  ~RelyingParty();
  static std::unique_ptr<RelyingParty> Create(const std::string &config_json);
  static std::unique_ptr<RelyingParty> FromFile(const std::string &path);

  Transaction Authorize();
  Transaction Authorize(const AuthorizeOptions &opts);
  // Both forms keep the tokens in the session token cache: under session_id, or
  // under a new identifier returned in Login::session_id.
  Login Complete(const std::map<std::string, std::string> &query, const Transaction &txn);
  Login Complete(const std::map<std::string, std::string> &query, const Transaction &txn,
                 const std::string &session_id);
  Login Refresh(const std::string &refresh_token, const std::string &scope, const Login *previous);
  Access ClientCredentials(const std::string &scope);
  std::string UserInfoSubject(const std::string &access_token, const std::string &expected_sub);
  std::string EndSessionURL(const EndSessionOptions &opts);

  // A valid access token for a session: the cached one while it has more than
  // 30 seconds left, otherwise one from the refresh token (the cache is updated).
  // A failed refresh removes the entry and throws.
  Access SessionAccessToken(const std::string &session_id);
  void RemoveSession(const std::string &session_id);
  void SetSessionStore(std::shared_ptr<SessionStore> store);

  // A request to a resource server with an access token from this relying party:
  // Bearer, or DPoP with a proof (and one retry on a use_dpop_nonce challenge).
  ResourceResponse ResourceRequest(const std::string &method, const std::string &url, const std::string &access_token,
                                   const std::vector<std::pair<std::string, std::string>> &headers = {},
                                   const std::string *body = nullptr);
  // The Authorization (and DPoP) headers for one resource request.
  std::map<std::string, std::string> ResourceHeaders(const std::string &method, const std::string &url,
                                                     const std::string &access_token);
  // Remembers a DPoP-Nonce from a resource response; true when the request should
  // be sent once more because the resource server asked for a nonce.
  bool ResourceChallenge(const std::string &url, int status, const std::string &www_authenticate,
                         const std::string &dpop_nonce);
  bool dpop() const;
  std::string dpop_jkt() const;

  bool signals_off() const;
  std::string client_id() const;
  std::string issuer() const;
  std::string tls_ca() const;
  std::string ssf_transmitter() const;
  int poll_interval_ms() const;

 private:
  struct Impl;
  explicit RelyingParty(std::unique_ptr<Impl> impl);
  static std::unique_ptr<RelyingParty> Make(const std::string &resolved_json);
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
    // Per-request headers, for a DPoP proof bound to the method and URL.
    std::function<std::map<std::string, std::string>(const std::string &method, const std::string &url)>
        request_headers;
    // Called with every response; true sends the request once more (a DPoP nonce).
    std::function<bool(const std::string &url, int status, const std::string &www_authenticate,
                       const std::string &dpop_nonce)>
        on_response;
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

// Receiver options whose every transmitter call carries a client-credentials
// token from rp (scope ssf.manage by default) with a DPoP proof when the token
// is DPoP-bound, and rp's tlsCa. rp must outlive the receiver.
SignalsReceiver::Options SignalsOptionsFor(RelyingParty &rp, const std::string &scope = "ssf.manage");

}  // namespace iya

#endif
