// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/oidc.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "b64.hpp"
#include "http.hpp"
#include "json.hpp"
#include "util.hpp"

namespace {

const char *kSession = "oidc_session";
const char *kTxn = "oidc_txn";

struct Session {
  iya::Login login;
  double expires = 0;
};

// One accepted Shared Signals event, for GET /live-status. Never a token.
struct LiveEvent {
  std::string type;
  std::string jti;
};

const char *kSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

struct Req {
  std::string method;
  std::string path;
  std::string query;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string header(const std::string &name) const {
    std::string want = name;
    for (char &c : want) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (const auto &kv : headers) {
      std::string got = kv.first;
      for (char &c : got) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      if (got == want) return kv.second;
    }
    return {};
  }
};

std::string Lower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool WriteAll(int fd, const std::string &data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n <= 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

bool ReadReq(int fd, Req &req) {
  std::string buf;
  while (buf.find("\r\n\r\n") == std::string::npos) {
    char tmp[4096];
    ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
    if (n <= 0) return false;
    buf.append(tmp, tmp + n);
    if (buf.size() > 1024 * 1024) return false;
  }
  auto head_end = buf.find("\r\n\r\n");
  std::string head = buf.substr(0, head_end);
  std::string rest = buf.substr(head_end + 4);
  auto line_end = head.find("\r\n");
  std::string start = line_end == std::string::npos ? head : head.substr(0, line_end);
  auto sp1 = start.find(' ');
  auto sp2 = start.find(' ', sp1 == std::string::npos ? 0 : sp1 + 1);
  if (sp1 == std::string::npos) return false;
  req.method = start.substr(0, sp1);
  std::string target = sp2 == std::string::npos ? start.substr(sp1 + 1) : start.substr(sp1 + 1, sp2 - sp1 - 1);
  auto q = target.find('?');
  if (q == std::string::npos) req.path = target;
  else {
    req.path = target.substr(0, q);
    req.query = target.substr(q + 1);
  }
  size_t at = line_end == std::string::npos ? head.size() : line_end + 2;
  size_t content_len = 0;
  while (at < head.size()) {
    auto next = head.find("\r\n", at);
    if (next == std::string::npos) next = head.size();
    if (next == at) break;
    std::string line = head.substr(at, next - at);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string name = line.substr(0, colon);
      std::string value = line.substr(colon + 1);
      while (!value.empty() && (value[0] == ' ' || value[0] == '\t')) value.erase(value.begin());
      req.headers.emplace_back(name, value);
      if (Lower(name) == "content-length") content_len = static_cast<size_t>(std::strtoul(value.c_str(), nullptr, 10));
    }
    if (next == head.size()) break;
    at = next + 2;
  }
  while (rest.size() < content_len) {
    char tmp[4096];
    ssize_t n = ::recv(fd, tmp, sizeof tmp, 0);
    if (n <= 0) return false;
    rest.append(tmp, tmp + n);
  }
  return true;
}

std::string HtmlEscape(const std::string &s) {
  std::string out;
  for (unsigned char c : s) {
    if (c == '&') out += "&amp;";
    else if (c == '<') out += "&lt;";
    else if (c == '>') out += "&gt;";
    else if (c == '"') out += "&quot;";
    else out.push_back(static_cast<char>(c));
  }
  return out;
}

std::string Page(const std::string &title, const std::string &body) {
  return "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>" +
         HtmlEscape(title) +
         "</title><link rel=\"stylesheet\" href=\"/styles.css\"></head>\n<body><header><a href=\"/\">oidc-caep-risc-c demo</a></header><main>\n" +
         body +
         "\n</main><footer>A traditional web application signing in with OpenID Connect through oidc-caep-risc-c.</footer></body>\n</html>\n";
}

int EnvPort() {
  const char *raw = std::getenv("PORT");
  if (!raw || !*raw) return 3000;
  std::string text = raw;
  char *end = nullptr;
  long port = std::strtol(text.c_str(), &end, 10);
  if (!end || *end || port < 1 || port > 65535 || std::to_string(port) != text) return 3000;
  return static_cast<int>(port);
}

std::string ReadPath(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

std::string OnPort(const std::string &raw, int port) {
  iya::URL u;
  if (!iya::ParseURL(raw, u)) return raw;
  if (!iya::IsLoopback(u.hostname())) return raw;
  u.port = std::to_string(port);
  if (u.path.empty()) u.path = "/";
  return u.str();
}

std::string MoveOrigin(const std::string &value, const std::string &public_url) {
  std::string base_text = public_url;
  if (base_text.empty() || base_text.back() != '/') base_text.push_back('/');
  iya::URL base;
  iya::URL nxt;
  if (!iya::ParseURL(base_text, base) || !iya::ParseURL(value, nxt)) return value;
  nxt.scheme = base.scheme;
  nxt.host = base.host;
  nxt.port = base.port;
  if (nxt.path.empty()) nxt.path = "/";
  return nxt.str();
}

void ApplyRedirects(iya::J &raw, int port, const std::string &public_url, bool given) {
  std::string redirect = iya::Trim(iya::Sprint(raw.find("redirectUri")));
  bool snake_redirect = false;
  if (redirect.empty()) {
    redirect = iya::Trim(iya::Sprint(raw.find("redirect_uri")));
    snake_redirect = raw.find("redirect_uri") != nullptr;
  }
  std::string post = iya::Trim(iya::Sprint(raw.find("postLogoutRedirectUri")));
  bool snake_post = false;
  if (post.empty()) {
    post = iya::Trim(iya::Sprint(raw.find("post_logout_redirect_uri")));
    snake_post = raw.find("post_logout_redirect_uri") && !raw.find("postLogoutRedirectUri");
  }
  std::string moved_r = redirect;
  std::string moved_p = post;
  if (given && !public_url.empty()) {
    moved_r = MoveOrigin(redirect, public_url);
    moved_p = MoveOrigin(post, public_url);
  } else if (port > 0) {
    moved_r = OnPort(redirect, port);
    moved_p = OnPort(post, port);
  }
  if (raw.find("redirectUri") || !snake_redirect) raw.set("redirectUri", iya::J::str(moved_r));
  else raw.set("redirect_uri", iya::J::str(moved_r));
  if (!post.empty() || raw.find("postLogoutRedirectUri") || raw.find("post_logout_redirect_uri")) {
    if (snake_post) raw.set("post_logout_redirect_uri", iya::J::str(moved_p));
    else raw.set("postLogoutRedirectUri", iya::J::str(moved_p));
  }
}

std::map<std::string, std::string> QueryMap(const std::string &query) {
  std::map<std::string, std::string> out;
  size_t i = 0;
  while (i < query.size()) {
    auto amp = query.find('&', i);
    std::string pair = query.substr(i, amp == std::string::npos ? std::string::npos : amp - i);
    auto eq = pair.find('=');
    std::string key = eq == std::string::npos ? pair : pair.substr(0, eq);
    std::string val = eq == std::string::npos ? std::string() : pair.substr(eq + 1);
    std::string dk;
    std::string dv;
    auto dec = [](const std::string &in) {
      std::string o;
      for (size_t n = 0; n < in.size(); n++) {
        if (in[n] == '+') {
          o.push_back(' ');
          continue;
        }
        if (in[n] == '%' && n + 2 < in.size()) {
          int v = 0;
          if (std::sscanf(in.c_str() + n + 1, "%2x", &v) == 1) {
            o.push_back(static_cast<char>(v));
            n += 2;
            continue;
          }
        }
        o.push_back(in[n]);
      }
      return o;
    };
    dk = dec(key);
    dv = dec(val);
    if (!out.count(dk)) out[dk] = dv;
    if (amp == std::string::npos) break;
    i = amp + 1;
  }
  return out;
}

std::string CookieValue(const Req &req, const std::string &name) {
  std::string header = req.header("Cookie");
  size_t i = 0;
  while (i < header.size()) {
    while (i < header.size() && (header[i] == ' ' || header[i] == ';')) i++;
    auto eq = header.find('=', i);
    auto semi = header.find(';', i);
    if (eq == std::string::npos || (semi != std::string::npos && eq > semi)) break;
    std::string key = header.substr(i, eq - i);
    size_t vend = semi == std::string::npos ? header.size() : semi;
    std::string val = header.substr(eq + 1, vend - eq - 1);
    if (key == name) return val;
    if (semi == std::string::npos) break;
    i = semi + 1;
  }
  return {};
}

struct App {
  std::mutex mu;
  std::map<std::string, Session> sessions;
  std::string secret;
  bool secure_cookies = true;
  std::string config_path;
  std::string public_url;
  bool public_given = false;
  std::unique_ptr<iya::RelyingParty> rp;
  std::string rp_err;
  bool loaded = false;
  std::string receiver_state;
  std::unique_ptr<iya::SignalsReceiver> receiver;
  std::vector<LiveEvent> events;

  std::string Mac(const std::string &value) const {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()), reinterpret_cast<const unsigned char *>(value.data()),
         value.size(), md, &len);
    return iya::B64URLEncode(md, len);
  }

  std::string Seal(const std::map<std::string, std::string> &value) const {
    iya::J doc = iya::J::obj();
    for (const auto &kv : value) doc.set(kv.first, iya::J::str(kv.second));
    std::string body = iya::B64URLEncode(iya::Stringify(doc));
    return body + "." + Mac(body);
  }

  std::map<std::string, std::string> Unseal(const std::string &token) const {
    auto dot = token.find('.');
    if (token.empty() || dot == std::string::npos) return {};
    std::string body = token.substr(0, dot);
    std::string tag = token.substr(dot + 1);
    std::string expect = Mac(body);
    if (expect.size() != tag.size() || CRYPTO_memcmp(expect.data(), tag.data(), expect.size()) != 0) return {};
    try {
      auto raw = iya::B64URLDecode(body, "cookie");
      iya::J doc = iya::Parse(std::string(raw.begin(), raw.end()));
      if (doc.type != iya::JType::Object) return {};
      std::map<std::string, std::string> out;
      for (const auto &kv : doc.o)
        if (kv.second.type == iya::JType::String) out[kv.first] = kv.second.s;
      return out;
    } catch (const std::exception &) {
      return {};
    }
  }

  std::string Cookie(const std::string &name, const std::string &value, const std::string &path, int max_age) const {
    std::string out = name + "=" + value + "; Path=" + path + "; HttpOnly; SameSite=Lax";
    if (secure_cookies) out += "; Secure";
    if (max_age >= 0) out += "; Max-Age=" + std::to_string(max_age);
    return out;
  }

  void Send(int fd, int status, const std::string &body, const std::string &type, const std::vector<std::string> &cookies) {
    std::string reason = status == 200 ? "OK" : status == 302 ? "Found" : status == 303 ? "See Other" : status == 400 ? "Bad Request" : status == 404 ? "Not Found" : "Error";
    std::ostringstream msg;
    msg << "HTTP/1.1 " << status << " " << reason << "\r\n";
    msg << "Content-Type: " << type << "\r\n";
    msg << "Cache-Control: no-store\r\n";
    msg << "Referrer-Policy: no-referrer\r\n";
    msg << "X-Content-Type-Options: nosniff\r\n";
    msg << "X-Frame-Options: DENY\r\n";
    msg << "Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n";
    for (const auto &cookie : cookies) msg << "Set-Cookie: " << cookie << "\r\n";
    if (status == 302 || status == 303) msg << "Content-Length: 0\r\n\r\n";
    else {
      msg << "Content-Length: " << body.size() << "\r\n\r\n";
      msg << body;
    }
    WriteAll(fd, msg.str());
  }

  void Redirect(int fd, int status, const std::string &location, const std::vector<std::string> &cookies) {
    std::ostringstream msg;
    std::string reason = status == 303 ? "See Other" : "Found";
    msg << "HTTP/1.1 " << status << " " << reason << "\r\n";
    msg << "Location: " << location << "\r\n";
    msg << "Cache-Control: no-store\r\n";
    msg << "Referrer-Policy: no-referrer\r\n";
    msg << "Content-Length: 0\r\n";
    for (const auto &cookie : cookies) msg << "Set-Cookie: " << cookie << "\r\n";
    msg << "\r\n";
    WriteAll(fd, msg.str());
  }

  std::string State() {
    std::lock_guard<std::mutex> lock(mu);
    return receiver_state;
  }

  std::string SessionOf(const Req &req, Session *out) {
    std::string sid = CookieValue(req, kSession);
    std::lock_guard<std::mutex> lock(mu);
    auto it = sessions.find(sid);
    if (it == sessions.end()) return {};
    if (it->second.expires <= iya::NowSec()) {
      sessions.erase(it);
      return {};
    }
    if (out) *out = it->second;
    return sid;
  }

  void StartReceiver(iya::RelyingParty *party) {
    if (party->signals_off() || party->ssf_transmitter().empty() || receiver) {
      if (party->signals_off()) receiver_state = "not configured (signals are off)";
      return;
    }
    int interval = party->poll_interval_ms();
    if (interval <= 0) interval = 5000;
    iya::SignalsReceiver::Options opts;
    opts.tls_ca = party->tls_ca();
    opts.poll_interval_ms = interval;
    opts.description = "oidc-caep-risc-c demo (" + party->client_id() + ")";
    opts.headers = [party] {
      try {
        iya::Access access = party->ClientCredentials("ssf.manage");
        return std::map<std::string, std::string>{{"Authorization", "Bearer " + access.access_token}};
      } catch (const std::exception &) {
        return std::map<std::string, std::string>{};
      }
    };
    try {
      receiver = iya::SignalsReceiver::New(
          party->ssf_transmitter(),
          [this](const std::vector<std::string> &ids, const iya::SignalEvent &) {
            std::lock_guard<std::mutex> lock(mu);
            for (const auto &id : ids) sessions.erase(id);
          },
          opts);
      receiver->On("*", [this](const iya::SignalEvent &event) { RememberLiveEvent(event); });
      receiver->Start();
      receiver_state = "polling stream " + receiver->stream_id() + " at " + party->ssf_transmitter();
    } catch (const std::exception &e) {
      receiver.reset();
      receiver_state = std::string("not running: ") + e.what();
      std::fprintf(stderr, "ssf: the receiver did not start: %s\n", e.what());
    }
  }

  // Records an accepted event for /live-status. The receiver ends a session only
  // when the event names one it tracks. A session-revoked that matched none
  // leaves this demo's one login in place, so the demo (not the library) ends
  // that one local session and untracks it.
  void RememberLiveEvent(const iya::SignalEvent &event) {
    std::lock_guard<std::mutex> lock(mu);
    events.push_back(LiveEvent{event.type, event.jti});
    if (event.type != kSessionRevoked || !event.sessions.empty() || sessions.size() != 1) return;
    std::string sid = sessions.begin()->first;
    sessions.clear();
    if (receiver) receiver->Untrack(sid);
  }

  // {signedIn, subject, receiver, events: [{type, jti}]} for scripts/live_iya_sts.py.
  // It never includes a token or an ID Token claim set.
  void LiveStatus(int fd, const Req &req) {
    Session sess;
    std::string sid = SessionOf(req, &sess);
    iya::J doc = iya::J::obj();
    doc.set("signedIn", iya::J::boolean(!sid.empty()));
    std::string who;
    if (!sid.empty()) {
      who = sess.login.preferred_username;
      if (who.empty()) who = sess.login.email;
      if (who.empty()) who = sess.login.subject;
    }
    doc.set("subject", who.empty() ? iya::J() : iya::J::str(who));
    iya::J list = iya::J::arr();
    {
      std::lock_guard<std::mutex> lock(mu);
      doc.set("receiver", iya::J::str(receiver_state));
      for (const auto &one : events) {
        iya::J item = iya::J::obj();
        item.set("type", iya::J::str(one.type));
        item.set("jti", one.jti.empty() ? iya::J() : iya::J::str(one.jti));
        list.a.push_back(item);
      }
    }
    doc.set("events", list);
    Send(fd, 200, iya::Stringify(doc), "application/json", {});
  }

  iya::RelyingParty *Relying() {
    if (loaded) return rp.get();
    loaded = true;
    try {
      std::string body = iya::ReadFile(config_path);
      iya::J doc = iya::Parse(body);
      if (const char *file = std::getenv("OIDC_METADATA_FILE"); file && *file) {
        doc.set("metadataFile", iya::J::str(file));
        doc.erase("metadataUrl");
        doc.erase("issuer");
      }
      int port = EnvPort();
      ApplyRedirects(doc, port, public_url, public_given);
      std::string redirect = iya::Sprint(doc.find("redirectUri"));
      if (redirect.empty()) redirect = iya::Sprint(doc.find("redirect_uri"));
      if (redirect.empty()) redirect = "http://localhost/";
      iya::URL parsed;
      if (iya::ParseURL(redirect, parsed))
        secure_cookies = parsed.scheme == "https" || parsed.hostname() == "localhost" || parsed.hostname() == "127.0.0.1";
      const iya::J *signals = doc.find("signals");
      if (signals && signals->type == iya::JType::Bool && !signals->b)
        receiver_state = "not configured (signals are off)";
      else {
        const iya::J *ssf = doc.find("ssf");
        if (!ssf || ssf->type != iya::JType::Object || iya::Trim(iya::Sprint(ssf->find("transmitter"))).empty())
          receiver_state = "not configured (no ssf block in the configuration file)";
        else
          receiver_state = "starting";
      }
      std::filesystem::path parent = std::filesystem::absolute(config_path).parent_path();
      std::string resolved = iya::ResolveConfigJSON(iya::Stringify(doc), parent.string());
      rp = iya::RelyingParty::Create(resolved);
      StartReceiver(rp.get());
    } catch (const std::exception &e) {
      rp_err = e.what();
    }
    return rp.get();
  }

  void Home(int fd, const Req &req) {
    Session sess;
    std::string sid = SessionOf(req, &sess);
    std::string problem;
    iya::RelyingParty *party = nullptr;
    {
      std::lock_guard<std::mutex> lock(mu);
      party = Relying();
      if (!party) problem = "The relying party is not configured yet: " + rp_err + ". Run scripts/configure_iya_sts.py.";
    }
    if (!sid.empty()) {
      std::string who = sess.login.preferred_username;
      if (who.empty()) who = sess.login.email;
      if (who.empty()) who = sess.login.subject;
      std::string rows;
      for (const auto &row : {std::pair<const char *, std::string>{"Subject", sess.login.subject},
                              {"Issuer", sess.login.issuer},
                              {"Email", sess.login.email},
                              {"Name", sess.login.name},
                              {"Username", sess.login.preferred_username}}) {
        if (row.second.empty()) continue;
        rows += "<tr><th>" + HtmlEscape(row.first) + "</th><td>" + HtmlEscape(row.second) + "</td></tr>";
      }
      std::string body = "<h1>Signed in as " + HtmlEscape(who) + "</h1><table class=\"facts\">" + rows +
                         "</table><p><small>The access token and the refresh token stay in this process. This page does not show them.</small></p><p><small>Shared Signals: " +
                         HtmlEscape(State()) +
                         "</small></p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>";
      Send(fd, 200, Page("Signed in", body), "text/html; charset=utf-8", {});
      return;
    }
    std::string issuer;
    if (party && !party->issuer().empty()) issuer = " of " + HtmlEscape(party->issuer());
    std::string problem_html;
    if (!problem.empty()) problem_html = "<p class=\"problem\">" + HtmlEscape(problem) + "</p>";
    std::string body = "<h1>Sign in with OpenID Connect</h1>" + problem_html +
                       "<p>This application is a confidential client" + issuer +
                       ". It sends the browser to the authorization endpoint (Authorization Code, PKCE S256) and takes the tokens on the back channel.</p><p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with OpenID Connect</a></p>";
    Send(fd, 200, Page("Sign in", body), "text/html; charset=utf-8", {});
  }

  void Login(int fd) {
    iya::RelyingParty *party = nullptr;
    std::string err;
    {
      std::lock_guard<std::mutex> lock(mu);
      party = Relying();
      err = rp_err;
    }
    if (!party) {
      Send(fd, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + HtmlEscape(err) + "</p>"),
           "text/html; charset=utf-8", {});
      return;
    }
    try {
      iya::Transaction txn = party->Authorize();
      std::map<std::string, std::string> saved = {{"state", txn.state},
                                                  {"nonce", txn.nonce},
                                                  {"code_verifier", txn.code_verifier},
                                                  {"redirect_uri", txn.redirect_uri}};
      Redirect(fd, 302, txn.url, {Cookie(kTxn, Seal(saved), "/callback", 600)});
    } catch (const std::exception &e) {
      Send(fd, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + HtmlEscape(e.what()) + "</p>"),
           "text/html; charset=utf-8", {});
    }
  }

  void Callback(int fd, const Req &req) {
    std::string clear = Cookie(kTxn, "", "/callback", 0);
    iya::RelyingParty *party = nullptr;
    std::string err;
    {
      std::lock_guard<std::mutex> lock(mu);
      party = Relying();
      err = rp_err;
    }
    if (!party) {
      Send(fd, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + HtmlEscape(err) + "</p>"),
           "text/html; charset=utf-8", {clear});
      return;
    }
    auto saved = Unseal(CookieValue(req, kTxn));
    if (saved.empty()) {
      Send(fd, 400,
           Page("Sign-in failed",
                "<h1>Sign-in failed</h1><p class=\"problem\">validation: this callback is not a sign-in this browser started</p><p><a href=\"/\">Start again</a></p>"),
           "text/html; charset=utf-8", {clear});
      return;
    }
    iya::Transaction txn;
    txn.state = saved["state"];
    txn.nonce = saved["nonce"];
    txn.code_verifier = saved["code_verifier"];
    txn.redirect_uri = saved["redirect_uri"];
    try {
      iya::Login login = party->Complete(QueryMap(req.query), txn);
      unsigned char buf[32];
      RAND_bytes(buf, sizeof buf);
      std::string sid = iya::B64URLEncode(buf, sizeof buf);
      {
        std::lock_guard<std::mutex> lock(mu);
        Session stored;
        stored.login = login;
        stored.expires = iya::NowSec() + 8 * 3600;
        sessions[sid] = stored;
      }
      if (receiver) receiver->Track(sid, login.subject, login.email, login.sid);
      Redirect(fd, 303, "/", {clear, Cookie(kSession, sid, "/", 8 * 3600)});
    } catch (const iya::OidcError &e) {
      std::string what = e.code + ": " + e.what();
      Send(fd, 400,
           Page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + HtmlEscape(what) +
                                      "</p><p><a href=\"/\">Start again</a></p>"),
           "text/html; charset=utf-8", {clear});
    } catch (const std::exception &e) {
      Send(fd, 400,
           Page("Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + HtmlEscape(e.what()) +
                                      "</p><p><a href=\"/\">Start again</a></p>"),
           "text/html; charset=utf-8", {clear});
    }
  }

  void Logout(int fd, const Req &req) {
    std::string sid = CookieValue(req, kSession);
    if (!sid.empty()) {
      std::lock_guard<std::mutex> lock(mu);
      sessions.erase(sid);
      if (receiver) receiver->Untrack(sid);
    }
    Redirect(fd, 303, "/", {Cookie(kSession, "", "/", 0)});
  }

  void Route(int fd, const Req &req) {
    try {
      if (req.path == "/healthz") {
        Send(fd, 200, "ok", "text/plain", {});
        return;
      }
      if (req.path == "/live-status" && req.method == "GET") {
        LiveStatus(fd, req);
        return;
      }
      if (req.path == "/styles.css" && req.method == "GET") {
        Send(fd, 200, ReadPath("demo/public/styles.css"), "text/css; charset=utf-8", {});
        return;
      }
      if (req.path == "/app.js" && req.method == "GET") {
        Send(fd, 200, ReadPath("demo/public/app.js"), "text/javascript; charset=utf-8", {});
        return;
      }
      if (req.path == "/" && req.method == "GET") {
        Home(fd, req);
        return;
      }
      if (req.path == "/login" && req.method == "GET") {
        Login(fd);
        return;
      }
      if (req.path == "/callback" && req.method == "GET") {
        Callback(fd, req);
        return;
      }
      if (req.path == "/logout" && req.method == "POST") {
        Logout(fd, req);
        return;
      }
      Send(fd, 404, Page("Not found", "<h1>Not found</h1>"), "text/html; charset=utf-8", {});
    } catch (const std::exception &e) {
      std::fprintf(stderr, "demo: %s\n", e.what());
      Send(fd, 500, Page("Error", "<h1>Something went wrong</h1><p class=\"problem\">" + HtmlEscape(e.what()) + "</p><p><a href=\"/\">Home</a></p>"),
           "text/html; charset=utf-8", {});
    }
  }
};

}  // namespace

int main(int argc, char **argv) {
  std::string public_url = std::getenv("PUBLIC_URL") ? std::getenv("PUBLIC_URL") : "";
  bool given = (std::getenv("PUBLIC_URL") && std::getenv("PUBLIC_URL")[0]) ||
               (std::getenv("OIDC_PUBLIC_URL_GIVEN") && std::getenv("OIDC_PUBLIC_URL_GIVEN")[0]);
  std::string config = std::getenv("OIDC_CONFIG") ? std::getenv("OIDC_CONFIG") : "";
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    auto take = [&](const std::string &name, std::string &dest) {
      if (arg == name && i + 1 < argc) {
        dest = argv[++i];
        return true;
      }
      if (arg.rfind(name + "=", 0) == 0) {
        dest = arg.substr(name.size() + 1);
        return true;
      }
      return false;
    };
    if (take("--public-url", public_url)) {
      given = true;
      continue;
    }
    if (take("--config", config)) {
      setenv("OIDC_CONFIG", config.c_str(), 1);
      continue;
    }
    std::fprintf(stderr, "unknown argument %s\n", arg.c_str());
    return 2;
  }
  while (!public_url.empty() && public_url.back() == '/') public_url.pop_back();
  if (config.empty()) config = "demo/oidc.json";
  std::string secret;
  if (const char *env = std::getenv("SESSION_SECRET"); env && *env) secret = env;
  else {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof buf);
    secret.assign(reinterpret_cast<char *>(buf), sizeof buf);
  }
  App app;
  app.secret = secret;
  app.config_path = config;
  app.public_url = public_url;
  app.public_given = given;
  std::string raw = ReadPath(config);
  if (raw.empty()) std::fprintf(stderr, "cannot read configuration: %s\n", config.c_str());
  else {
    try {
      iya::J doc = iya::Parse(raw);
      ApplyRedirects(doc, EnvPort(), app.public_url, app.public_given);
      std::string redirect = iya::Sprint(doc.find("redirectUri"));
      if (redirect.empty()) redirect = iya::Sprint(doc.find("redirect_uri"));
      if (redirect.empty()) redirect = "http://localhost/";
      iya::URL parsed;
      if (iya::ParseURL(redirect, parsed))
        app.secure_cookies = parsed.scheme == "https" || parsed.hostname() == "localhost" || parsed.hostname() == "127.0.0.1";
    } catch (const std::exception &) {
    }
  }
  int port = EnvPort();
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return 1;
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(static_cast<uint16_t>(port));
  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof addr) != 0 || listen(fd, 64) != 0) {
    std::perror("bind");
    return 1;
  }
  std::printf("oidc-caep-risc-c demo on port %d\n", port);
  std::fflush(stdout);
  while (true) {
    int client = accept(fd, nullptr, nullptr);
    if (client < 0) continue;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    std::thread([client, &app] {
      Req req;
      if (ReadReq(client, req)) app.Route(client, req);
      ::close(client);
    }).detach();
  }
}
