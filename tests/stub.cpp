// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "stub.h"

#include "iya/oidc.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "b64.hpp"
#include "http.hpp"
#include "json.hpp"
#include "util.hpp"

namespace {

const char *kClient = "oidc-caep-risc-demo";
const char *kSecret = "test-secret";
const char *kScopes = "openid profile email offline_access ssf.read ssf.manage";

std::string DupString(const std::string &s) { return s; }

char *DupC(const std::string &s) {
  char *out = new char[s.size() + 1];
  std::memcpy(out, s.data(), s.size());
  out[s.size()] = '\0';
  return out;
}

std::string Lower(std::string s) {
  for (char &c : s) {
    unsigned char u = static_cast<unsigned char>(c);
    if (u >= 'A' && u <= 'Z') c = static_cast<char>(u - 'A' + 'a');
  }
  return s;
}

std::string PctDecode(const std::string &in) {
  std::string out;
  for (size_t i = 0; i < in.size(); i++) {
    if (in[i] == '+') {
      out.push_back(' ');
      continue;
    }
    if (in[i] == '%' && i + 2 < in.size() && std::isxdigit(static_cast<unsigned char>(in[i + 1])) &&
        std::isxdigit(static_cast<unsigned char>(in[i + 2]))) {
      int v = 0;
      std::sscanf(in.c_str() + i + 1, "%2x", &v);
      out.push_back(static_cast<char>(v));
      i += 2;
      continue;
    }
    out.push_back(in[i]);
  }
  return out;
}

std::map<std::string, std::string> Form(const std::string &body) {
  std::map<std::string, std::string> out;
  size_t i = 0;
  while (i < body.size()) {
    auto amp = body.find('&', i);
    std::string pair = body.substr(i, amp == std::string::npos ? std::string::npos : amp - i);
    auto eq = pair.find('=');
    std::string key = PctDecode(eq == std::string::npos ? pair : pair.substr(0, eq));
    std::string val = PctDecode(eq == std::string::npos ? std::string() : pair.substr(eq + 1));
    if (!out.count(key)) out[key] = val;
    if (amp == std::string::npos) break;
    i = amp + 1;
  }
  return out;
}

bool WriteAll(int fd, const std::string &data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n < 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

struct Req {
  std::string method;
  std::string path;
  std::string query;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
  std::string header(const std::string &name) const {
    std::string want = Lower(name);
    for (const auto &kv : headers)
      if (Lower(kv.first) == want) return kv.second;
    return {};
  }
};

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
  auto sp2 = sp1 == std::string::npos ? std::string::npos : start.find(' ', sp1 + 1);
  if (sp1 == std::string::npos) return false;
  req.method = start.substr(0, sp1);
  std::string target = sp2 == std::string::npos ? start.substr(sp1 + 1) : start.substr(sp1 + 1, sp2 - sp1 - 1);
  auto q = target.find('?');
  if (q == std::string::npos) {
    req.path = target;
  } else {
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
  req.body = rest.substr(0, content_len);
  return true;
}

void Respond(int fd, int status, const std::string &body, const std::string &type, const std::string &extra) {
  std::string reason = "OK";
  if (status == 201) reason = "Created";
  else if (status == 204) reason = "No Content";
  else if (status == 302) reason = "Found";
  else if (status == 400) reason = "Bad Request";
  else if (status == 401) reason = "Unauthorized";
  else if (status == 404) reason = "Not Found";
  std::string msg = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
  if (!type.empty()) msg += "Content-Type: " + type + "\r\n";
  msg += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  msg += "Connection: close\r\n";
  if (!extra.empty()) msg += extra;
  msg += "\r\n";
  msg += body;
  WriteAll(fd, msg);
}

void RespondJSON(int fd, int status, const iya::J &doc) { Respond(fd, status, iya::Stringify(doc), "application/json", ""); }

struct HttpServer {
  int fd = -1;
  std::thread thread;
  bool stop = false;
  std::string url;
  std::function<void(int, const Req &)> on;

  bool Listen() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof addr) != 0) return false;
    if (listen(fd, 16) != 0) return false;
    socklen_t len = sizeof addr;
    getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    url = "http://127.0.0.1:" + std::to_string(ntohs(addr.sin_port));
    return true;
  }

  void Start() {
    thread = std::thread([this] {
      while (!stop) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) continue;
        int client = accept(fd, nullptr, nullptr);
        if (client < 0) continue;
        int one = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        Req req;
        if (ReadReq(client, req) && on) on(client, req);
        ::close(client);
      }
    });
  }

  void Close() {
    stop = true;
    if (fd >= 0) {
      ::shutdown(fd, SHUT_RDWR);
      ::close(fd);
      fd = -1;
    }
    if (thread.joinable()) thread.join();
  }
};

EVP_PKEY *GenerateRSA() {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
  if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) return nullptr;
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY *key = nullptr;
  if (EVP_PKEY_generate(ctx, &key) <= 0) key = nullptr;
  EVP_PKEY_CTX_free(ctx);
  return key;
}

std::string BnB64(const BIGNUM *bn) {
  int len = BN_num_bytes(bn);
  std::vector<unsigned char> buf(static_cast<size_t>(len));
  BN_bn2bin(bn, buf.data());
  return iya::B64URLEncode(buf.data(), buf.size());
}

iya::J PublicJWK(EVP_PKEY *key, const char *kid) {
  BIGNUM *n = nullptr;
  BIGNUM *e = nullptr;
  EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
  EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);
  iya::J j = iya::J::obj();
  j.set("kty", iya::J::str("RSA"));
  j.set("n", iya::J::str(BnB64(n)));
  j.set("e", iya::J::str(BnB64(e)));
  j.set("kid", iya::J::str(kid));
  j.set("alg", iya::J::str("RS256"));
  j.set("use", iya::J::str("sig"));
  BN_free(n);
  BN_free(e);
  return j;
}

std::string PemOf(EVP_PKEY *key) {
  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PKCS8PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
  char *data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string out(data, data + static_cast<size_t>(len));
  BIO_free(bio);
  return out;
}

std::string SignRS256(EVP_PKEY *key, const iya::J &header, const iya::J &payload, bool corrupt) {
  std::string h = iya::B64URLEncode(iya::Stringify(header));
  std::string p = iya::B64URLEncode(iya::Stringify(payload));
  std::string input = h + "." + p;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key);
  EVP_DigestSignUpdate(ctx, input.data(), input.size());
  size_t siglen = 0;
  EVP_DigestSignFinal(ctx, nullptr, &siglen);
  std::vector<unsigned char> sig(siglen);
  EVP_DigestSignFinal(ctx, sig.data(), &siglen);
  sig.resize(siglen);
  EVP_MD_CTX_free(ctx);
  std::string encoded = iya::B64URLEncode(sig.data(), sig.size());
  if (corrupt && !encoded.empty()) encoded[0] = encoded[0] == 'A' ? 'B' : 'A';
  return input + "." + encoded;
}

bool VerifyAssertion(const std::string &assertion, EVP_PKEY *key, const std::string &audience) {
  std::vector<std::string> parts;
  size_t start = 0;
  while (start <= assertion.size()) {
    auto at = assertion.find('.', start);
    if (at == std::string::npos) {
      parts.push_back(assertion.substr(start));
      break;
    }
    parts.push_back(assertion.substr(start, at - start));
    start = at + 1;
  }
  if (parts.size() != 3) return false;
  std::vector<uint8_t> hb;
  std::vector<uint8_t> pb;
  std::vector<uint8_t> sig;
  try {
    hb = iya::B64URLDecode(parts[0], "header");
    pb = iya::B64URLDecode(parts[1], "payload");
    sig = iya::B64URLDecode(parts[2], "signature");
  } catch (const std::exception &) {
    return false;
  }
  iya::J header;
  iya::J payload;
  try {
    header = iya::Parse(std::string(hb.begin(), hb.end()));
    payload = iya::Parse(std::string(pb.begin(), pb.end()));
  } catch (const std::exception &) {
    return false;
  }
  if (iya::Sprint(header.find("alg")) != "RS256") return false;
  std::string input = parts[0] + "." + parts[1];
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
            EVP_DigestVerifyUpdate(ctx, input.data(), input.size()) == 1 &&
            EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) == 1;
  EVP_MD_CTX_free(ctx);
  if (!ok) return false;
  if (iya::Sprint(payload.find("iss")) != kClient || iya::Sprint(payload.find("sub")) != kClient) return false;
  const iya::J *aud = payload.find("aud");
  if (aud && aud->type == iya::JType::String) return aud->s == audience;
  if (aud && aud->type == iya::JType::Array) {
    for (const iya::J &item : aud->a)
      if (iya::Sprint(item) == audience) return true;
  }
  return false;
}

std::string RandomB64(size_t n) {
  std::vector<unsigned char> buf(n);
  RAND_bytes(buf.data(), static_cast<int>(n));
  return iya::B64URLEncode(buf.data(), buf.size());
}

struct Keys {
  EVP_PKEY *main_key = nullptr;
  EVP_PKEY *other_key = nullptr;
  iya::J jwk;
  Keys() {
    main_key = GenerateRSA();
    other_key = GenerateRSA();
    jwk = PublicJWK(main_key, "k1");
  }
};

Keys &SSFKeys() {
  static Keys keys;
  return keys;
}

struct Row {
  std::string sub;
  std::string email;
  std::string sid;
  std::string nonce;
  std::string redirect;
  std::string challenge;
};

struct Provider {
  HttpServer server;
  std::mutex mu;
  EVP_PKEY *sign_key = nullptr;
  EVP_PKEY *client_key = nullptr;
  std::string client_pem;
  iya::J jwk;
  bool par = false;
  bool corrupt = false;
  std::string aud = kClient;
  bool has_exp = false;
  long long exp = 0;
  bool bad_at_hash = false;
  std::map<std::string, Row> codes;
  std::map<std::string, Row> refresh;
  std::map<std::string, std::string> access;
  std::map<std::string, std::map<std::string, std::string>> pushed;

  iya::J Metadata() {
    iya::J doc = iya::J::obj();
    doc.set("issuer", iya::J::str(server.url));
    doc.set("authorization_endpoint", iya::J::str(server.url + "/authorize"));
    doc.set("token_endpoint", iya::J::str(server.url + "/token"));
    doc.set("jwks_uri", iya::J::str(server.url + "/jwks"));
    doc.set("userinfo_endpoint", iya::J::str(server.url + "/userinfo"));
    doc.set("end_session_endpoint", iya::J::str(server.url + "/end-session"));
    iya::J code = iya::J::arr();
    code.a.push_back(iya::J::str("code"));
    doc.set("response_types_supported", code);
    iya::J subjects = iya::J::arr();
    subjects.a.push_back(iya::J::str("public"));
    doc.set("subject_types_supported", subjects);
    iya::J algs = iya::J::arr();
    algs.a.push_back(iya::J::str("RS256"));
    doc.set("id_token_signing_alg_values_supported", algs);
    iya::J methods = iya::J::arr();
    methods.a.push_back(iya::J::str("client_secret_basic"));
    methods.a.push_back(iya::J::str("client_secret_post"));
    methods.a.push_back(iya::J::str("private_key_jwt"));
    doc.set("token_endpoint_auth_methods_supported", methods);
    iya::J challenges = iya::J::arr();
    challenges.a.push_back(iya::J::str("S256"));
    doc.set("code_challenge_methods_supported", challenges);
    doc.set("authorization_response_iss_parameter_supported", iya::J::boolean(true));
    iya::J scopes = iya::J::arr();
    for (const auto &part : iya::Fields(kScopes)) scopes.a.push_back(iya::J::str(part));
    doc.set("scopes_supported", scopes);
    bool use_par = false;
    {
      std::lock_guard<std::mutex> lock(mu);
      use_par = par;
    }
    if (use_par) doc.set("pushed_authorization_request_endpoint", iya::J::str(server.url + "/par"));
    return doc;
  }

  bool Authorized(const Req &req) {
    std::string header = req.header("Authorization");
    if (header.size() > 6 && Lower(header.substr(0, 6)) == "basic ") {
      std::string raw = header.substr(6);
      try {
        auto decoded = iya::B64StdDecode(raw);
        return std::string(decoded.begin(), decoded.end()) == std::string(kClient) + ":" + kSecret;
      } catch (const std::exception &) {
        return false;
      }
    }
    auto form = Form(req.body);
    if (!form["client_secret"].empty()) return form["client_id"] == kClient && form["client_secret"] == kSecret;
    if (form["client_assertion"].empty()) return false;
    return VerifyAssertion(form["client_assertion"], client_key, server.url);
  }

  iya::J TokenFor(const Row &row) {
    std::string access_token = RandomB64(16);
    std::string refresh_token = RandomB64(16);
    long long now = static_cast<long long>(std::time(nullptr));
    long long exp_at = now + 300;
    long long iat = now;
    bool bad = false;
    bool flip = false;
    std::string audience = kClient;
    {
      std::lock_guard<std::mutex> lock(mu);
      audience = aud;
      if (has_exp) {
        exp_at = exp;
        iat = exp;
      }
      bad = bad_at_hash;
      flip = corrupt;
      aud = kClient;
      corrupt = false;
      bad_at_hash = false;
      has_exp = false;
    }
    std::string at_hash = bad ? "aaaa" : iya::HashClaim(access_token, "RS256");
    iya::J payload = iya::J::obj();
    payload.set("iss", iya::J::str(server.url));
    payload.set("sub", iya::J::str(row.sub));
    payload.set("aud", iya::J::str(audience));
    payload.set("exp", iya::J::integer(exp_at));
    payload.set("iat", iya::J::integer(iat));
    payload.set("nonce", iya::J::str(row.nonce));
    payload.set("email", iya::J::str(row.email));
    payload.set("name", iya::J::str("Demo User"));
    payload.set("preferred_username", iya::J::str(row.sub));
    payload.set("sid", iya::J::str(row.sid));
    payload.set("at_hash", iya::J::str(at_hash));
    iya::J header = iya::J::obj();
    header.set("alg", iya::J::str("RS256"));
    header.set("kid", iya::J::str("op"));
    header.set("typ", iya::J::str("JWT"));
    std::string token = SignRS256(sign_key, header, payload, flip);
    {
      std::lock_guard<std::mutex> lock(mu);
      refresh[refresh_token] = row;
      access[access_token] = iya::Stringify(payload);
    }
    iya::J out = iya::J::obj();
    out.set("access_token", iya::J::str(access_token));
    out.set("token_type", iya::J::str("Bearer"));
    out.set("expires_in", iya::J::integer(300));
    out.set("refresh_token", iya::J::str(refresh_token));
    out.set("id_token", iya::J::str(token));
    out.set("scope", iya::J::str(kScopes));
    return out;
  }

  void Serve(int fd, const Req &req) {
    if (req.path == "/.well-known/openid-configuration") {
      RespondJSON(fd, 200, Metadata());
      return;
    }
    if (req.path == "/jwks") {
      iya::J doc = iya::J::obj();
      iya::J keys = iya::J::arr();
      keys.a.push_back(jwk);
      doc.set("keys", keys);
      RespondJSON(fd, 200, doc);
      return;
    }
    if (req.path == "/userinfo") {
      std::string header = req.header("Authorization");
      std::string token = header;
      if (Lower(token).rfind("bearer ", 0) == 0) token = token.substr(7);
      while (!token.empty() && token[0] == ' ') token.erase(token.begin());
      std::string claims;
      {
        std::lock_guard<std::mutex> lock(mu);
        auto it = access.find(token);
        if (it != access.end()) claims = it->second;
      }
      if (claims.empty()) {
        iya::J err = iya::J::obj();
        err.set("error", iya::J::str("invalid_token"));
        RespondJSON(fd, 401, err);
        return;
      }
      Respond(fd, 200, claims, "application/json", "");
      return;
    }
    if (req.path == "/par" && req.method == "POST") {
      if (!Authorized(req)) {
        iya::J err = iya::J::obj();
        err.set("error", iya::J::str("invalid_client"));
        RespondJSON(fd, 401, err);
        return;
      }
      auto values = Form(req.body);
      std::string request_uri = "urn:par:" + RandomB64(8);
      {
        std::lock_guard<std::mutex> lock(mu);
        pushed[request_uri] = values;
      }
      iya::J doc = iya::J::obj();
      doc.set("request_uri", iya::J::str(request_uri));
      doc.set("expires_in", iya::J::integer(60));
      RespondJSON(fd, 201, doc);
      return;
    }
    if (req.path == "/authorize") {
      auto values = Form(req.query);
      std::string stored = values["request_uri"];
      if (!stored.empty()) {
        std::lock_guard<std::mutex> lock(mu);
        auto it = pushed.find(stored);
        if (it == pushed.end()) {
          iya::J err = iya::J::obj();
          err.set("error", iya::J::str("invalid_request"));
          RespondJSON(fd, 400, err);
          return;
        }
        values = it->second;
      }
      if (values["code_challenge_method"] != "S256" || values["code_challenge"].empty()) {
        iya::J err = iya::J::obj();
        err.set("error", iya::J::str("invalid_request"));
        RespondJSON(fd, 400, err);
        return;
      }
      Row row;
      row.sub = "user-1";
      row.email = "user-1@example.com";
      row.sid = "sid-1";
      row.nonce = values["nonce"];
      row.redirect = values["redirect_uri"];
      row.challenge = values["code_challenge"];
      std::string code = RandomB64(16);
      {
        std::lock_guard<std::mutex> lock(mu);
        codes[code] = row;
      }
      std::string query = "code=" + iya::QueryEscape(code) + "&state=" + iya::QueryEscape(values["state"]) +
                          "&iss=" + iya::QueryEscape(server.url);
      std::string dest = row.redirect;
      dest += (dest.find('?') == std::string::npos ? "?" : "&");
      dest += query;
      Respond(fd, 302, "", "", "Location: " + dest + "\r\n");
      return;
    }
    if (req.path == "/token" && req.method == "POST") {
      if (!Authorized(req)) {
        iya::J err = iya::J::obj();
        err.set("error", iya::J::str("invalid_client"));
        err.set("error_description", iya::J::str("client authentication failed"));
        RespondJSON(fd, 401, err);
        return;
      }
      auto params = Form(req.body);
      if (params["grant_type"] == "client_credentials") {
        iya::J doc = iya::J::obj();
        doc.set("access_token", iya::J::str("cc-token"));
        doc.set("token_type", iya::J::str("Bearer"));
        doc.set("expires_in", iya::J::integer(120));
        doc.set("scope", iya::J::str(params["scope"]));
        RespondJSON(fd, 200, doc);
        return;
      }
      if (params["grant_type"] == "refresh_token") {
        Row row;
        bool found = false;
        {
          std::lock_guard<std::mutex> lock(mu);
          auto it = refresh.find(params["refresh_token"]);
          if (it != refresh.end()) {
            row = it->second;
            found = true;
          }
        }
        if (!found) {
          iya::J err = iya::J::obj();
          err.set("error", iya::J::str("invalid_grant"));
          RespondJSON(fd, 400, err);
          return;
        }
        iya::J minted = TokenFor(row);
        std::string access_token = iya::Sprint(minted.find("access_token"));
        std::string claims;
        {
          std::lock_guard<std::mutex> lock(mu);
          claims = access[access_token];
        }
        iya::J body = iya::Parse(claims);
        body.erase("nonce");
        iya::J header = iya::J::obj();
        header.set("alg", iya::J::str("RS256"));
        header.set("kid", iya::J::str("op"));
        header.set("typ", iya::J::str("JWT"));
        minted.set("id_token", iya::J::str(SignRS256(sign_key, header, body, false)));
        RespondJSON(fd, 200, minted);
        return;
      }
      std::string code = params["code"];
      Row row;
      bool found = false;
      {
        std::lock_guard<std::mutex> lock(mu);
        auto it = codes.find(code);
        if (it != codes.end()) {
          row = it->second;
          found = true;
        }
      }
      if (!found || params["redirect_uri"] != row.redirect ||
          iya::CodeChallengeS256(params["code_verifier"]) != row.challenge) {
        iya::J err = iya::J::obj();
        err.set("error", iya::J::str("invalid_grant"));
        if (found && iya::CodeChallengeS256(params["code_verifier"]) != row.challenge)
          err.set("error_description", iya::J::str("pkce"));
        RespondJSON(fd, 400, err);
        return;
      }
      {
        std::lock_guard<std::mutex> lock(mu);
        codes.erase(code);
      }
      RespondJSON(fd, 200, TokenFor(row));
      return;
    }
    iya::J err = iya::J::obj();
    err.set("error", iya::J::str("not_found"));
    RespondJSON(fd, 404, err);
  }
};

struct Transmitter {
  HttpServer server;
  std::mutex mu;
  std::vector<std::string> order;
  std::map<std::string, std::string> queue;
  std::vector<std::string> acked;
  std::map<std::string, std::string> errs;
  int created = 0;
  std::string authorization;
  std::string verify_state;
  int verify_status = 0;
  std::string hold;

  std::string PollBody() {
    iya::J sets = iya::J::obj();
    for (const auto &jti : order) {
      auto it = queue.find(jti);
      if (it == queue.end()) continue;
      sets.set(jti, iya::J::str(it->second));
    }
    iya::J root = iya::J::obj();
    root.set("sets", sets);
    root.set("moreAvailable", iya::J::boolean(false));
    return iya::Stringify(root);
  }

  void Serve(int fd, const Req &req) {
    std::string auth = req.header("Authorization");
    {
      std::lock_guard<std::mutex> lock(mu);
      authorization = auth;
    }
    if (auth != "Bearer app-token" && req.path != "/.well-known/ssf-configuration" && req.path.rfind("/jwks", 0) != 0) {
      iya::J err = iya::J::obj();
      err.set("error", iya::J::str("invalid_token"));
      RespondJSON(fd, 401, err);
      return;
    }
    if (req.path == "/.well-known/ssf-configuration") {
      iya::J doc = iya::J::obj();
      doc.set("issuer", iya::J::str(server.url));
      doc.set("jwks_uri", iya::J::str(server.url + "/jwks"));
      doc.set("configuration_endpoint", iya::J::str(server.url + "/ssf/stream"));
      doc.set("verification_endpoint", iya::J::str(server.url + "/ssf/verify"));
      iya::J methods = iya::J::arr();
      methods.a.push_back(iya::J::str("urn:ietf:rfc:8936"));
      doc.set("delivery_methods_supported", methods);
      RespondJSON(fd, 200, doc);
      return;
    }
    if (req.path == "/jwks") {
      iya::J doc = iya::J::obj();
      iya::J keys = iya::J::arr();
      keys.a.push_back(SSFKeys().jwk);
      doc.set("keys", keys);
      RespondJSON(fd, 200, doc);
      return;
    }
    if (req.path == "/ssf/stream" && req.method == "GET") {
      Respond(fd, 200, "[]", "application/json", "");
      return;
    }
    if (req.path == "/ssf/stream" && req.method == "POST") {
      iya::J doc = iya::Parse(req.body.empty() ? "{}" : req.body);
      int n = 0;
      std::string method;
      {
        std::lock_guard<std::mutex> lock(mu);
        created++;
        n = created;
      }
      const iya::J *delivery = doc.find("delivery");
      if (delivery) method = iya::Sprint(delivery->find("method"));
      iya::J stream = iya::J::obj();
      stream.set("stream_id", iya::J::str("s" + std::to_string(n)));
      stream.set("iss", iya::J::str(server.url));
      stream.set("aud", iya::J::str("my-app"));
      iya::J del = iya::J::obj();
      del.set("method", iya::J::str(method));
      del.set("endpoint_url", iya::J::str(server.url + "/ssf/poll/s" + std::to_string(n)));
      stream.set("delivery", del);
      if (const iya::J *events = doc.find("events_requested")) {
        stream.set("events_requested", *events);
        stream.set("events_delivered", *events);
      }
      RespondJSON(fd, 201, stream);
      return;
    }
    if (req.path == "/ssf/verify") {
      iya::J doc = iya::Parse(req.body.empty() ? "{}" : req.body);
      std::string state = iya::Sprint(doc.find("state"));
      {
        std::lock_guard<std::mutex> lock(mu);
        verify_state = state;
        verify_status = 204;
      }
      Respond(fd, 204, "", "", "");
      return;
    }
    if (req.path.rfind("/ssf/poll/", 0) == 0) {
      iya::J doc = iya::Parse(req.body.empty() ? "{}" : req.body);
      {
        std::lock_guard<std::mutex> lock(mu);
        if (const iya::J *ack = doc.find("ack"); ack && ack->type == iya::JType::Array) {
          for (const iya::J &item : ack->a) {
            acked.push_back(iya::Sprint(item));
            queue.erase(iya::Sprint(item));
          }
        }
        if (const iya::J *set_errs = doc.find("setErrs"); set_errs && set_errs->type == iya::JType::Object) {
          for (const auto &kv : set_errs->o) {
            errs[kv.first] = iya::Sprint(kv.second.find("err"));
            queue.erase(kv.first);
          }
        }
      }
      std::string raw;
      {
        std::lock_guard<std::mutex> lock(mu);
        raw = PollBody();
      }
      Respond(fd, 200, raw, "application/json", "");
      return;
    }
    iya::J err = iya::J::obj();
    err.set("error", iya::J::str("not_found"));
    RespondJSON(fd, 404, err);
  }
};

iya::J BaseConfig(const std::string &url) {
  iya::J doc = iya::J::obj();
  doc.set("metadataUrl", iya::J::str(url + "/.well-known/openid-configuration"));
  doc.set("clientId", iya::J::str(kClient));
  doc.set("clientSecret", iya::J::str(kSecret));
  doc.set("tokenEndpointAuthMethod", iya::J::str("client_secret_basic"));
  doc.set("redirectUri", iya::J::str("http://127.0.0.1/callback"));
  doc.set("postLogoutRedirectUri", iya::J::str("http://127.0.0.1/"));
  doc.set("scopes", iya::J::str(kScopes));
  doc.set("privateKeyAlg", iya::J::str("RS256"));
  doc.set("par", iya::J::str("auto"));
  doc.set("clockToleranceSec", iya::J::integer(30));
  doc.set("maxIdTokenAgeSec", iya::J::integer(600));
  doc.set("allowInsecure", iya::J::boolean(true));
  return doc;
}

const iya::J *Walk(const iya::J &root, const std::string &path) {
  const iya::J *cur = &root;
  size_t i = 0;
  while (i <= path.size()) {
    auto dot = path.find('.', i);
    std::string key = path.substr(i, dot == std::string::npos ? std::string::npos : dot - i);
    if (!cur || cur->type != iya::JType::Object) return nullptr;
    cur = cur->find(key);
    if (!cur) return nullptr;
    if (dot == std::string::npos) break;
    i = dot + 1;
  }
  return cur;
}

}  // namespace

extern "C" {

iya_test_provider *iya_test_provider_start(void) {
  auto *provider = new Provider();
  provider->sign_key = GenerateRSA();
  provider->client_key = GenerateRSA();
  provider->client_pem = PemOf(provider->client_key);
  provider->jwk = PublicJWK(provider->sign_key, "op");
  if (!provider->server.Listen()) {
    delete provider;
    return nullptr;
  }
  provider->server.on = [provider](int fd, const Req &req) { provider->Serve(fd, req); };
  provider->server.Start();
  return reinterpret_cast<iya_test_provider *>(provider);
}

void iya_test_provider_free(iya_test_provider *provider) {
  if (!provider) return;
  auto *p = reinterpret_cast<Provider *>(provider);
  p->server.Close();
  EVP_PKEY_free(p->sign_key);
  EVP_PKEY_free(p->client_key);
  delete p;
}

const char *iya_test_provider_url(iya_test_provider *provider) {
  return reinterpret_cast<Provider *>(provider)->server.url.c_str();
}

char *iya_test_provider_config(iya_test_provider *provider, const char *overrides_json) {
  auto *p = reinterpret_cast<Provider *>(provider);
  iya::J doc = BaseConfig(p->server.url);
  if (overrides_json && overrides_json[0]) {
    iya::J over = iya::Parse(overrides_json);
    for (const auto &kv : over.o) {
      if (kv.second.type == iya::JType::Null) doc.erase(kv.first);
      else doc.set(kv.first, kv.second);
    }
  }
  return DupC(iya::Stringify(doc));
}

char *iya_test_provider_config_jwt(iya_test_provider *provider) {
  auto *p = reinterpret_cast<Provider *>(provider);
  iya::J doc = BaseConfig(p->server.url);
  doc.set("tokenEndpointAuthMethod", iya::J::str("private_key_jwt"));
  doc.erase("clientSecret");
  doc.set("privateKeyPem", iya::J::str(p->client_pem));
  return DupC(iya::Stringify(doc));
}

void iya_test_provider_set_par(iya_test_provider *provider, int on) {
  auto *p = reinterpret_cast<Provider *>(provider);
  std::lock_guard<std::mutex> lock(p->mu);
  p->par = on != 0;
}

void iya_test_provider_set_corrupt(iya_test_provider *provider, int on) {
  auto *p = reinterpret_cast<Provider *>(provider);
  std::lock_guard<std::mutex> lock(p->mu);
  p->corrupt = on != 0;
}

void iya_test_provider_set_aud(iya_test_provider *provider, const char *aud) {
  auto *p = reinterpret_cast<Provider *>(provider);
  std::lock_guard<std::mutex> lock(p->mu);
  p->aud = aud ? aud : "";
}

void iya_test_provider_set_exp(iya_test_provider *provider, long long exp) {
  auto *p = reinterpret_cast<Provider *>(provider);
  std::lock_guard<std::mutex> lock(p->mu);
  p->has_exp = true;
  p->exp = exp;
}

void iya_test_provider_set_bad_at_hash(iya_test_provider *provider, int on) {
  auto *p = reinterpret_cast<Provider *>(provider);
  std::lock_guard<std::mutex> lock(p->mu);
  p->bad_at_hash = on != 0;
}

int iya_test_manual(const char *url, int *status, char *location, size_t location_len) {
  try {
    iya::HttpResult res = iya::Send(url ? url : "", "GET", {}, nullptr, "", "protocol");
    if (status) *status = res.status;
    std::string loc = res.header("Location");
    if (location && location_len) std::snprintf(location, location_len, "%s", loc.c_str());
    return 0;
  } catch (const std::exception &) {
    return -1;
  }
}

iya_test_tx *iya_test_tx_start(void) {
  SSFKeys();
  auto *tx = new Transmitter();
  if (!tx->server.Listen()) {
    delete tx;
    return nullptr;
  }
  tx->server.on = [tx](int fd, const Req &req) { tx->Serve(fd, req); };
  tx->server.Start();
  return reinterpret_cast<iya_test_tx *>(tx);
}

void iya_test_tx_free(iya_test_tx *tx) {
  if (!tx) return;
  auto *t = reinterpret_cast<Transmitter *>(tx);
  t->server.Close();
  delete t;
}

const char *iya_test_tx_url(iya_test_tx *tx) { return reinterpret_cast<Transmitter *>(tx)->server.url.c_str(); }

int iya_test_tx_created(iya_test_tx *tx) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  std::lock_guard<std::mutex> lock(t->mu);
  return t->created;
}

const char *iya_test_tx_authorization(iya_test_tx *tx) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  std::lock_guard<std::mutex> lock(t->mu);
  t->hold = t->authorization;
  return t->hold.c_str();
}

char *iya_test_tx_deliver(iya_test_tx *tx, const char *event_type, const char *sub_json, const char *extra_json,
                          int other_key) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  unsigned char buf[16];
  RAND_bytes(buf, sizeof buf);
  char jti[48];
  std::snprintf(jti, sizeof jti, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", buf[0], buf[1],
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13],
                buf[14], buf[15]);
  iya::J event = iya::J::obj();
  event.set("event_timestamp", iya::J::integer(1));
  if (extra_json && extra_json[0]) {
    iya::J extra = iya::Parse(extra_json);
    if (extra.type == iya::JType::Object) {
      for (const auto &kv : extra.o) event.set(kv.first, kv.second);
    }
  }
  iya::J events = iya::J::obj();
  events.set(event_type ? event_type : "", event);
  iya::J payload = iya::J::obj();
  payload.set("iss", iya::J::str(t->server.url));
  payload.set("aud", iya::J::str("my-app"));
  payload.set("jti", iya::J::str(jti));
  payload.set("iat", iya::J::integer(static_cast<long long>(std::time(nullptr))));
  payload.set("sub_id", iya::Parse(sub_json ? sub_json : "{}"));
  payload.set("events", events);
  iya::J header = iya::J::obj();
  header.set("alg", iya::J::str("RS256"));
  header.set("kid", iya::J::str("k1"));
  header.set("typ", iya::J::str("secevent+jwt"));
  EVP_PKEY *key = other_key ? SSFKeys().other_key : SSFKeys().main_key;
  std::string token = SignRS256(key, header, payload, false);
  {
    std::lock_guard<std::mutex> lock(t->mu);
    t->queue[jti] = token;
    t->order.emplace_back(jti);
  }
  return DupC(jti);
}

int iya_test_tx_ack_count(iya_test_tx *tx) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  std::lock_guard<std::mutex> lock(t->mu);
  return static_cast<int>(t->acked.size());
}

const char *iya_test_tx_ack_at(iya_test_tx *tx, int index) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  std::lock_guard<std::mutex> lock(t->mu);
  if (index < 0 || index >= static_cast<int>(t->acked.size())) return "";
  t->hold = t->acked[static_cast<size_t>(index)];
  return t->hold.c_str();
}

const char *iya_test_tx_err(iya_test_tx *tx, const char *jti) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  std::lock_guard<std::mutex> lock(t->mu);
  auto it = t->errs.find(jti ? jti : "");
  t->hold = it == t->errs.end() ? "" : it->second;
  return t->hold.c_str();
}

const char *iya_test_tx_verify_state(iya_test_tx *tx) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  std::lock_guard<std::mutex> lock(t->mu);
  t->hold = t->verify_state;
  return t->hold.c_str();
}

int iya_test_tx_verify_status(iya_test_tx *tx) {
  auto *t = reinterpret_cast<Transmitter *>(tx);
  std::lock_guard<std::mutex> lock(t->mu);
  return t->verify_status;
}

char *iya_test_sign_set(const char *payload_json, const char *header_json, int which_key) {
  iya::J payload = iya::Parse(payload_json ? payload_json : "{}");
  iya::J header;
  if (header_json && header_json[0]) {
    header = iya::Parse(header_json);
  } else {
    header = iya::J::obj();
    header.set("alg", iya::J::str("RS256"));
    header.set("kid", iya::J::str("k1"));
    header.set("typ", iya::J::str("secevent+jwt"));
  }
  EVP_PKEY *key = which_key ? SSFKeys().other_key : SSFKeys().main_key;
  return DupC(SignRS256(key, header, payload, false));
}

char *iya_test_ssf_jwks(void) {
  iya::J doc = iya::J::obj();
  iya::J keys = iya::J::arr();
  keys.a.push_back(SSFKeys().jwk);
  doc.set("keys", keys);
  return DupC(iya::Stringify(doc));
}

int iya_test_lookup(const char *json, const char *path, char *out, size_t out_len, int *kind) {
  if (kind) *kind = 0;
  if (out && out_len) out[0] = '\0';
  if (!json || !path) return 0;
  iya::J doc;
  try {
    doc = iya::Parse(json);
  } catch (const std::exception &) {
    return -1;
  }
  const iya::J *cur = Walk(doc, path);
  if (!cur) return 0;
  if (cur->type == iya::JType::Null) {
    if (kind) *kind = 1;
    return 0;
  }
  if (cur->type == iya::JType::Bool) {
    if (kind) *kind = cur->b ? 3 : 2;
    return 0;
  }
  std::string text;
  int k = 5;
  if (cur->type == iya::JType::Int) {
    text = std::to_string(cur->i);
    k = 4;
  } else if (cur->type == iya::JType::Float) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.16g", cur->d);
    text = buf;
    k = 4;
  } else if (cur->type == iya::JType::String) {
    text = cur->s;
    k = 5;
  } else {
    text = iya::Stringify(*cur);
    k = 5;
  }
  if (kind) *kind = k;
  if (out && out_len) std::snprintf(out, out_len, "%s", text.c_str());
  return 0;
}

}  // extern "C"
