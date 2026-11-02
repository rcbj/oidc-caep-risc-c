// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "http.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>

#include <algorithm>
#include <cctype>
#include <memory>
#include <sstream>
#include <string>

#include "iya/oidc.hpp"
#include "util.hpp"

namespace iya {
namespace {

constexpr size_t kMaxBody = 2 * 1024 * 1024;
constexpr int kTimeoutMs = 15000;

struct PipeIgnore {
  PipeIgnore() { std::signal(SIGPIPE, SIG_IGN); }
};

PipeIgnore pipe_ignore;

std::string Lower(std::string s) {
  for (char &c : s) {
    unsigned char u = static_cast<unsigned char>(c);
    if (u >= 'A' && u <= 'Z') c = static_cast<char>(u - 'A' + 'a');
  }
  return s;
}

bool IsIP(const std::string &host) {
  in_addr a4{};
  if (inet_pton(AF_INET, host.c_str(), &a4) == 1) return true;
  in6_addr a6{};
  return inet_pton(AF_INET6, host.c_str(), &a6) == 1;
}

class Conn {
 public:
  int fd = -1;
  SSL_CTX *ctx = nullptr;
  SSL *ssl = nullptr;
  std::string buf;

  ~Conn() { Close(); }

  void Close() {
    if (ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      ssl = nullptr;
    }
    if (ctx) {
      SSL_CTX_free(ctx);
      ctx = nullptr;
    }
    if (fd >= 0) {
      ::close(fd);
      fd = -1;
    }
  }

  void SetTimeout() {
    timeval tv{};
    tv.tv_sec = kTimeoutMs / 1000;
    tv.tv_usec = (kTimeoutMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
  }

  bool ReadSome() {
    char tmp[4096];
    int n = 0;
    if (ssl) {
      n = SSL_read(ssl, tmp, sizeof tmp);
      if (n <= 0) return false;
    } else {
      n = static_cast<int>(::recv(fd, tmp, sizeof tmp, 0));
      if (n <= 0) return false;
    }
    buf.append(tmp, tmp + n);
    return true;
  }

  bool Ensure(size_t n) {
    while (buf.size() < n) {
      if (!ReadSome()) return false;
    }
    return true;
  }

  bool ReadUntil(const std::string &mark, size_t max, std::string &out) {
    while (buf.find(mark) == std::string::npos) {
      if (buf.size() > max) return false;
      if (!ReadSome()) return false;
    }
    auto at = buf.find(mark);
    out.assign(buf, 0, at + mark.size());
    buf.erase(0, at + mark.size());
    return true;
  }

  bool Take(size_t n, std::string &out) {
    if (!Ensure(n)) return false;
    out.append(buf, 0, n);
    buf.erase(0, n);
    return true;
  }

  void WriteAll(const std::string &data) {
    size_t off = 0;
    while (off < data.size()) {
      int n = 0;
      if (ssl) {
        n = SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
        if (n <= 0) throw std::runtime_error("write failed");
      } else {
        n = static_cast<int>(::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL));
        if (n <= 0) throw std::runtime_error("write failed");
      }
      off += static_cast<size_t>(n);
    }
  }
};

int ConnectTo(const std::string &host, const std::string &port, const std::string &code, const std::string &url) {
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo *res = nullptr;
  std::string porttext = port.empty() ? std::string("80") : port;
  if (getaddrinfo(host.c_str(), porttext.c_str(), &hints, &res) != 0 || !res) {
    throw OidcError(code, url + ": name lookup failed");
  }
  int fd = -1;
  for (addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc != 0 && errno != EINPROGRESS) {
      ::close(fd);
      fd = -1;
      continue;
    }
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int pr = poll(&pfd, 1, kTimeoutMs);
    if (pr <= 0) {
      ::close(fd);
      fd = -1;
      continue;
    }
    int so = 0;
    socklen_t sl = sizeof so;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &sl);
    if (so != 0) {
      ::close(fd);
      fd = -1;
      continue;
    }
    fcntl(fd, F_SETFL, flags);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    break;
  }
  freeaddrinfo(res);
  if (fd < 0) throw OidcError(code, url + " did not answer within 15 s");
  return fd;
}

void ApplyCA(SSL_CTX *ctx, const std::string &ca, const std::string &code) {
  SSL_CTX_set_default_verify_paths(ctx);
  if (ca.empty()) return;
  BIO *bio = BIO_new_mem_buf(ca.data(), static_cast<int>(ca.size()));
  if (!bio) throw OidcError(code, "the configured tlsCa is not a PEM trust anchor");
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  int added = 0;
  while (true) {
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) break;
    if (X509_STORE_add_cert(store, cert) == 1) added++;
    X509_free(cert);
  }
  BIO_free(bio);
  ERR_clear_error();
  if (added == 0) throw OidcError(code, "the configured tlsCa is not a PEM trust anchor");
}

std::string ReadChunked(Conn &conn, const std::string &url, const std::string &code) {
  std::string body;
  while (true) {
    std::string line;
    if (!conn.ReadUntil("\n", 64 * 1024, line)) throw OidcError(code, url + " did not answer within 15 s");
    if (!line.empty() && line.back() == '\n') line.pop_back();
    if (!line.empty() && line.back() == '\r') line.pop_back();
    auto semi = line.find(';');
    std::string hex = semi == std::string::npos ? line : line.substr(0, semi);
    size_t size = 0;
    try {
      size = static_cast<size_t>(std::stoul(hex, nullptr, 16));
    } catch (...) {
      throw OidcError(code, url + ": bad chunk");
    }
    if (size == 0) {
      std::string trailer;
      conn.ReadUntil("\r\n", 64 * 1024, trailer);
      break;
    }
    if (body.size() + size > kMaxBody) throw OidcError(code, Fmt("%s answered more than %zu bytes", url.c_str(), kMaxBody));
    if (!conn.Take(size, body)) throw OidcError(code, url + " did not answer within 15 s");
    std::string crlf;
    if (!conn.Take(2, crlf)) throw OidcError(code, url + " did not answer within 15 s");
  }
  return body;
}

}  // namespace

std::string URL::hostport() const {
  std::string h = host;
  if (h.find(':') != std::string::npos) h = "[" + h + "]";
  if (!port.empty()) h += ":" + port;
  return h;
}

std::string URL::origin() const { return scheme + "://" + hostport(); }

std::string URL::str() const {
  std::string out = origin();
  out += path.empty() ? "/" : path;
  if (!query.empty()) {
    out.push_back('?');
    out += query;
  }
  if (!fragment.empty()) {
    out.push_back('#');
    out += fragment;
  }
  return out;
}

bool ParseURL(const std::string &raw, URL &out) {
  auto pos = raw.find("://");
  if (pos == std::string::npos || pos == 0) return false;
  URL u;
  u.scheme = raw.substr(0, pos);
  if (u.scheme != "http" && u.scheme != "https") return false;
  size_t i = pos + 3;
  if (i >= raw.size()) return false;
  auto slash = raw.find_first_of("/?#", i);
  std::string auth = slash == std::string::npos ? raw.substr(i) : raw.substr(i, slash - i);
  if (auth.empty()) return false;
  auto at = auth.rfind('@');
  if (at != std::string::npos) {
    u.userinfo = auth.substr(0, at);
    auth = auth.substr(at + 1);
  }
  if (!auth.empty() && auth[0] == '[') {
    auto br = auth.find(']');
    if (br == std::string::npos) return false;
    u.host = auth.substr(1, br - 1);
    if (br + 1 < auth.size()) {
      if (auth[br + 1] != ':') return false;
      u.port = auth.substr(br + 2);
    }
  } else {
    auto colon = auth.rfind(':');
    if (colon != std::string::npos && auth.find(':') == colon) {
      u.host = auth.substr(0, colon);
      u.port = auth.substr(colon + 1);
    } else {
      u.host = auth;
    }
  }
  if (u.host.empty()) return false;
  std::string rest = slash == std::string::npos ? std::string() : raw.substr(slash);
  auto hash = rest.find('#');
  if (hash != std::string::npos) {
    u.fragment = rest.substr(hash + 1);
    rest = rest.substr(0, hash);
  }
  auto q = rest.find('?');
  if (q != std::string::npos) {
    u.query = rest.substr(q + 1);
    u.path = rest.substr(0, q);
  } else {
    u.path = rest;
  }
  out = std::move(u);
  return true;
}

std::string SchemeOf(const std::string &value) {
  std::string text = value;
  if (text.find("://") == std::string::npos) text = "https://" + text;
  URL u;
  if (!ParseURL(text, u)) return {};
  return u.scheme;
}

bool IsLoopback(const std::string &hostname) {
  return hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname == "[::1]";
}

std::string HttpResult::header(const std::string &name) const {
  std::string want = Lower(name);
  for (const auto &kv : headers)
    if (Lower(kv.first) == want) return kv.second;
  return {};
}

HttpResult Send(const std::string &url, const std::string &method,
                const std::vector<std::pair<std::string, std::string>> &headers, const std::string *body,
                const std::string &ca, const std::string &code) {
  URL u;
  if (!ParseURL(url, u) || u.host.empty()) throw OidcError(code, Fmt("%s is not an http(s) URL", url.c_str()));
  std::string port = u.port;
  if (port.empty()) port = u.scheme == "https" ? "443" : "80";
  Conn conn;
  try {
    conn.fd = ConnectTo(u.host, port, code, url);
  } catch (const OidcError &) {
    throw;
  } catch (const std::exception &e) {
    throw OidcError(code, url + ": " + e.what());
  }
  conn.SetTimeout();
  if (u.scheme == "https") {
    conn.ctx = SSL_CTX_new(TLS_client_method());
    if (!conn.ctx) throw OidcError(code, url + ": tls");
    SSL_CTX_set_min_proto_version(conn.ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(conn.ctx, SSL_VERIFY_PEER, nullptr);
    try {
      ApplyCA(conn.ctx, ca, code);
    } catch (...) {
      throw;
    }
    conn.ssl = SSL_new(conn.ctx);
    SSL_set_fd(conn.ssl, conn.fd);
    if (!IsIP(u.host)) SSL_set_tlsext_host_name(conn.ssl, u.host.c_str());
    SSL_set1_host(conn.ssl, u.host.c_str());
    if (SSL_connect(conn.ssl) != 1) throw OidcError(code, url + ": tls handshake failed");
  }
  std::string path = u.path.empty() ? "/" : u.path;
  if (!u.query.empty()) {
    path.push_back('?');
    path += u.query;
  }
  std::ostringstream req;
  req << method << ' ' << path << " HTTP/1.1\r\n";
  req << "Host: " << u.hostport() << "\r\n";
  req << "Connection: close\r\n";
  bool has_len = false;
  for (const auto &kv : headers) {
    req << kv.first << ": " << kv.second << "\r\n";
    if (Lower(kv.first) == "content-length") has_len = true;
  }
  if (body && !has_len) req << "Content-Length: " << body->size() << "\r\n";
  req << "\r\n";
  if (body) req << *body;
  try {
    conn.WriteAll(req.str());
  } catch (const std::exception &e) {
    if (std::string(e.what()).find("within 15") != std::string::npos) throw;
    throw OidcError(code, url + ": " + e.what());
  }
  std::string head;
  if (!conn.ReadUntil("\r\n\r\n", 64 * 1024, head)) throw OidcError(code, url + " did not answer within 15 s");
  auto line_end = head.find("\r\n");
  if (line_end == std::string::npos) throw OidcError(code, url + ": bad response");
  std::string status_line = head.substr(0, line_end);
  auto sp1 = status_line.find(' ');
  if (sp1 == std::string::npos) throw OidcError(code, url + ": bad response");
  auto sp2 = status_line.find(' ', sp1 + 1);
  std::string code_text = sp2 == std::string::npos ? status_line.substr(sp1 + 1) : status_line.substr(sp1 + 1, sp2 - sp1 - 1);
  HttpResult result;
  try {
    result.status = std::stoi(code_text);
  } catch (...) {
    throw OidcError(code, url + ": bad response");
  }
  size_t at = line_end + 2;
  bool chunked = false;
  bool have_len = false;
  size_t content_len = 0;
  bool close_conn = true;
  while (at + 2 <= head.size()) {
    auto next = head.find("\r\n", at);
    if (next == std::string::npos || next == at) break;
    std::string line = head.substr(at, next - at);
    at = next + 2;
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string name = line.substr(0, colon);
    std::string value = line.substr(colon + 1);
    while (!value.empty() && (value[0] == ' ' || value[0] == '\t')) value.erase(value.begin());
    result.headers.emplace_back(name, value);
    std::string lname = Lower(name);
    if (lname == "content-type") result.content_type = value;
    if (lname == "content-length" && !have_len) {
      try {
        content_len = static_cast<size_t>(std::stoull(value));
        have_len = true;
      } catch (...) {
        throw OidcError(code, url + ": bad content-length");
      }
    }
    if (lname == "transfer-encoding" && Lower(value).find("chunked") != std::string::npos) chunked = true;
    if (lname == "connection" && Lower(value).find("close") == std::string::npos) close_conn = false;
  }
  std::string payload;
  if (chunked) {
    payload = ReadChunked(conn, url, code);
  } else if (have_len) {
    if (content_len > kMaxBody) throw OidcError(code, Fmt("%s answered more than %zu bytes", url.c_str(), kMaxBody));
    if (content_len && !conn.Take(content_len, payload)) throw OidcError(code, url + " did not answer within 15 s");
  } else {
    payload = conn.buf;
    conn.buf.clear();
    char tmp[4096];
    while (payload.size() <= kMaxBody) {
      int n = 0;
      if (conn.ssl) n = SSL_read(conn.ssl, tmp, sizeof tmp);
      else n = static_cast<int>(::recv(conn.fd, tmp, sizeof tmp, 0));
      if (n <= 0) break;
      payload.append(tmp, tmp + n);
    }
    if (payload.size() > kMaxBody) throw OidcError(code, Fmt("%s answered more than %zu bytes", url.c_str(), kMaxBody));
    (void)close_conn;
  }
  result.body = std::move(payload);
  return result;
}

}  // namespace iya
