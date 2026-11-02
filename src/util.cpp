// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "util.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cctype>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#include "b64.hpp"

namespace iya {

std::string Trim(const std::string &s) {
  size_t a = 0;
  while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) a++;
  size_t b = s.size();
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
  return s.substr(a, b - a);
}

std::string TrimRightSlash(const std::string &s) {
  size_t b = s.size();
  while (b > 0 && s[b - 1] == '/') b--;
  return s.substr(0, b);
}

bool StartsWith(const std::string &s, const std::string &prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool Contains(const std::string &s, const std::string &part) { return s.find(part) != std::string::npos; }

std::string ToLower(std::string s) {
  for (char &c : s) {
    unsigned char u = static_cast<unsigned char>(c);
    if (u >= 'A' && u <= 'Z') c = static_cast<char>(u - 'A' + 'a');
  }
  return s;
}

std::vector<std::string> Fields(const std::string &s) {
  std::vector<std::string> out;
  std::string cur;
  for (unsigned char c : s) {
    if (std::isspace(c)) {
      if (!cur.empty()) {
        out.push_back(cur);
        cur.clear();
      }
    } else {
      cur.push_back(static_cast<char>(c));
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

bool ContainsString(const std::vector<std::string> &list, const std::string &want) {
  for (const auto &item : list)
    if (item == want) return true;
  return false;
}

bool SameText(const std::string &left, const std::string &right) {
  if (left.size() != right.size()) return false;
  return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

double NowSec() {
  timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
}

std::string HexEncode(const uint8_t *data, size_t n) {
  static const char *hex = "0123456789abcdef";
  std::string out(n * 2, '\0');
  for (size_t i = 0; i < n; i++) {
    out[i * 2] = hex[data[i] >> 4];
    out[i * 2 + 1] = hex[data[i] & 0xF];
  }
  return out;
}

std::string RandomToken() {
  uint8_t buf[32];
  if (RAND_bytes(buf, sizeof buf) != 1) throw std::runtime_error("random bytes failed");
  return B64URLEncode(buf, sizeof buf);
}

std::string Uuid4() {
  uint8_t b[16];
  if (RAND_bytes(b, sizeof b) != 1) throw std::runtime_error("random bytes failed");
  b[6] = static_cast<uint8_t>((b[6] & 0x0F) | 0x40);
  b[8] = static_cast<uint8_t>((b[8] & 0x3F) | 0x80);
  char out[40];
  std::snprintf(out, sizeof out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
                b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
  return out;
}

std::string QueryEscape(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char c : value) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
        c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      char buf[4];
      std::snprintf(buf, sizeof buf, "%%%02X", c);
      out += buf;
    }
  }
  return out;
}

std::string FormEncode(const std::string &value) {
  static const char *extra = "-_.!~*'()";
  std::string out;
  for (unsigned char c : value) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || std::strchr(extra, c)) {
      out.push_back(static_cast<char>(c));
    } else if (c == ' ') {
      out.push_back('+');
    } else {
      char buf[4];
      std::snprintf(buf, sizeof buf, "%%%02X", c);
      out += buf;
    }
  }
  return out;
}

std::string FormBody(const std::vector<std::pair<std::string, std::string>> &fields,
                     const std::vector<std::string> &order) {
  std::string out;
  std::vector<char> seen(fields.size(), 0);
  auto write = [&](const std::string &k, const std::string &v) {
    if (!out.empty()) out.push_back('&');
    out += QueryEscape(k);
    out.push_back('=');
    out += QueryEscape(v);
  };
  for (const std::string &key : order) {
    for (size_t i = 0; i < fields.size(); i++) {
      if (!seen[i] && fields[i].first == key) {
        write(fields[i].first, fields[i].second);
        seen[i] = 1;
      }
    }
  }
  for (size_t i = 0; i < fields.size(); i++) {
    if (!seen[i]) write(fields[i].first, fields[i].second);
  }
  return out;
}

std::string JoinPath(const std::string &base, const std::string &rel) {
  if (!rel.empty() && rel[0] == '/') return rel;
  if (base.empty() || base == ".") return rel;
  if (!base.empty() && base.back() == '/') return base + rel;
  return base + "/" + rel;
}

std::string ReadFile(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error(std::string("could not read ") + path + ": " + std::strerror(errno));
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

std::string CodeChallengeS256(const std::string &verifier) {
  unsigned char sum[32];
  unsigned int n = 0;
  EVP_Digest(verifier.data(), verifier.size(), sum, &n, EVP_sha256(), nullptr);
  return B64URLEncode(sum, n);
}

}  // namespace iya
