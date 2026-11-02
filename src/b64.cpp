// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "b64.hpp"

namespace iya {
namespace {

int ValURL(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

int ValStd(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

std::string Encode(const uint8_t *data, size_t n, const char *alpha, bool pad) {
  std::string out;
  out.reserve((n + 2) / 3 * 4);
  size_t i = 0;
  while (i + 3 <= n) {
    uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
    out.push_back(alpha[(v >> 18) & 63]);
    out.push_back(alpha[(v >> 12) & 63]);
    out.push_back(alpha[(v >> 6) & 63]);
    out.push_back(alpha[v & 63]);
    i += 3;
  }
  if (i < n) {
    uint32_t v = uint32_t(data[i]) << 16;
    if (i + 1 < n) v |= uint32_t(data[i + 1]) << 8;
    out.push_back(alpha[(v >> 18) & 63]);
    out.push_back(alpha[(v >> 12) & 63]);
    if (i + 1 < n) {
      out.push_back(alpha[(v >> 6) & 63]);
      if (pad) out.push_back('=');
    } else if (pad) {
      out += "==";
    }
  }
  return out;
}

std::vector<uint8_t> Decode(const std::string &value, int (*val)(char), bool pad, const std::string &what) {
  std::string in = value;
  if (pad) {
    while (!in.empty() && in.back() == '=') in.pop_back();
  }
  for (char c : in) {
    if (val(c) < 0) throw std::runtime_error(what + " is not base64url");
  }
  if (in.size() % 4 == 1) throw std::runtime_error(what + " is not base64url");
  std::vector<uint8_t> out;
  out.reserve(in.size() / 4 * 3);
  size_t i = 0;
  while (i + 4 <= in.size()) {
    int a = val(in[i]), b = val(in[i + 1]), c = val(in[i + 2]), d = val(in[i + 3]);
    uint32_t v = (uint32_t(a) << 18) | (uint32_t(b) << 12) | (uint32_t(c) << 6) | uint32_t(d);
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    i += 4;
  }
  size_t rem = in.size() - i;
  if (rem == 2) {
    int a = val(in[i]), b = val(in[i + 1]);
    uint32_t v = (uint32_t(a) << 18) | (uint32_t(b) << 12);
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  } else if (rem == 3) {
    int a = val(in[i]), b = val(in[i + 1]), c = val(in[i + 2]);
    uint32_t v = (uint32_t(a) << 18) | (uint32_t(b) << 12) | (uint32_t(c) << 6);
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  } else if (rem != 0) {
    throw std::runtime_error(what + " is not base64url");
  }
  return out;
}

}  // namespace

std::string B64URLEncode(const uint8_t *data, size_t n) {
  static const char *alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  return Encode(data, n, alpha, false);
}

std::string B64URLEncode(const std::string &data) {
  return B64URLEncode(reinterpret_cast<const uint8_t *>(data.data()), data.size());
}

std::vector<uint8_t> B64URLDecode(const std::string &value, const std::string &what) {
  return Decode(value, ValURL, false, what);
}

std::string B64StdEncode(const uint8_t *data, size_t n) {
  static const char *alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  return Encode(data, n, alpha, true);
}

std::vector<uint8_t> B64StdDecode(const std::string &value) {
  return Decode(value, ValStd, true, "base64");
}

}  // namespace iya
