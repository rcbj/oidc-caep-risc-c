// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_UTIL_HPP
#define IYA_UTIL_HPP

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace iya {

inline std::string Fmt(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char stack[2048];
  int n = vsnprintf(stack, sizeof stack, fmt, ap);
  va_end(ap);
  if (n < 0) return {};
  if (static_cast<size_t>(n) < sizeof stack) return std::string(stack);
  std::string out(static_cast<size_t>(n) + 1, '\0');
  va_start(ap, fmt);
  vsnprintf(out.data(), out.size(), fmt, ap);
  va_end(ap);
  out.resize(static_cast<size_t>(n));
  return out;
}

std::string Trim(const std::string &s);
std::string TrimRightSlash(const std::string &s);
bool StartsWith(const std::string &s, const std::string &prefix);
bool Contains(const std::string &s, const std::string &part);
std::string ToLower(std::string s);
std::vector<std::string> Fields(const std::string &s);
bool ContainsString(const std::vector<std::string> &list, const std::string &want);
bool SameText(const std::string &left, const std::string &right);
double NowSec();
std::string HexEncode(const uint8_t *data, size_t n);
std::string RandomToken();
std::string Uuid4();
std::string QueryEscape(const std::string &value);
std::string FormEncode(const std::string &value);
std::string FormBody(const std::vector<std::pair<std::string, std::string>> &fields,
                     const std::vector<std::string> &order);
std::string JoinPath(const std::string &base, const std::string &rel);
std::string ReadFile(const std::string &path);
std::string CodeChallengeS256(const std::string &verifier);

}  // namespace iya

#endif
