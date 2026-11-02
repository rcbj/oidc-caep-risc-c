// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_HTTP_HPP
#define IYA_HTTP_HPP

#include <string>
#include <utility>
#include <vector>

namespace iya {

struct URL {
  std::string scheme;
  std::string host;
  std::string port;
  std::string path;
  std::string query;
  std::string fragment;
  std::string userinfo;
  std::string hostname() const { return host; }
  std::string hostport() const;
  std::string origin() const;
  std::string str() const;
};

bool ParseURL(const std::string &raw, URL &out);
std::string SchemeOf(const std::string &value);
bool IsLoopback(const std::string &hostname);

struct HttpResult {
  int status = 0;
  std::string content_type;
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string header(const std::string &name) const;
};

HttpResult Send(const std::string &url, const std::string &method,
                const std::vector<std::pair<std::string, std::string>> &headers, const std::string *body,
                const std::string &ca, const std::string &code);

}  // namespace iya

#endif
