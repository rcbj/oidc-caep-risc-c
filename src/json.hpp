// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_JSON_HPP
#define IYA_JSON_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace iya {

struct JsonError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

enum class JType { Null, Bool, Int, Float, String, Array, Object };

struct J {
  JType type = JType::Null;
  bool b = false;
  int64_t i = 0;
  double d = 0;
  std::string s;
  std::vector<J> a;
  std::vector<std::pair<std::string, J>> o;

  static J nul();
  static J boolean(bool v);
  static J integer(int64_t v);
  static J floating(double v);
  static J str(std::string v);
  static J arr();
  static J obj();

  const J *find(const std::string &key) const;
  J *find(const std::string &key);
  bool has(const std::string &key) const;
  void set(const std::string &key, J value);
  void erase(const std::string &key);
};

J Parse(const std::string &text);
std::string Stringify(const J &value);

std::string Sprint(const J *v);
std::string Sprint(const J &v);
bool IsExactTrue(const J *v);
bool IsNullish(const J *v);
bool AsFloat(const J *v, double &out);
bool AsStringList(const J *v, std::vector<std::string> &out);
bool Truthy(const J *v);

}  // namespace iya

#endif
