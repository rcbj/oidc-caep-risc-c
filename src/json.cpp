// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "json.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <sstream>
#include <string>

namespace iya {
namespace {

bool IsSpace(unsigned char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

void AppendUTF8(std::string &out, uint32_t cp) {
  if (cp <= 0x7F) {
    out.push_back(static_cast<char>(cp));
  } else if (cp <= 0x7FF) {
    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp <= 0xFFFF) {
    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

class Parser {
 public:
  explicit Parser(const std::string &in) : in_(in) {}

  J ParseValue() {
    Skip();
    if (i_ >= in_.size()) throw JsonError("invalid JSON");
    char c = in_[i_];
    if (c == '{') return ParseObject();
    if (c == '[') return ParseArray();
    if (c == '"') return J::str(ParseString());
    if (c == 't') return Expect("true"), J::boolean(true);
    if (c == 'f') return Expect("false"), J::boolean(false);
    if (c == 'n') return Expect("null"), J::nul();
    if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber();
    throw JsonError("invalid JSON");
  }

  void Finish() {
    Skip();
  }

 private:
  const std::string &in_;
  size_t i_ = 0;
  int depth_ = 0;

  void Skip() {
    while (i_ < in_.size() && IsSpace(static_cast<unsigned char>(in_[i_]))) i_++;
  }

  void Expect(const char *lit) {
    for (size_t k = 0; lit[k]; k++) {
      if (i_ >= in_.size() || in_[i_] != lit[k]) throw JsonError("invalid JSON");
      i_++;
    }
  }

  std::string ParseString() {
    if (i_ >= in_.size() || in_[i_] != '"') throw JsonError("invalid JSON");
    i_++;
    std::string out;
    while (i_ < in_.size()) {
      unsigned char c = static_cast<unsigned char>(in_[i_++]);
      if (c == '"') return out;
      if (c == '\\') {
        if (i_ >= in_.size()) throw JsonError("invalid JSON");
        char e = in_[i_++];
        switch (e) {
          case '"':
          case '\\':
          case '/':
            out.push_back(e);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            uint32_t cp = ReadHex4();
            if (cp >= 0xD800 && cp <= 0xDBFF) {
              if (i_ + 1 < in_.size() && in_[i_] == '\\' && in_[i_ + 1] == 'u') {
                i_ += 2;
                uint32_t lo = ReadHex4();
                if (lo < 0xDC00 || lo > 0xDFFF) throw JsonError("invalid JSON");
                cp = 0x10000 + (((cp - 0xD800) << 10) | (lo - 0xDC00));
              } else {
                throw JsonError("invalid JSON");
              }
            }
            AppendUTF8(out, cp);
            break;
          }
          default:
            throw JsonError("invalid JSON");
        }
      } else if (c < 0x20) {
        throw JsonError("invalid JSON");
      } else {
        out.push_back(static_cast<char>(c));
      }
    }
    throw JsonError("invalid JSON");
  }

  uint32_t ReadHex4() {
    if (i_ + 4 > in_.size()) throw JsonError("invalid JSON");
    uint32_t cp = 0;
    for (int k = 0; k < 4; k++) {
      char c = in_[i_++];
      cp <<= 4;
      if (c >= '0' && c <= '9') cp |= static_cast<uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') cp |= static_cast<uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') cp |= static_cast<uint32_t>(c - 'A' + 10);
      else throw JsonError("invalid JSON");
    }
    return cp;
  }

  J ParseNumber() {
    size_t start = i_;
    if (in_[i_] == '-') i_++;
    if (i_ >= in_.size() || in_[i_] < '0' || in_[i_] > '9') throw JsonError("invalid JSON");
    if (in_[i_] == '0') {
      i_++;
    } else {
      while (i_ < in_.size() && in_[i_] >= '0' && in_[i_] <= '9') i_++;
    }
    bool real = false;
    if (i_ < in_.size() && in_[i_] == '.') {
      real = true;
      i_++;
      if (i_ >= in_.size() || in_[i_] < '0' || in_[i_] > '9') throw JsonError("invalid JSON");
      while (i_ < in_.size() && in_[i_] >= '0' && in_[i_] <= '9') i_++;
    }
    if (i_ < in_.size() && (in_[i_] == 'e' || in_[i_] == 'E')) {
      real = true;
      i_++;
      if (i_ < in_.size() && (in_[i_] == '+' || in_[i_] == '-')) i_++;
      if (i_ >= in_.size() || in_[i_] < '0' || in_[i_] > '9') throw JsonError("invalid JSON");
      while (i_ < in_.size() && in_[i_] >= '0' && in_[i_] <= '9') i_++;
    }
    std::string text = in_.substr(start, i_ - start);
    if (!real) {
      try {
        size_t used = 0;
        long long v = std::stoll(text, &used, 10);
        if (used == text.size()) return J::integer(static_cast<int64_t>(v));
      } catch (...) {
      }
    }
    try {
      size_t used = 0;
      double v = std::stod(text, &used);
      if (used != text.size() || !std::isfinite(v)) throw JsonError("invalid JSON");
      return J::floating(v);
    } catch (const JsonError &) {
      throw;
    } catch (...) {
      throw JsonError("invalid JSON");
    }
  }

  J ParseArray() {
    if (++depth_ > 64) throw JsonError("invalid JSON");
    Expect("[");
    J out = J::arr();
    Skip();
    if (i_ < in_.size() && in_[i_] == ']') {
      i_++;
      depth_--;
      return out;
    }
    while (true) {
      out.a.push_back(ParseValue());
      Skip();
      if (i_ >= in_.size()) throw JsonError("invalid JSON");
      if (in_[i_] == ',') {
        i_++;
        continue;
      }
      if (in_[i_] == ']') {
        i_++;
        depth_--;
        return out;
      }
      throw JsonError("invalid JSON");
    }
  }

  J ParseObject() {
    if (++depth_ > 64) throw JsonError("invalid JSON");
    Expect("{");
    J out = J::obj();
    Skip();
    if (i_ < in_.size() && in_[i_] == '}') {
      i_++;
      depth_--;
      return out;
    }
    while (true) {
      Skip();
      std::string key = ParseString();
      Skip();
      if (i_ >= in_.size() || in_[i_] != ':') throw JsonError("invalid JSON");
      i_++;
      out.set(key, ParseValue());
      Skip();
      if (i_ >= in_.size()) throw JsonError("invalid JSON");
      if (in_[i_] == ',') {
        i_++;
        continue;
      }
      if (in_[i_] == '}') {
        i_++;
        depth_--;
        return out;
      }
      throw JsonError("invalid JSON");
    }
  }
};

void DumpString(const std::string &s, std::string &out) {
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
    }
  }
  out.push_back('"');
}

void Dump(const J &v, std::string &out) {
  switch (v.type) {
    case JType::Null:
      out += "null";
      break;
    case JType::Bool:
      out += v.b ? "true" : "false";
      break;
    case JType::Int:
      out += std::to_string(v.i);
      break;
    case JType::Float: {
      char buf[64];
      std::snprintf(buf, sizeof buf, "%.16g", v.d);
      out += buf;
      break;
    }
    case JType::String:
      DumpString(v.s, out);
      break;
    case JType::Array: {
      out.push_back('[');
      for (size_t i = 0; i < v.a.size(); i++) {
        if (i) out.push_back(',');
        Dump(v.a[i], out);
      }
      out.push_back(']');
      break;
    }
    case JType::Object: {
      out.push_back('{');
      for (size_t i = 0; i < v.o.size(); i++) {
        if (i) out.push_back(',');
        DumpString(v.o[i].first, out);
        out.push_back(':');
        Dump(v.o[i].second, out);
      }
      out.push_back('}');
      break;
    }
  }
}

}  // namespace

J J::nul() { return J(); }
J J::boolean(bool v) {
  J j;
  j.type = JType::Bool;
  j.b = v;
  return j;
}
J J::integer(int64_t v) {
  J j;
  j.type = JType::Int;
  j.i = v;
  return j;
}
J J::floating(double v) {
  J j;
  j.type = JType::Float;
  j.d = v;
  return j;
}
J J::str(std::string v) {
  J j;
  j.type = JType::String;
  j.s = std::move(v);
  return j;
}
J J::arr() {
  J j;
  j.type = JType::Array;
  return j;
}
J J::obj() {
  J j;
  j.type = JType::Object;
  return j;
}

const J *J::find(const std::string &key) const {
  if (type != JType::Object) return nullptr;
  for (const auto &kv : o)
    if (kv.first == key) return &kv.second;
  return nullptr;
}

J *J::find(const std::string &key) {
  return const_cast<J *>(static_cast<const J *>(this)->find(key));
}

bool J::has(const std::string &key) const { return find(key) != nullptr; }

void J::set(const std::string &key, J value) {
  type = JType::Object;
  if (J *cur = find(key)) {
    *cur = std::move(value);
    return;
  }
  o.emplace_back(key, std::move(value));
}

void J::erase(const std::string &key) {
  if (type != JType::Object) return;
  for (auto it = o.begin(); it != o.end(); ++it) {
    if (it->first == key) {
      o.erase(it);
      return;
    }
  }
}

J Parse(const std::string &text) {
  Parser p(text);
  J v = p.ParseValue();
  p.Finish();
  return v;
}

std::string Stringify(const J &value) {
  std::string out;
  Dump(value, out);
  return out;
}

std::string Sprint(const J &v) {
  switch (v.type) {
    case JType::Null:
      return "";
    case JType::Bool:
      return v.b ? "true" : "false";
    case JType::Int:
      return std::to_string(v.i);
    case JType::Float: {
      char buf[64];
      std::snprintf(buf, sizeof buf, "%.16g", v.d);
      return buf;
    }
    case JType::String:
      return v.s;
    default:
      return Stringify(v);
  }
}

std::string Sprint(const J *v) { return v ? Sprint(*v) : std::string(); }

bool IsExactTrue(const J *v) { return v && v->type == JType::Bool && v->b; }

bool IsNullish(const J *v) { return v == nullptr || v->type == JType::Null; }

bool AsFloat(const J *v, double &out) {
  if (!v) return false;
  if (v->type == JType::Int) {
    out = static_cast<double>(v->i);
    return true;
  }
  if (v->type == JType::Float) {
    out = v->d;
    return true;
  }
  return false;
}

bool AsStringList(const J *v, std::vector<std::string> &out) {
  if (!v || v->type != JType::Array) return false;
  out.clear();
  out.reserve(v->a.size());
  for (const J &item : v->a) out.push_back(Sprint(item));
  return true;
}

bool Truthy(const J *v) {
  if (!v || v->type == JType::Null) return false;
  if (v->type == JType::Bool) return v->b;
  if (v->type == JType::String) return !v->s.empty();
  if (v->type == JType::Int) return v->i != 0;
  if (v->type == JType::Float) return v->d != 0;
  return true;
}

}  // namespace iya
