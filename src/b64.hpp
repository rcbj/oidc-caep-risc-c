// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_B64_HPP
#define IYA_B64_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace iya {

std::string B64URLEncode(const uint8_t *data, size_t n);
std::string B64URLEncode(const std::string &data);
std::vector<uint8_t> B64URLDecode(const std::string &value, const std::string &what);
std::string B64StdEncode(const uint8_t *data, size_t n);
std::vector<uint8_t> B64StdDecode(const std::string &value);

}  // namespace iya

#endif
