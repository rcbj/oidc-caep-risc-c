// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "iya/oidc.hpp"

#include <iostream>
#include <string>

int main() {
  const char *bad =
      "{\"signals\":\"no\",\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\","
      "\"client_id\":\"oidc-caep-risc-demo\",\"clientSecret\":\"secret\","
      "\"redirectUri\":\"http://127.0.0.1/callback\"}";
  try {
    std::string resolved = iya::ResolveConfigJSON(bad, ".");
    std::cerr << resolved << "\n";
    return 1;
  } catch (const iya::OidcError &err) {
    if (err.code != "config" || std::string(err.what()) != "signals must be true or false") {
      std::cerr << err.code << " " << err.what() << "\n";
      return 2;
    }
  } catch (const std::exception &err) {
    std::cerr << err.what() << "\n";
    return 3;
  }
  if (std::string(iya::DefaultScopes()) != "openid profile email offline_access ssf.read ssf.manage") return 4;
  const char *ok =
      "{\"metadataUrl\":\"https://localhost:8081/.well-known/openid-configuration\","
      "\"client_id\":\"oidc-caep-risc-demo\",\"clientSecret\":\"secret\","
      "\"redirectUri\":\"http://127.0.0.1/callback\"}";
  std::string resolved = iya::ResolveConfigJSON(ok, ".");
  if (resolved.find("ssf.read") == std::string::npos || resolved.find("\"signals\"") != std::string::npos) {
    std::cerr << resolved << "\n";
    return 5;
  }
  if (std::string(iya::EventURI("sessionRevoked")) !=
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked")
    return 6;
  return 0;
}
