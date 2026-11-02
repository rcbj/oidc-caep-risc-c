// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#ifndef IYA_CRYPTO_HPP
#define IYA_CRYPTO_HPP

#include <openssl/evp.h>

#include <cstdint>
#include <string>
#include <vector>

#include "json.hpp"

namespace iya {

struct AlgSpec {
  const char *name;
  const char *kty;
  const char *hash;
  const char *mode;
};

const AlgSpec *LookupAlg(const std::string &name);
const std::vector<std::string> &AsymmetricAlgs();
const std::vector<std::string> &SupportedJWSAlgs();

EVP_PKEY *LoadPrivateKey(const std::string &pem, const std::string &alg);
void FreeKey(EVP_PKEY *key);

std::vector<uint8_t> SignJWS(EVP_PKEY *key, const std::string &alg, const uint8_t *input, size_t len);
bool VerifySignature(EVP_PKEY *key, const std::string &alg, const uint8_t *input, size_t len, const uint8_t *sig,
                     size_t sig_len);
bool VerifyHMAC(const std::string &secret, const std::string &alg, const uint8_t *input, size_t len,
                const uint8_t *sig, size_t sig_len);
EVP_PKEY *PublicKeyFromJWK(const J &jwk);

}  // namespace iya

#endif
