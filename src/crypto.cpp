// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

#include "crypto.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstring>

#include "b64.hpp"
#include "iya/oidc.hpp"
#include "util.hpp"

namespace iya {
namespace {

const AlgSpec kAlgs[] = {
    {"RS256", "RSA", "sha256", "pkcs1"}, {"RS384", "RSA", "sha384", "pkcs1"}, {"RS512", "RSA", "sha512", "pkcs1"},
    {"PS256", "RSA", "sha256", "pss"},   {"PS384", "RSA", "sha384", "pss"},   {"PS512", "RSA", "sha512", "pss"},
    {"ES256", "EC", "sha256", "p1363"},  {"ES384", "EC", "sha384", "p1363"},  {"ES512", "EC", "sha512", "p1363"},
    {"EdDSA", "OKP", "", "eddsa"},       {"Ed25519", "OKP", "", "eddsa"},
    {"HS256", "oct", "sha256", "hmac"},  {"HS384", "oct", "sha384", "hmac"},  {"HS512", "oct", "sha512", "hmac"},
};

const EVP_MD *MDOf(const char *hash) {
  if (!hash) return EVP_sha256();
  if (std::strcmp(hash, "sha384") == 0) return EVP_sha384();
  if (std::strcmp(hash, "sha512") == 0) return EVP_sha512();
  return EVP_sha256();
}

int CurveSize(const std::string &alg) {
  if (alg == "ES384") return 48;
  if (alg == "ES512") return 66;
  return 32;
}

std::string CurveName(const std::string &alg) {
  if (alg == "ES384") return "P-384";
  if (alg == "ES512") return "P-521";
  return "P-256";
}

std::string OpenSSLCurve(const std::string &alg) {
  if (alg == "ES384") return "secp384r1";
  if (alg == "ES512") return "secp521r1";
  return "prime256v1";
}

std::string OsslText() {
  char buf[256];
  unsigned long e = ERR_get_error();
  if (!e) return "openssl error";
  ERR_error_string_n(e, buf, sizeof buf);
  return buf;
}

EVP_PKEY *FromParams(const char *type, OSSL_PARAM *params) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr);
  if (!ctx) return nullptr;
  EVP_PKEY *pkey = nullptr;
  if (EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
    EVP_PKEY_free(pkey);
    pkey = nullptr;
  }
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

bool VerifyDigest(EVP_PKEY *key, const EVP_MD *md, bool pss, const uint8_t *input, size_t len, const uint8_t *sig,
                  size_t sig_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) return false;
  EVP_PKEY_CTX *pctx = nullptr;
  bool ok = false;
  if (EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, key) == 1) {
    if (pss && pctx) {
      EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
      EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    }
    if (EVP_DigestVerifyUpdate(ctx, input, len) == 1 && EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) ok = true;
  }
  EVP_MD_CTX_free(ctx);
  return ok;
}

bool VerifyES(EVP_PKEY *key, const EVP_MD *md, int size, const uint8_t *input, size_t len, const uint8_t *sig,
              size_t sig_len) {
  if (static_cast<int>(sig_len) != size * 2) return false;
  BIGNUM *r = BN_bin2bn(sig, size, nullptr);
  BIGNUM *s = BN_bin2bn(sig + size, size, nullptr);
  if (!r || !s) {
    BN_free(r);
    BN_free(s);
    return false;
  }
  ECDSA_SIG *es = ECDSA_SIG_new();
  if (!es || ECDSA_SIG_set0(es, r, s) != 1) {
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(es);
    return false;
  }
  int der_len = i2d_ECDSA_SIG(es, nullptr);
  if (der_len <= 0) {
    ECDSA_SIG_free(es);
    return false;
  }
  std::vector<uint8_t> der(static_cast<size_t>(der_len));
  unsigned char *p = der.data();
  i2d_ECDSA_SIG(es, &p);
  ECDSA_SIG_free(es);
  return VerifyDigest(key, md, false, input, len, der.data(), der.size());
}

}  // namespace

const AlgSpec *LookupAlg(const std::string &name) {
  for (const AlgSpec &spec : kAlgs)
    if (name == spec.name) return &spec;
  return nullptr;
}

const std::vector<std::string> &AsymmetricAlgs() {
  static const std::vector<std::string> algs = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                                                 "ES256", "ES384", "ES512", "EdDSA", "Ed25519"};
  return algs;
}

const std::vector<std::string> &SupportedJWSAlgs() { return AsymmetricAlgs(); }

void FreeKey(EVP_PKEY *key) { EVP_PKEY_free(key); }

EVP_PKEY *LoadPrivateKey(const std::string &pem, const std::string &alg) {
  const AlgSpec *spec = LookupAlg(alg);
  if (!spec || std::strcmp(spec->mode, "hmac") == 0) {
    throw OidcError("config", Fmt("the private key could not be read as %s: unsupported algorithm", alg.c_str()));
  }
  if (pem.find("-----BEGIN") == std::string::npos) {
    throw OidcError("config", Fmt("the private key could not be read as %s: not a PEM key", alg.c_str()));
  }
  BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) throw OidcError("config", Fmt("the private key could not be read as %s: not a PEM key", alg.c_str()));
  EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!key) {
    std::string why = OsslText();
    throw OidcError("config", "the private key could not be read as " + alg + ": " + why);
  }
  bool match = false;
  if (std::strcmp(spec->kty, "RSA") == 0) match = EVP_PKEY_is_a(key, "RSA") == 1;
  if (std::strcmp(spec->kty, "EC") == 0) {
    if (EVP_PKEY_is_a(key, "EC") == 1) {
      char curve[64];
      size_t clen = 0;
      if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof curve, &clen) == 1) {
        // OpenSSL names the curves prime256v1, secp384r1 and secp521r1.
        std::string got = curve;
        match = CurveName(alg) == got || OpenSSLCurve(alg) == got;
      }
    }
  }
  if (std::strcmp(spec->kty, "OKP") == 0) match = EVP_PKEY_is_a(key, "ED25519") == 1;
  if (!match) {
    EVP_PKEY_free(key);
    throw OidcError("config", Fmt("the private key could not be read as %s: key type does not match %s", alg.c_str(),
                                  alg.c_str()));
  }
  return key;
}

std::vector<uint8_t> SignJWS(EVP_PKEY *key, const std::string &alg, const uint8_t *input, size_t len) {
  const AlgSpec *spec = LookupAlg(alg);
  if (!spec || !key) throw OidcError("protocol", "the client assertion could not be signed: unsupported algorithm");
  bool ecdsa = std::strcmp(spec->mode, "p1363") == 0;
  if (std::strcmp(spec->mode, "pkcs1") != 0 && std::strcmp(spec->mode, "pss") != 0 && !ecdsa) {
    throw OidcError("protocol", "the client assertion could not be signed: unsupported algorithm");
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) throw OidcError("protocol", "the client assertion could not be signed: openssl");
  EVP_PKEY_CTX *pctx = nullptr;
  std::vector<uint8_t> sig;
  try {
    if (EVP_DigestSignInit(ctx, &pctx, MDOf(spec->hash), nullptr, key) != 1) throw std::runtime_error(OsslText());
    if (std::strcmp(spec->mode, "pss") == 0) {
      EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
      EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    }
    if (EVP_DigestSignUpdate(ctx, input, len) != 1) throw std::runtime_error(OsslText());
    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) throw std::runtime_error(OsslText());
    sig.resize(siglen);
    if (EVP_DigestSignFinal(ctx, sig.data(), &siglen) != 1) throw std::runtime_error(OsslText());
    sig.resize(siglen);
    if (ecdsa) {
      // OpenSSL signs ECDSA as DER; a JWS carries r and s, each padded to the curve size.
      const unsigned char *p = sig.data();
      ECDSA_SIG *es = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(sig.size()));
      if (!es) throw std::runtime_error(OsslText());
      const BIGNUM *r = nullptr;
      const BIGNUM *s = nullptr;
      ECDSA_SIG_get0(es, &r, &s);
      int size = CurveSize(alg);
      std::vector<uint8_t> raw(static_cast<size_t>(size * 2));
      bool ok = BN_bn2binpad(r, raw.data(), size) == size && BN_bn2binpad(s, raw.data() + size, size) == size;
      ECDSA_SIG_free(es);
      if (!ok) throw std::runtime_error("ECDSA signature does not fit the curve");
      sig = std::move(raw);
    }
  } catch (const std::exception &e) {
    EVP_MD_CTX_free(ctx);
    throw OidcError("protocol", std::string("the client assertion could not be signed: ") + e.what());
  }
  EVP_MD_CTX_free(ctx);
  return sig;
}

bool VerifySignature(EVP_PKEY *key, const std::string &alg, const uint8_t *input, size_t len, const uint8_t *sig,
                     size_t sig_len) {
  const AlgSpec *spec = LookupAlg(alg);
  if (!spec || !key) return false;
  if (std::strcmp(spec->mode, "pkcs1") == 0) return VerifyDigest(key, MDOf(spec->hash), false, input, len, sig, sig_len);
  if (std::strcmp(spec->mode, "pss") == 0) return VerifyDigest(key, MDOf(spec->hash), true, input, len, sig, sig_len);
  if (std::strcmp(spec->mode, "p1363") == 0)
    return VerifyES(key, MDOf(spec->hash), CurveSize(alg), input, len, sig, sig_len);
  if (std::strcmp(spec->mode, "eddsa") == 0) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
              EVP_DigestVerify(ctx, sig, sig_len, input, len) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
  }
  return false;
}

bool VerifyHMAC(const std::string &secret, const std::string &alg, const uint8_t *input, size_t len, const uint8_t *sig,
                size_t sig_len) {
  const AlgSpec *spec = LookupAlg(alg);
  if (!spec || std::strcmp(spec->mode, "hmac") != 0) return false;
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int maclen = 0;
  if (!HMAC(MDOf(spec->hash), secret.data(), static_cast<int>(secret.size()), input, len, mac, &maclen)) return false;
  if (maclen != sig_len) return false;
  return CRYPTO_memcmp(mac, sig, maclen) == 0;
}

EVP_PKEY *GenerateP256() {
  EVP_PKEY *key = EVP_EC_gen("P-256");
  if (!key) throw OidcError("config", "the DPoP key could not be generated: " + OsslText());
  return key;
}

J PublicJWKOfP256(EVP_PKEY *key) {
  BIGNUM *x = nullptr;
  BIGNUM *y = nullptr;
  if (!key || EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x) != 1 ||
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y) != 1) {
    BN_free(x);
    BN_free(y);
    throw OidcError("config", "the DPoP key has no P-256 public point");
  }
  uint8_t xb[32];
  uint8_t yb[32];
  bool ok = BN_bn2binpad(x, xb, 32) == 32 && BN_bn2binpad(y, yb, 32) == 32;
  BN_free(x);
  BN_free(y);
  if (!ok) throw OidcError("config", "the DPoP key is not a P-256 key");
  // RFC 7638: the required members in lexicographic order, which is also the thumbprint input.
  J jwk = J::obj();
  jwk.set("crv", J::str("P-256"));
  jwk.set("kty", J::str("EC"));
  jwk.set("x", J::str(B64URLEncode(xb, 32)));
  jwk.set("y", J::str(B64URLEncode(yb, 32)));
  return jwk;
}

std::string JWKThumbprint(const J &jwk) {
  J members = J::obj();
  for (const char *name : {"crv", "kty", "x", "y"}) members.set(name, J::str(Sprint(jwk.find(name))));
  std::string input = Stringify(members);
  unsigned char sum[EVP_MAX_MD_SIZE];
  unsigned int n = 0;
  EVP_Digest(input.data(), input.size(), sum, &n, EVP_sha256(), nullptr);
  return B64URLEncode(sum, n);
}

std::string SHA256B64URL(const std::string &value) {
  unsigned char sum[EVP_MAX_MD_SIZE];
  unsigned int n = 0;
  EVP_Digest(value.data(), value.size(), sum, &n, EVP_sha256(), nullptr);
  return B64URLEncode(sum, n);
}

EVP_PKEY *PublicKeyFromJWK(const J &jwk) {
  const J *kty = jwk.find("kty");
  std::string kind = Sprint(kty);
  try {
    if (kind == "RSA") {
      const J *n = jwk.find("n");
      const J *e = jwk.find("e");
      if (!n || n->type != JType::String || !e || e->type != JType::String) throw OidcError("signature", "missing modulus");
      auto nb = B64URLDecode(n->s, "n");
      auto eb = B64URLDecode(e->s, "e");
      BIGNUM *bn = BN_bin2bn(nb.data(), static_cast<int>(nb.size()), nullptr);
      BIGNUM *be = BN_bin2bn(eb.data(), static_cast<int>(eb.size()), nullptr);
      if (!bn || !be || BN_is_zero(be) || BN_is_negative(be)) {
        BN_free(bn);
        BN_free(be);
        throw OidcError("signature", "bad exponent");
      }
      OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn);
      OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be);
      OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY *pkey = FromParams("RSA", params);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      BN_free(bn);
      BN_free(be);
      if (!pkey) throw OidcError("signature", "missing modulus");
      return pkey;
    }
    if (kind == "EC") {
      std::string crv = Sprint(jwk.find("crv"));
      int size = 0;
      if (crv == "P-256") size = 32;
      else if (crv == "P-384") size = 48;
      else if (crv == "P-521") size = 66;
      else throw OidcError("signature", "unknown curve");
      auto xb = B64URLDecode(Sprint(jwk.find("x")), "x");
      auto yb = B64URLDecode(Sprint(jwk.find("y")), "y");
      if (static_cast<int>(xb.size()) != size || static_cast<int>(yb.size()) != size)
        throw OidcError("signature", "EC coordinate length");
      std::vector<uint8_t> point;
      point.reserve(static_cast<size_t>(1 + size * 2));
      point.push_back(0x04);
      point.insert(point.end(), xb.begin(), xb.end());
      point.insert(point.end(), yb.begin(), yb.end());
      OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, crv.c_str(), crv.size());
      OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size());
      OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY *pkey = FromParams("EC", params);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      if (!pkey) throw OidcError("signature", "unknown curve");
      return pkey;
    }
    if (kind == "OKP") {
      const J *crv = jwk.find("crv");
      if (crv && crv->type != JType::Null && Sprint(crv) != "Ed25519") throw OidcError("signature", Sprint(crv));
      auto xb = B64URLDecode(Sprint(jwk.find("x")), "x");
      if (xb.size() != 32) throw OidcError("signature", "Ed25519 length");
      OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
      OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, xb.data(), xb.size());
      OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
      EVP_PKEY *pkey = FromParams("ED25519", params);
      OSSL_PARAM_free(params);
      OSSL_PARAM_BLD_free(bld);
      if (!pkey) throw OidcError("signature", "Ed25519 length");
      return pkey;
    }
  } catch (const OidcError &) {
    throw;
  } catch (const std::exception &e) {
    std::string kid = Sprint(jwk.find("kid"));
    throw OidcError("signature", "the transmitter's key " + kid + " cannot be read: " + e.what());
  }
  throw OidcError("signature", "the key type " + kind + " cannot be read");
}

}  // namespace iya
