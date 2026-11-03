# oidc-caep-risc-c

A confidential OpenID Connect relying party for a traditional C or C++ application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

The protocol is implemented once, in C++17, in `src/`. `include/iya/oidc.hpp` is the C++ API. `include/iya_oidc.h` is the C ABI: `extern "C"` functions in this library call those classes. C and C++ callers link one binary, `iya_oidc`. Do not implement the protocol a second time behind the C header. Do not wrap another language port.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. The default scope string still names those two scopes. They are removed after that default is applied. A value that is neither true nor false is refused. The shipped demo omits `signals`, so they stay on. `pollIntervalMs` is a millisecond pause, not a port.

The license is the MIT License in `LICENSE`. The library is a CMake package: `find_package(iya_oidc)` gives `iya::oidc`; static by default, shared with `BUILD_SHARED_LIBS`; `IYA_OIDC_BUILD_TESTS` and `IYA_OIDC_BUILD_PROGRAMS` default on only at the top level. `tests/package/check.sh` (run by the Docker test stage) installs both variants and builds the smoke test against each. A pull request merged into `main` releases the library after the test workflow succeeds on that commit: `release.yml` tags `v<VERSION>` and makes a GitHub Release, whose source archive is what a package recipe (such as a ConanCenter one) builds from. A direct push does not release. A tag that already exists stays; the next release is a new version in `VERSION`, which the CMake project, the package and the tag all read. `develop` and `main` are the branches the test workflow runs. The root `conanfile.py` is the clone-and-`conan create` recipe ConanCenter's maintainers recommended when they declined the package (conan-io/conan-center-index#31317–#31320, 2026-11-03): it builds from the checkout's own files (`exports_sources`), takes its version from `VERSION` and refuses a different `--version`, and runs `conan/all/test_package`. `conan/` stays for a later ConanCenter submission.

Cryptography is OpenSSL from the Debian packages (`libssl` and `libcrypto`). HTTP/1.1 and JSON are in this repository. No curl, no JSON library, no OAuth library, and no Boost.

## Client profile (#15)

`RelyingParty::Create` (and `iya_oidc_create`) resolves the configuration like `FromFile`, so the defaults (`par` and `dpop` auto, `clockToleranceSec` 30, `maxIdTokenAgeSec` 600, `idTokenSigningAlgs` `["RS256"]`, `requireIdTokenTypAndAtHash` true), the redirect rule (https, or http on a loopback host; `allowInsecure` does not widen it, also for a per-request redirect URI) and the metadata checks (an inline `metadata` object too) apply to both. Resolving is idempotent (`privateKeyPem`, `dpopKeyPem` and `metadata` in a resolved configuration are read back).

DPoP is in `src/rp.cpp` (`Impl::Proof`, `PostForm`, `Resource`): an ES256 key generated per relying party or `dpopKey`, a proof on PAR, token (every grant) and resource requests (`ath`), `dpop_jkt` on the authorization request, one retry per `use_dpop_nonce`, nonces kept per origin, `token_type` DPoP exactly when a proof was sent. `auto` turns on only when ES256 is advertised. The SSF receiver gets per-request headers and a retry decision through `SignalsReceiver::Options::request_headers` and `on_response`; `SignalsOptionsFor(rp)` and `iya_oidc_receiver_new_for_rp` fill them. ID token algorithms: the list narrowed to the provider's, failing only when empty; a pin must be advertised. `acr` is checked on the code exchange only. The session token cache is `SessionStore` (default `MemorySessionStore`; C: `iya_oidc_session_store`, entries as JSON); `SessionAccessToken` refreshes at 30 seconds left, and a failed refresh removes the entry. The stub provider (`tests/stub.cpp`) checks DPoP proofs itself (its RFC 7638 thumbprint is written out, not the library's) and records what it saw in notes (`iya_test_provider_note`).

## Layout

| Path | What it is |
|---|---|
| `include/iya/oidc.hpp` | C++ classes. `FromFile`, `Authorize`, `Complete`. |
| `include/iya_oidc.h` | The same operations as `extern "C"`. |
| `src` | The only implementation. |
| `tests` | `ctest`. A stub provider and a stub transmitter. `tests/trust.c`: the `tlsCa` chain, a forged leaf, the host name, and `trust_chain.py`. No live iya-sts. |
| `demo` | `demo/main.cpp` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client and writes the listener CA chain named by `tlsCa`. `trust_chain.py` fetches and saves that chain. `live_iya_sts.py` is the live sign-in. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Usage

```cpp
auto rp = iya::RelyingParty::FromFile("oidc.json");
iya::Transaction request = rp->Authorize();
iya::Login who = rp->Complete(query, request);
```

Keep the transaction (`state`, nonce, code verifier) until the browser returns. Tokens stay in this process. C++ throws `iya::OidcError` and does not log. The C functions log that failure once and return `IYA_OIDC_ERR_*` plus `iya_oidc_error`.

## Tests

```bash
docker build --target test .
```

The `test` stage is a sibling of the demo build. It runs `ctest` in Debian bookworm. GitHub Actions uses that command. Do not run the compiler or the library on the host. `docker build .` builds the demo and does not run the suite.

## Live test and nightly

`python3 scripts/live_iya_sts.py` (host stdlib python3 and Docker; never CMake or a compiler on the host) starts a fresh iya-sts `main` in memory mode as container `iya-sts-live-oidc-caep-risc-c` on `LIVE_STS_PORT` (default 18528), copies the checkout to a scratch build context, builds the demo image, runs `scripts/configure_iya_sts.py` on the host against that copy (which writes the trust chain), rebuilds the image (which bakes the chain in), checks the image's chain equals the saved one, runs `oidc-caep-risc-c-live-demo` with `--network host` on `LIVE_DEMO_PORT` (default 18628) mounting only `client-secret` and with `TLS_CA_REFRESH=0`, signs in through `/authn-api`, emits `credential-change` then `session-revoked`, and checks `GET /live-status`. `IYA_STS_URL` and `IYA_STS_IMAGE` select an existing iya-sts or image. It never binds 3000, 8081 or 18481-18495. Always against a fresh iya-sts. Secrets reach `docker run` as `-e NAME` and are never printed. `.github/workflows/nightly.yml` runs the unit image and the live script at 07:50 UTC (`50 7 * * *`).

`/live-status` is `{signedIn, subject, receiver, events: [{type, jti}]}`, never tokens. The demo completes a sign-in under its session cookie's id, reads the access token from the session cache on `GET /` and calls UserInfo with it (DPoP when bound), removes the cache entry at sign-out and when a CAEP event ends the session, and builds its receiver with `SignalsOptionsFor`. `scripts/configure_iya_sts.py` registers the client with `oauthIdTokenSignedResponseAlg: RS256` (iya-sts's name for `id_token_signed_response_alg`). A `session-revoked` that matched no tracked session ends the demo's one local session (`RememberLiveEvent` in `demo/main.cpp`, not the library).

## tlsCa, the iya-sts trust chain

`tlsCa` (demo default `generated/idp-ca.pem`) is iya-sts's listener CA trust chain. `scripts/configure_iya_sts.py` writes the whole chain on every run via `scripts/trust_chain.py` (`GET /tls/server-certificate`, falling back to the handshake) and prints the path, anchor subject and SHA-256. `src/http.cpp` loads every PEM block as an anchor (and, with `tlsCa` set, no system roots) and verifies the host name (`SSL_set1_host`, or `X509_VERIFY_PARAM_set1_ip_asc` for an IP literal, which gets no SNI). There is no pinned shortcut: a forged leaf followed by the real CA certificates fails verification. The test and build stages copy only `CMakeLists.txt`, `VERSION`, `include`, `src`, `tests`, `scripts` and `demo/main.cpp`; the demo stage then does `COPY demo demo`, and `.dockerignore` excludes `demo/generated/*` except `idp-ca.pem`, so the image carries the chain and no secret, and a build without it still succeeds. Rebuild the demo image after re-running the install script against a different iya-sts. `demo/entrypoint.sh` still refreshes the chain at start unless `TLS_CA_REFRESH=0`.

The install script never prints a generated test-user password or the client secret: a generated password goes to `demo/generated/<user>.password` and the client secret to the file `secretFile` names, each created mode 0600, and only the password file's path is printed; `--dry-run`'s plan never holds the client secret. No line it or the live script prints carries anything derived from a password or secret.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /live-status` is the JSON above. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. The signals receiver runs when `signals` is not false.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application.

```sh
python scripts/configure_iya_sts.py --config demo/oidc.json
```

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 while another demo is already using it.
