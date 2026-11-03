# oidc-caep-risc-c

A confidential OpenID Connect relying party for a traditional C or C++ application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. The token request is on the back channel. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused.

The protocol is implemented once, in C++17. `include/iya/oidc.hpp` is that implementation. `include/iya_oidc.h` declares the same operations as `extern "C"`. Those functions are defined in this library and call the C++ classes. C callers and C++ callers link one library, `iya_oidc`. The C functions are the ABI. They are not a second protocol stack.

JSON configuration keys match the Go library `oidc-caep-risc-go`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. The default scope string still names those two scopes. The shipped demo leaves `signals` on (the key is omitted). A value that is neither `true` nor `false` is refused. `pollIntervalMs` is a millisecond pause, not a port.

The license is MIT.

## Using it from CMake

The build installs the library, its public headers and a CMake package. It builds static by
default and shared with `-DBUILD_SHARED_LIBS=ON`; `-DIYA_OIDC_BUILD_TESTS=OFF -DIYA_OIDC_BUILD_PROGRAMS=OFF`
builds the library alone (both are on only when this is the top-level project). Then:

```cmake
find_package(iya_oidc REQUIRED)
target_link_libraries(app PRIVATE iya::oidc)
```

The package finds the library's own dependencies, and the target carries the include
directory and C++17. The Docker test stage checks this: it installs the static and the shared
library and builds the C++ smoke test against each through `find_package` (`tests/package/`).

A pull request merged into `main` releases the library after the test workflow succeeds on that commit: `release.yml` tags `v<VERSION>` and makes a GitHub Release, whose source archive is what a package recipe (such as a ConanCenter one) builds from. A direct push does not release. A tag that already exists stays; the next release is a new version in `VERSION`, which the CMake project, the package and the tag all read.

## Usage

C++:

```cpp
#include "iya/oidc.hpp"

auto rp = iya::RelyingParty::FromFile("oidc.json");
iya::Transaction request = rp->Authorize();
// redirect the browser to request.url; keep state, nonce, and code_verifier
iya::Login who = rp->Complete(query, request);
```

`iya::OidcError` extends `std::runtime_error`. `what()` is the message. `code` is `config`, `discovery`, `protocol`, `validation`, `signature`, or `ssf`. The C++ methods throw that type and do not log.

C:

```c
#include "iya_oidc.h"

iya_oidc_error err;
iya_oidc_rp *rp = NULL;
if (iya_oidc_open_file("oidc.json", &rp, &err) != IYA_OIDC_OK) return err.code;
iya_oidc_txn *txn = NULL;
if (iya_oidc_authorize(rp, &txn, &err) != IYA_OIDC_OK) return err.code;
/* redirect the browser to iya_oidc_txn_url(txn); keep the transaction */
iya_oidc_login *who = NULL;
if (iya_oidc_complete(rp, keys, vals, n, txn, &who, &err) != IYA_OIDC_OK) return err.code;
```

A C function logs once with `fprintf(stderr, "oidc: %s: %s\n", code, message)` and returns the integer code. `err.message` is the same text. `iya_oidc_error_name` maps the code to the same names as `iya::OidcError::code`.

Tokens stay in this process. Keep the transaction until the browser returns. A code is accepted once. A callback that is not this sign-in is refused. ID tokens are checked, including `typ` and `at_hash`.

`iya_oidc_create` (`RelyingParty::Create`) and `iya_oidc_open_file` (`RelyingParty::FromFile`) resolve the configuration the same way: the same defaults, the same redirect-URI rule, and metadata given inline (`metadata`) is validated like discovered metadata. A relative path in a configuration given to `iya_oidc_create` is read from the current directory.

### DPoP (RFC 9449)

`dpop` is `auto` (default), `always`, or `never`. `auto` uses DPoP when the provider lists `ES256` in `dpop_signing_alg_values_supported`; `always` fails at creation when it does not; `never` sends no proofs. The key is a P-256 key generated when the relying party is created and held in memory, or the PEM key `dpopKey` names (for an application that runs several processes). A proof goes on every request to the PAR and token endpoints (code, refresh and client-credentials grants), and on every resource request made with a DPoP-bound token (UserInfo, the SSF transmitter), with `ath`. `dpop_jkt` is sent on the authorization request (in the PAR body when PAR is used). A `use_dpop_nonce` answer (400 from the authorization server, 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` from a resource server) is retried once with the nonce it gave, and the latest nonce per server origin goes on the next proof. When a proof was sent the `token_type` must be `DPoP`, and when none was it must be `Bearer`.

```c
int status = 0;
char *body = NULL;
iya_oidc_resource_request(rp, "GET", "https://api.example/items", token, NULL, NULL, &status, &body, &err);
```

`iya_oidc_resource_request` (`RelyingParty::ResourceRequest`) sends `Authorization: Bearer` or `Authorization: DPoP` with a proof as this relying party's tokens require. `iya_oidc_receiver_new_for_rp` (`iya::SignalsOptionsFor`) builds a receiver whose every transmitter call carries a client-credentials token from the relying party, with a proof when it is DPoP-bound.

### The session token cache

`Complete` keeps the tokens of a completed sign-in under a session identifier: the one passed to `iya_oidc_complete_session` (`Complete(query, txn, session_id)`), or one the library chooses (`iya_oidc_login_session_id`). `iya_oidc_session_access_token` (`SessionAccessToken`) returns the cached access token while it has more than 30 seconds left, and otherwise refreshes it (with a DPoP proof when DPoP is in use) and updates the entry. A failed refresh removes the entry and is refused. `iya_oidc_session_remove` (`RemoveSession`) clears an entry at sign-out; a receiver made with `iya_oidc_receiver_new_for_rp` also clears it when a CAEP event ends the session. The store is in memory; `iya_oidc_set_session_store` (`SetSessionStore`, an `iya::SessionStore`) replaces it with one shared by several processes.

### ID tokens

The accepted algorithms are `idTokenSigningAlgs` (default `["RS256"]`) narrowed to the ones the provider advertises; creation fails when none is left. `idTokenSignedResponseAlg` pins one algorithm, which the provider must advertise. `none` is never accepted, and a symmetric algorithm (`HS256`) only when it is named. The header must carry `typ` (`JWT` or `application/jwt`), and when the token response carries an access token the ID token must carry a matching `at_hash`; `requireIdTokenTypAndAtHash: false` checks them only when present. An `iat` more than `clockToleranceSec` in the future is refused. When `acr_values` is requested (`acrValues`, or `iya_oidc_authorize_with`), the ID token from the code exchange must carry an `acr` that is one of them; a refresh does not check it again.

## Configuration

| Key | Meaning |
|---|---|
| `clientId`, `client_id` | Confidential client identifier. Required. |
| `clientSecret` | Literal, `env:NAME`, or `file:path`. Required unless `private_key_jwt`. |
| `tokenEndpointAuthMethod` | `client_secret_basic` (default), `client_secret_post`, or `private_key_jwt`. `"none"` is refused. |
| `redirectUri`, `redirect_uri` | Authorization code redirect. Required. `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]`; `allowInsecure` does not widen this. A per-request redirect URI is held to the same rule. |
| `postLogoutRedirectUri`, `post_logout_redirect_uri` | Optional end-session redirect. |
| `scopes` | String or array. Must include `openid`. Omitted uses `openid profile email offline_access ssf.read ssf.manage`. |
| `signals` | Omitted or `true` keeps CAEP and RISC. `false` drops `ssf.read` and `ssf.manage` from the applied scope list and does not start the receiver. |
| `metadataUrl` | `https://issuer/.well-known/openid-configuration`. |
| `issuer` | Must match the issuer in that URL when both are set. |
| `metadataFile` | Provider metadata already on disk. |
| `metadata` | Provider metadata as an object, validated like discovered metadata. |
| `privateKey` | PEM for `private_key_jwt`, as a literal, `env:NAME`, `file:path`, or a path. |
| `privateKeyAlg` | Defaults to `RS256`. |
| `tlsCa` | The provider's TLS listener CA trust chain: PEM, inline, `file:`, `env:`, or a path (demo: `generated/idp-ca.pem`). Every certificate in it is a trust anchor, and the system roots are not added. A missing file or an empty env var omits the key, and the system roots are used. |
| `par` | `auto` (default), `always`, or `never`. When the provider sets `require_pushed_authorization_requests`, `never` fails at creation and `auto` always pushes. `always` without a PAR endpoint fails at creation. |
| `dpop` | `auto` (default), `always`, or `never`. |
| `dpopKey` | Optional P-256 PEM private key for DPoP, as a literal, `env:NAME`, `file:path`, or a path. Generated in memory when omitted. |
| `idTokenSigningAlgs` | Accepted ID token algorithms, a list. Defaults to `["RS256"]`. |
| `idTokenSignedResponseAlg` | Pins the ID token algorithm when set. |
| `requireIdTokenTypAndAtHash` | Defaults to `true`. `false` checks `typ` and `at_hash` only when present. |
| `acrValues` | `acr_values` to request, a string or a list. The ID token's `acr` must be one of them. |
| `clockToleranceSec` | Defaults to 30. |
| `maxIdTokenAgeSec` | Defaults to 600. |
| `allowInsecure` | Allows a non-loopback `http` provider in development. It does not relax the redirect-URI rule. |
| `ssf.transmitter` | Transmitter base URL. A trailing slash is removed. Required only when `signals` is on and the object is present. |
| `ssf.pollIntervalMs` | Poll pause in milliseconds. `3000` stays a poll interval. |

## Tests

```bash
docker build --target test .
```

The `test` stage builds the library and runs `ctest` in Debian bookworm. GitHub Actions uses that command. The demo image does not run the suite. The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts. `tests/trust.c` serves HTTPS from a four-certificate chain shaped like iya-sts's and checks that the whole `tlsCa` chain file is the trust store (the leaf alone or another root is refused), that a forged leaf followed by the real CA certificates is refused, that the host name is verified (right chain, wrong name refused; a DNS name and `127.0.0.1` via an IP SAN accepted), and that `scripts/trust_chain.py` writes the whole chain from `GET /tls/server-certificate` and from the handshake.

## Live iya-sts test and the nightly suite

```bash
python3 scripts/live_iya_sts.py
```

The script starts the latest `main` of iya-sts in a container (memory mode, no persistence, no clustering), registers the demo with it, signs in through the demo, emits CAEP `credential-change` and then `session-revoked`, and requires the demo's `GET /live-status` to show both, the second one with the local session ended. It prints JSON ending in `"ok": true`. `IYA_STS_URL` uses an iya-sts that is already running (and does not stop it), `IYA_STS_IMAGE` starts a fresh container from that image, and otherwise iya-sts `main` is cloned and built. `LIVE_STS_PORT` (default 18528) and `LIVE_DEMO_PORT` (default 18628) are the host ports; 3000, 8081 and 18481-18495 are refused. Always use a fresh iya-sts: a second run against an already-registered client is not supported. The library and the demo build and run only in containers; the script needs the host's `python3` (standard library) and Docker.

`GET /live-status` answers `{"signedIn", "subject", "receiver", "events": [{"type", "jti"}]}` and never a token. When a `session-revoked` event matches no tracked session, the demo ends its one local session and untracks it.

`.github/workflows/nightly.yml` runs the unit suite and the live script every day at 07:50 UTC (`50 7 * * *`), and on demand. Push and pull-request CI stays in `tests.yml`.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` (demo default `generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain presented in the TLS handshake when that is missing. It prints the path, the anchor's subject and its SHA-256.

The install script never prints a generated test-user password or the client secret: a generated password goes to `demo/generated/<user>.password` and the client secret to the file `secretFile` names, each created mode 0600, and only the password file's path is printed; `--dry-run`'s plan never holds the client secret. No line it or the live script prints carries anything derived from a password or secret.

The library loads every PEM block of `tlsCa` into its OpenSSL trust store, so the presented path ends at the self-signed Root, and it verifies that the listener's certificate names the host in the URL: a DNS name against a DNS SAN, an IP literal (such as `127.0.0.1`) against an IP SAN. A certificate that chains to the trusted root but does not name the host is refused, and so is a forged leaf sent ahead of the real CA certificates.

The demo image build copies `demo/` after compiling, and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`, so the image carries the chain at `/app/demo/generated/idp-ca.pem` with no bind mount. The client secret stays out of the image. A build before the install script has run still succeeds; the image then has no chain. Rebuild the image after re-running the install script against a different iya-sts. The entrypoint also refreshes the chain at start unless `TLS_CA_REFRESH=0`.

## Layout

| Path | What it is |
|---|---|
| `include/iya/oidc.hpp` | C++ classes. The protocol implementation. |
| `include/iya_oidc.h` | `extern "C"` ABI over those classes. |
| `src` | The only implementation. JSON, HTTP/1.1, and OpenSSL. |
| `tests` | C tests of the relying party and Shared Signals cases, plus one C++ smoke test. Both link `iya_oidc`. |
| `demo` | `demo/main.cpp` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts and writes the listener CA trust chain where `tlsCa` names it. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `scripts/trust_chain.py` | Fetches and saves that chain. |
| `scripts/live_iya_sts.py` | The live sign-in against a fresh iya-sts. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts the code flow and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` reports the sign-in and the accepted Shared Signals events as JSON, without tokens. The signals receiver runs when `signals` is not `false`.

`docker-compose.yml` sets `network_mode: host` and does not publish a host port. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when the registrar runs.

Register the client with:

```sh
python scripts/configure_iya_sts.py --config demo/oidc.json
```

It also writes the trust chain to `demo/generated/idp-ca.pem`; rebuild the demo image afterwards (`docker compose build`).

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 while another demo is already using it.
