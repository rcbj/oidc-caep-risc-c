# oidc-caep-risc-c

A confidential OpenID Connect relying party for a traditional C or C++ application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. The token request is on the back channel. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused.

The protocol is implemented once, in C++17. `include/iya/oidc.hpp` is that implementation. `include/iya_oidc.h` declares the same operations as `extern "C"`. Those functions are defined in this library and call the C++ classes. C callers and C++ callers link one library, `iya_oidc`. The C functions are the ABI. They are not a second protocol stack.

JSON configuration keys match the Go library `oidc-caep-risc-go`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. The default scope string still names those two scopes. The shipped demo leaves `signals` on (the key is omitted). A value that is neither `true` nor `false` is refused. `pollIntervalMs` is a millisecond pause, not a port.

The license is MIT. Publishing is not set up.

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

Tokens stay in this process. Keep the transaction until the browser returns. A code is accepted once. A callback that is not this sign-in is refused. ID tokens are checked, including `at_hash`.

## Configuration

| Key | Meaning |
|---|---|
| `clientId`, `client_id` | Confidential client identifier. Required. |
| `clientSecret` | Literal, `env:NAME`, or `file:path`. Required unless `private_key_jwt`. |
| `tokenEndpointAuthMethod` | `client_secret_basic` (default), `client_secret_post`, or `private_key_jwt`. `"none"` is refused. |
| `redirectUri`, `redirect_uri` | Authorization code redirect. Required. |
| `postLogoutRedirectUri`, `post_logout_redirect_uri` | Optional end-session redirect. |
| `scopes` | String or array. Must include `openid`. Omitted uses `openid profile email offline_access ssf.read ssf.manage`. |
| `signals` | Omitted or `true` keeps CAEP and RISC. `false` drops `ssf.read` and `ssf.manage` from the applied scope list and does not start the receiver. |
| `metadataUrl` | `https://issuer/.well-known/openid-configuration`. |
| `issuer` | Must match the issuer in that URL when both are set. |
| `metadataFile` | Provider metadata already on disk. |
| `privateKey` | PEM for `private_key_jwt`, as a literal, `env:NAME`, `file:path`, or a path. |
| `privateKeyAlg` | Defaults to `RS256`. |
| `tlsCa` | The provider's TLS listener CA trust chain: PEM, inline, `file:`, `env:`, or a path (demo: `generated/idp-ca.pem`). Every certificate in it is a trust anchor, and the system roots are not added. A missing file or an empty env var omits the key, and the system roots are used. |
| `par` | `auto` (default), `always`, or `never`. |
| `idTokenSignedResponseAlg` | Pins the ID token algorithm when set. |
| `clockToleranceSec` | Defaults to 30. |
| `maxIdTokenAgeSec` | Defaults to 600. |
| `allowInsecure` | Allows a non-loopback `http` provider in development. |
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
