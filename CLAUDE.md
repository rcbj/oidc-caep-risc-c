# oidc-caep-risc-c

A confidential OpenID Connect relying party for a traditional C or C++ application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

The protocol is implemented once, in C++17, in `src/`. `include/iya/oidc.hpp` is the C++ API. `include/iya_oidc.h` is the C ABI: `extern "C"` functions in this library call those classes. C and C++ callers link one binary, `iya_oidc`. Do not implement the protocol a second time behind the C header. Do not wrap another language port.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. The default scope string still names those two scopes. They are removed after that default is applied. A value that is neither true nor false is refused. The shipped demo omits `signals`, so they stay on. `pollIntervalMs` is a millisecond pause, not a port.

The license is the MIT License in `LICENSE`. Publishing is not set up. `develop` and `main` are the branches the test workflow runs.

Cryptography is OpenSSL from the Debian packages (`libssl` and `libcrypto`). HTTP/1.1 and JSON are in this repository. No curl, no JSON library, no OAuth library, and no Boost.

## Layout

| Path | What it is |
|---|---|
| `include/iya/oidc.hpp` | C++ classes. `FromFile`, `Authorize`, `Complete`. |
| `include/iya_oidc.h` | The same operations as `extern "C"`. |
| `src` | The only implementation. |
| `tests` | `ctest`. A stub provider and a stub transmitter. No live iya-sts. |
| `demo` | `demo/main.cpp` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client. `trust_chain.py` refreshes the listener CA file named by `tlsCa`. |
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

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. The signals receiver runs when `signals` is not false.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application.

```sh
python scripts/configure_iya_sts.py --config demo/oidc.json
```

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 while another demo is already using it.
