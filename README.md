# connauth

connauth authenticates clients over UDP and then forwards TCP connections to a
backend service, such as SSH.

[中文说明](README.zh-CN.md)

## Why?

Many private services are still reachable over the public Internet. Even when
SSH keys, service passwords, or other application-level authentication are in
place, it is useful to hide the service behind an additional network gate.

A firewall can do this, but maintaining allow lists is inconvenient when client
addresses change often. [Port knocking](https://en.wikipedia.org/wiki/Port_knocking)
is one way to open access on demand, but common implementations have a few
drawbacks:

* they often need root privileges to update firewall rules
* knocking packets can be observed and replayed if the protocol is weak
* some implementations temporarily open the protected port to more sources than
  intended

Inspired by [giuliocomi/knockandgo](https://github.com/giuliocomi/knockandgo),
connauth takes a different approach: authenticate the client first, then forward
the connection directly to the backend service.

connauth is an extra network gate, not a replacement for
[SSH](https://en.wikipedia.org/wiki/Secure_Shell) public key authentication,
[VPN](https://en.wikipedia.org/wiki/Virtual_private_network), host firewall
rules, or backend service authentication.

## Features

* runs without root or administrator privileges
* authenticates access by static IP or
  [token](https://en.wikipedia.org/wiki/Authentication_token)
* supports per-port allow rules, global allow rules, and global deny rules
* supports reusable named token and IP rules in the server config
* supports token rotation by accepting multiple valid tokens during migration
* supports auth key rotation with `keyid`, `notbefore`, and `notafter`
* uses encrypted UDP
  [challenge-response](https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication)
  authentication before forwarding traffic
* binds auth messages to `serverid`, `clientid`, `keyid`, port,
  [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce), and timestamp
* resists replay with client/server nonces, challenge TTL, and timestamp checks
* expires token-based authorization after a configurable time window
* limits active forwarded connections per source IP and per forward port
* validates configuration with `--check-config`
* optionally sends authserver logs to Aliyun SLS
* runs cross-platform, including Windows service mode

## Difference from knockandgo

* uses a fixed UDP auth port instead of random ports, because connauth is
  designed as a long-running service rather than a temporary tunnel like
  knockandgo
* uses shared keys and
  [AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) encrypted
  challenge-response messages instead of PEM certificate files
* forwards traffic directly after authentication, without changing firewall
  rules

## Build

Build the server and client binaries:

```bash
GOPROXY=https://goproxy.io go build ./cmd/authserver
GOPROXY=https://goproxy.io go build ./cmd/authclient
```

Run tests:

```bash
GOPROXY=https://goproxy.io go test ./...
```

## Usage

### Server side

1. Copy `authserver` to your server.
2. Copy `cmd/authserver/config.yaml.template` to the same directory and rename
   it to `server_config.yaml`.
3. Replace every `CHANGE_ME_*` value with your own random key or token.
4. Adjust `authaddr`, `forwardconfigs`, `allowtokens`, `allowips`, and deny
   rules for your environment.
5. Validate the config:

```bash
./authserver -c server_config.yaml --check-config
```

6. Start authserver:

```bash
./authserver -c server_config.yaml
```

### Client side

1. Copy `authclient` to your client.
2. Copy `cmd/authclient/config.yaml.template` to the same directory and rename
   it to `client_config.yaml`.
3. Set the server address, `serverid`, `keyid`, key, token, target port, and
   auth interval.
4. Validate the config:

```bash
./authclient -c client_config.yaml --check-config
```

5. Start authclient:

```bash
./authclient -c client_config.yaml
```

6. Connect to the forwarded TCP port as usual.

## Example

Suppose your server is `203.0.113.10`, and SSH listens on `127.0.0.1:22` on
that server. You want clients to connect through TCP port `40022`, while UDP
port `40100` is used for authentication.

Make sure clients can reach UDP `40100` and TCP `40022`.

Server config:

```yaml
serverid: "connauth-server"
loglevel: "info"

authaddr: "0.0.0.0:40100"

authkeys:
  - id: "primary-2026-06"
    key: "CHANGE_ME_RANDOM_32_BYTES_BASE64URL_AUTH_KEY"
    notbefore: "2026-06-01T00:00:00Z"
    notafter: "2026-09-01T00:00:00Z"

tokens:
  ssh-primary: "CHANGE_ME_RANDOM_LONG_TOKEN_FOR_SSH"

iprules:
  trusted-office: "198.51.100.0/24"

forwardconfigs:
  - bindport: 40022
    forwardaddr: "127.0.0.1:22"
    allowtokens:
      - tokenref: "ssh-primary"
    allowips:
      - ipref: "trusted-office"
    dropdelaytime: 0
    maxconnperip: 16
    maxconnglobal: 1024
    dialtimeoutms: 3000
    idletimeoutms: 300000
    authexpiredtime: 3600

globalallowtokens: []
globalallowips: []
globaldenyips: []
```

Client config:

```yaml
clientid: "workstation"
loglevel: "info"

servers:
  - addr: "203.0.113.10:40100"
    serverid: "connauth-server"
    keyid: "primary-2026-06"
    key: "CHANGE_ME_RANDOM_32_BYTES_BASE64URL_AUTH_KEY"
    authconfigs:
      - token: "CHANGE_ME_RANDOM_LONG_TOKEN_FOR_SSH"
        port: 40022
        interval: 60
```

Run authclient, then connect:

```bash
ssh -p 40022 user@203.0.113.10
```

## Authentication flow

The client first sends an encrypted challenge request without the token. If
`serverid`, `keyid`, and the shared key are valid, the server returns an
encrypted challenge. The client then sends an encrypted challenge response that
contains the token and both nonces.

The final step is intentionally silent: valid and invalid tokens both produce
no UDP reply. Use client and server logs when troubleshooting.

Server and client clocks must be synchronized. Enable
[NTP](https://en.wikipedia.org/wiki/Network_Time_Protocol) on both sides.

## Configuration notes

Use long random values for keys and tokens. At least 32 random bytes encoded as
base64url or hex is recommended. Do not use the example placeholders directly.

`tokens` and `iprules` define reusable named rules. Reference them from
`allowtokens`, `globalallowtokens`, `allowips`, `globalallowips`, or
`globaldenyips` with `tokenref` and `ipref`:

```yaml
tokens:
  ssh-primary: "CHANGE_ME_RANDOM_LONG_TOKEN_FOR_SSH"

iprules:
  trusted-office: "198.51.100.0/24"

forwardconfigs:
  - bindport: 40022
    forwardaddr: "127.0.0.1:22"
    allowtokens:
      - tokenref: "ssh-primary"
      - token: "CHANGE_ME_ONE_OFF_RANDOM_TOKEN"
    allowips:
      - ipref: "trusted-office"
      - ip: "192.0.2.10"
```

Use `tokenref` and `ipref` when the same rule is shared by multiple ports or
global rules. Use inline `token` and `ip` entries for one-off rules. A single
rule entry must not mix `tokenref` with inline token fields, or `ipref` with
inline IP fields.

`globaldenyips` overrides static IP allow rules and token authorization.

Authorization is still source-IP based. Devices behind the same NAT or shared
public IP may share access during the authorization window.

Keep config files out of Git. Set file permissions to `0600` where possible.

## Operations

Supervisor, systemd, or Windows service mode can keep the process running. When
migrating between old and new instances, keep binaries, configs, logs, and
process names separate until the new instance has been verified.

To rotate an auth key, keep the old key in `authkeys`, add the new key with a
new `id`, deploy the server config, then update clients to use the new `keyid`
and key. During the overlap window, clients using either active `keyid` can
authenticate. Remove the old key only after all clients have migrated.

To rotate a token, add the new token to the relevant allow list, deploy the
server config, update clients, verify access, then remove the old token.
