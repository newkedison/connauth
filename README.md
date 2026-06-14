# connauth

connauth authenticates a client over UDP before allowing TCP forwarding to a
backend service such as SSH. It is an extra network gate, not a replacement for
SSH public-key authentication, VPN, host firewall rules, or backend service
authentication.

## Security Model

The client and server use a two-step challenge-response protocol. The client
sends an encrypted challenge request without a token. The server replies only
when the key is valid, then the client sends an encrypted challenge response
containing the token and both nonces. The final response is always silent:
correct and incorrect tokens both produce no UDP reply.

Messages are bound to `server_id`, `client_id`, `key_id`, target port, and
nonces. Captured packets cannot be replayed, and a challenge can only be used
from the source IP that requested it. Server and client clocks must be
synchronized; enable NTP on both sides.

Authorization is still source-IP based. Devices behind the same NAT or shared
public IP may share access during the authorization window. Deny lists override
allow lists and token authorization.

## Build And Test

```bash
GOPROXY=https://goproxy.io go test ./...
GOPROXY=https://goproxy.io go build ./cmd/authserver
GOPROXY=https://goproxy.io go build ./cmd/authclient
```

Validate config without opening listeners:

```bash
./authserver -c server_config.yaml --check-config
./authclient -c client_config.yaml --check-config
```

## Configuration

Start from `cmd/authserver/config.yaml.template` and
`cmd/authclient/config.yaml.template`. Replace all `CHANGE_ME_*` values with
random secrets. Use at least 32 random bytes encoded with base64url or hex for
keys and tokens. Keep config files out of Git and set permissions to `0600`.

Server key rotation: add the new `authkeys` entry with a unique `id`, deploy the
server config, update clients to use the new `keyid` and `key`, verify access,
then remove the old key after the overlap window.

Token rotation: add the new token to the target `allowtokens`, deploy the
server config, update clients, verify access, then remove the old token.


## Operations

Supervisor remains a suitable process manager. Use `autorestart=true`,
`startsecs=5`, `stopwaitsecs=10`, explicit `user`, `directory`, `environment`,
and `umask=077`. Keep old and new instance binaries, configs, logs, and program
names separate during migration.

