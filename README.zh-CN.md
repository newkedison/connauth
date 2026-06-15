# connauth

connauth 先通过 UDP 认证客户端，再把 TCP 连接转发到后端服务，例如 SSH。

[English README](README.md)

## 为什么？

很多内部服务最终还是会暴露在公网入口上。即使已经使用 SSH key、服务密码或
应用自己的认证机制，在服务前面再加一层网络入口控制，仍然很有价值。

防火墙可以做到这一点，但如果客户端出口 IP 经常变化，维护 allow list 会很
麻烦。[port knocking](https://en.wikipedia.org/wiki/Port_knocking) 也是一种
按需开放入口的方式，不过常见实现有几个问题：

* 通常需要 root 权限修改防火墙规则
* 如果协议设计较弱，knocking packet 可能被观察或重放
* 有些实现会在短时间内把受保护端口开放给比预期更大的来源范围

受 [giuliocomi/knockandgo](https://github.com/giuliocomi/knockandgo) 启发，
connauth 采用了另一种方式：先认证客户端，再直接把连接转发到真实后端服务。

connauth 只是额外的网络入口控制。它不能替代
[SSH](https://en.wikipedia.org/wiki/Secure_Shell) public key authentication、
[VPN](https://en.wikipedia.org/wiki/Virtual_private_network)、主机防火墙规则，
也不能替代后端服务自身的认证。

## 功能

* 不需要 root 或 administrator 权限
* 支持按静态 IP 或 [token](https://en.wikipedia.org/wiki/Authentication_token)
  授权访问
* 支持按端口配置 allow rule，也支持全局 allow rule 和 deny rule
* 支持在服务端配置里复用命名 token rule 和 IP rule
* 支持迁移期间同时接受多个有效 token，方便 token rotation
* 支持通过 `keyid`、`notbefore`、`notafter` 做 auth key rotation
* 转发流量前，先通过加密 UDP
  [challenge-response](https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication)
  完成认证
* 认证消息绑定 `serverid`、`clientid`、`keyid`、端口、
  [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) 和时间戳
* 通过客户端/服务端 nonce、challenge TTL 和时间戳检查降低 replay 风险
* token 授权只在配置的时间窗口内有效
* 限制每个来源 IP、每个转发端口的活跃连接数
* 支持 `--check-config` 检查配置
* authserver 可选把日志发送到阿里云 SLS
* 跨平台运行，包括 Windows service mode

## 和 knockandgo 的区别

* 本项目使用固定 UDP auth port，而不是随机端口，因为本项目的设计目标是作为
  长期运行的服务，而不是像 knockandgo 一样只是搭建一个临时通道
* 使用共享密钥和 [AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
  加密的 challenge-response 消息，而不是 PEM 证书文件
* 认证通过后直接转发流量，不修改防火墙规则

## 构建

构建服务端和客户端：

```bash
GOPROXY=https://goproxy.io go build ./cmd/authserver
GOPROXY=https://goproxy.io go build ./cmd/authclient
```

运行测试：

```bash
GOPROXY=https://goproxy.io go test ./...
```

## 使用方法

### 服务端

1. 把 `authserver` 复制到服务器。
2. 把 `cmd/authserver/config.yaml.template` 复制到同一目录，并重命名为
   `server_config.yaml`。
3. 把所有 `CHANGE_ME_*` 值替换成你自己的随机 key 或 token。
4. 按实际环境修改 `authaddr`、`forwardconfigs`、`allowtokens`、`allowips`
   和 deny rule。
5. 检查配置：

```bash
./authserver -c server_config.yaml --check-config
```

6. 启动 authserver：

```bash
./authserver -c server_config.yaml
```

### 客户端

1. 把 `authclient` 复制到客户端。
2. 把 `cmd/authclient/config.yaml.template` 复制到同一目录，并重命名为
   `client_config.yaml`。
3. 设置服务端地址、`serverid`、`keyid`、key、token、目标端口和认证间隔。
4. 检查配置：

```bash
./authclient -c client_config.yaml --check-config
```

5. 启动 authclient：

```bash
./authclient -c client_config.yaml
```

6. 像平常一样连接被转发的 TCP 端口。

## 示例

假设服务器地址是 `203.0.113.10`，服务器上的 SSH 监听在 `127.0.0.1:22`。
你希望客户端通过 TCP `40022` 连接 SSH，同时使用 UDP `40100` 做认证。

请确认客户端能够访问 UDP `40100` 和 TCP `40022`。

服务端配置：

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

客户端配置：

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

启动 authclient 后连接：

```bash
ssh -p 40022 user@203.0.113.10
```

## 认证流程

客户端先发送一个不带 token 的加密 challenge request。如果 `serverid`、
`keyid` 和共享 key 都正确，服务端会返回加密 challenge。随后客户端发送
challenge response，里面包含 token 和双方 nonce。

最后一步故意保持静默：token 正确或错误，服务端都不会发送 UDP 回复。排查
问题时，请看客户端和服务端日志。

服务端和客户端的系统时间必须同步。建议两边都启用
[NTP](https://en.wikipedia.org/wiki/Network_Time_Protocol)。

## 配置说明

key 和 token 应使用足够长的随机值。推荐至少 32 字节随机数据，并用
base64url 或 hex 编码。不要直接使用示例中的占位符。

`tokens` 和 `iprules` 用来定义可复用的命名规则。需要使用时，在
`allowtokens`、`globalallowtokens`、`allowips`、`globalallowips` 或
`globaldenyips` 里通过 `tokenref`、`ipref` 引用：

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

如果同一个规则会被多个端口或全局规则复用，优先使用 `tokenref` 和 `ipref`。
只在某个位置使用一次的规则，可以直接写 inline `token` 或 `ip`。同一个规则
项里不能同时混用 `tokenref` 和 inline token 字段，也不能同时混用 `ipref` 和
inline IP 字段。

`globaldenyips` 优先级高于静态 IP allow rule 和 token 授权。

授权仍然基于来源 IP。处在同一个 NAT 或共享公网 IP 后面的设备，可能会在授权
有效期内共享访问权限。

配置文件不要提交到 Git。条件允许时，把配置文件权限设置为 `0600`。

## 运维

可以使用 supervisor、systemd 或 Windows service mode 保持进程运行。迁移新旧
实例时，在新实例验证完成前，建议把二进制、配置、日志和进程名分开。

轮换 auth key 时，先保留旧 key，并在 `authkeys` 中加入带新 `id` 的新 key，
然后部署服务端配置，再把客户端切换到新的 `keyid` 和 key。重叠窗口内，使用
任意一个仍然有效的 `keyid` 都可以认证。确认所有客户端都已迁移后，再删除旧
key。

轮换 token 时，先把新 token 加入对应 allow list，部署服务端配置，更新客户端，
确认访问正常后，再删除旧 token。
