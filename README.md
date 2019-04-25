# ssproxy

Golang实现的socks5、http代理协议，支持黑名单和白名单。支持通过二级代理包括shadowsocks连接。

## 功能列表

- 自动识别 HTTP 和 socks5 协议
- 支持二级代理，可通过 shadowsocks 上网
- 支持黑名单和白名单，规则基于 ad block
- 支持多代理负载均衡
- 支持默认二级代理，当直连失败会使用默认代理连接

## 使用

1. 拉取源码

```go
go get github.com/lifei6671/ssproxy
```

2. 编译

```go
go build -o=ssproxy main.go
```

3. 配置

将 `config/config.toml.example` 重命名为 `config/config.toml`。

4. 启动

```go
./ssproy run -config=./config/config.toml
```


## License

MIT License