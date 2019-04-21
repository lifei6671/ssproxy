module github.com/lifei6671/ssproxy

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/StackExchange/wmi v0.0.0-20181212234831-e0a55b97c705 // indirect
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gorilla/websocket v1.4.0 // indirect
	github.com/mkevac/debugcharts v0.0.0-20180124214838-d3203a8fa926
	github.com/pkg/errors v0.8.1
	github.com/shadowsocks/shadowsocks-go v0.0.0-20190307081127-ac922d10041c
	github.com/shirou/gopsutil v2.18.12+incompatible // indirect
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	gopkg.in/urfave/cli.v2 v2.0.0-20180128182452-d3ae77c26ac8
)

replace golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 => github.com/golang/time v0.0.0-20190308202827-9d24e82272b4

replace golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 => github.com/golang/crypto v0.0.0-20190308221718-c2843e01d9a2

replace golang.org/x/net v0.0.0-20190415214537-1da14a5a36f => github.com/golang/net v0.0.0-20190415214537-1da14a5a36f

replace golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a => github.com/golang/sys v0.0.0-20190215142949-d0b11bdaac8a
