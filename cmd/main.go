package main

import (
	"context"
	"github.com/BurntSushi/toml"
	"github.com/lifei6671/ssproxy"
	"github.com/lifei6671/ssproxy/logs"
	_ "github.com/mkevac/debugcharts" // 可选，添加后可以查看几个实时图表数据
	"gopkg.in/urfave/cli.v2"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof" // 必须，引入 pprof 模块
	"os"
	"time"
)

const defaultGFWListURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
const APP_VERSION = "0.1"

func main() {
	defer logs.Flush()

	if os.Getenv("debugPProf") == "true" {
		go func() {
			// terminal: $ go tool pprof -http=:8081 http://localhost:6060/debug/pprof/heap
			// web:
			// 1、http://localhost:8081/ui
			// 2、http://localhost:6060/debug/charts
			// 3、http://localhost:6060/debug/pprof
			log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
		}()
	}

	proxy := ssproxy.NewProxyServer()

	proxy.SetDeadline(time.Second * 30)
	go func() {
		tunnel := &ssproxy.ProxyTunnel{Name: "ss", UserName: "aes-256-cfb", Password: "_hvolZ8H-mZ_bTar", Type: "ss", Addr: "la1533.256ss.com:32318"}
		if err := proxy.AddRouteFromGFWList(defaultGFWListURL, tunnel); err != nil {
			log.Fatal("添加路由失败 ->", err)
		}
	}()

	defer func() {
		_ = proxy.Close()
	}()

	if err := proxy.Listen(context.Background(), "tcp", "127.0.0.1:8580"); err != nil {
		log.Fatal(err)
	}
}

type (
	ProxyConfig struct {
		Listen string                 `toml:"listen"`
		Proxy  map[string]ProxyTunnel `toml:"proxy"`
		Rules  []Rule                 `toml:"rules"`
	}
	ProxyTunnel struct {
		Name     string `toml:"name" json:"name"`
		Type     string `toml:"type" json:"type"`
		Addr     string `toml:"addr" json:"addr"`
		UserName string `toml:"username" json:"username"`
		Password string `toml:"password" json:"password"`
	}
	Rule struct {
		//支持多个代理负载均衡
		Proxy []struct {
			//代理名称
			ProxyName string `toml:"proxy_name"`
			//权重，权重越高流量越大
			Weight int `toml:"weight" json:"weight"`
		} `toml:"proxy" json:"proxy"`
		//匹配规则
		Condition struct {
			//规则类型：如果是 GFW 则 Pattern 指定的是 GFWList 获取地址，默认 HostWildcardCondition 规则统配，HostRegexCondition：域名正则
			ConditionType string `toml:"condition_type" json:"condition_type"`
			Pattern       string `toml:"pattern" json:"pattern"`
		} `toml:"condition" json:"condition"`
	}
)

func Run() {
	app := &cli.App{}
	app.Name = "ssproxy"
	app.Usage = "A proxy tool"
	app.Version = APP_VERSION
	app.Commands = []*cli.Command{
		start,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("启动命令行失败 -> %s", err)
	}
}

var start = &cli.Command{
	Name:        "run",
	Usage:       "启动本地代理",
	Description: `启动一个本地代理,支持HTTP、Socks5代理，支持二级代理以及ShadowSocks.`,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "gfwlist",
			Aliases: []string{"gfw"},
			Value:   defaultGFWListURL,
			Usage:   "GFW文件原始URL",
		},
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"f"},
			Value:   "./config/config.conf",
			Usage:   "配置文件路径",
		},
		&cli.StringFlag{
			Name:  "addr",
			Value: ":8580",
			Usage: "本地监听的地址和端口号：127.0.0.1:8580",
		},
	},
	Action: func(ctx *cli.Context) error {

		configFile := ctx.String("config")

		if b, err := ioutil.ReadFile(configFile); err == nil {
			var config ProxyConfig
			if _, err := toml.Decode(string(b), &config); err != nil {
				logs.Error("解析配置失败 ->", err)
				os.Exit(-1)
			}

		}

		return nil
	},
}
