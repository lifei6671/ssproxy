package main

import (
	"context"
	"github.com/BurntSushi/toml"
	"github.com/howeyc/fsnotify"
	"github.com/lifei6671/ssproxy"
	"github.com/lifei6671/ssproxy/logs"
	"gopkg.in/urfave/cli.v2"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof" // 必须，引入 pprof 模块
	"os"
)

const defaultGFWListURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
const APP_VERSION = "0.1"

func main() {
	defer logs.Flush()

	Run()
}

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
			Value:   "./config/config.toml",
			Usage:   "配置文件路径",
		},
		&cli.StringFlag{
			Name:  "addr",
			Value: ":8580",
			Usage: "本地监听的地址和端口号：127.0.0.1:8580",
		},
		&cli.BoolFlag{
			Name:  "pprof",
			Value: false,
			Usage: "是否开启 pprof 模块",
		},
		&cli.StringFlag{
			Name:  "pprof_addr",
			Value: "127.0.0.1:6060",
			Usage: "pprof 模块监听地址和端口号",
		},
	},
	Action: func(ctx *cli.Context) error {

		configFile := ctx.String("config")

		var config ssproxy.ProxyConfig

		if b, err := ioutil.ReadFile(configFile); err == nil {

			if _, err := toml.Decode(string(b), &config); err != nil {
				logs.Error("解析配置失败 ->", err)
				return err
			}
		}

		if ctx.Bool("pprof") {
			go func() {
				if err := http.ListenAndServe(ctx.String("pprof_addr"), nil); err != nil {
					logs.Error(err)
				}
			}()
		}

		proxy := ssproxy.NewProxyServer()

		go func() {
			_ = loadConfig(proxy, configFile)
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				logs.Error("创建文件监视器失败 ->", err)
				return
			}
			go func() {
				for {
					select {
					case ev := <-watcher.Event:
						//如果是修改了配置文件
						if ev.IsModify() {
							_ = loadConfig(proxy, configFile)
							logs.Info("配置文件已加载 ->", configFile)
						} else if ev.IsRename() {
							watcher.WatchFlags(configFile, fsnotify.FSN_MODIFY|fsnotify.FSN_RENAME)
						}
					case err := <-watcher.Error:
						logs.Error("配置文件监控器错误 ->", err)

					}
				}
			}()

			err = watcher.WatchFlags(configFile, fsnotify.FSN_MODIFY|fsnotify.FSN_RENAME)

			if err != nil {
				logs.Error("监控配置文件失败 ->", err)
			}
		}()

		defer func() {
			_ = proxy.Close()
		}()

		if err := proxy.Listen(context.Background(), "tcp", config.Listen); err != nil {
			log.Fatal(err)
		}
		return nil
	},
}

func loadConfig(proxy *ssproxy.ProxyServer, configFile string) error {
	var config ssproxy.ProxyConfig

	if b, err := ioutil.ReadFile(configFile); err == nil {

		if _, err := toml.Decode(string(b), &config); err != nil {
			logs.Error("解析配置失败 ->", err)
			return err
		}
	}
	routes, err := config.Resolve()
	if err != nil {
		log.Fatal("解析路由规则失败 ->", err)
	}
	logs.Info("路由规则解析完成 ->", len(routes))
	for _, route := range routes {
		if err := proxy.AddRule(route); err != nil {
			logs.Warn("加入规则失败 ->", err)
		}
	}
	return nil
}
