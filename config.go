package ssproxy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/lifei6671/ssproxy/logs"
	"net/http"
)

type (
	ProxyConfig struct {
		Listen   string                 `toml:"listen" json:"listen"`
		GFWList  string                 `toml:"gfw_list" json:"gfw_list"`
		GFWProxy []string               `toml:"gfw_proxy" json:"gfw_proxy"`
		Proxy    map[string]ProxyTunnel `toml:"proxy" json:"proxy"`
		Rules    map[string]ProxyRule   `toml:"rule" json:"rule"`
	}
	ProxyTunnel struct {
		Name     string `toml:"name" json:"name"`
		Type     string `toml:"type" json:"type"`
		Addr     string `toml:"addr" json:"addr"`
		UserName string `toml:"username" json:"username"`
		Password string `toml:"password" json:"password"`
	}
	ProxyRule struct {
		//规则类型：默认 HostWildcardCondition 规则统配，HostRegexCondition：域名正则
		ConditionType string   `toml:"condition_type" json:"condition_type"`
		Pattern       []string `toml:"pattern" json:"pattern"`
	}
	ProxyRoute struct {
		Rule    *Rule
		Channel map[string]*ProxyTunnel
	}
)

func (p *ProxyConfig) String() string {
	if p == nil {
		return ""
	}
	buf := bytes.NewBufferString("")

	if err := toml.NewEncoder(buf).Encode(p); err == nil {
		return buf.String()
	}
	return ""
}

func (proxy *ProxyTunnel) String() string {
	return fmt.Sprintf("name:%s - addr:%s - type:%s - username:%s", proxy.Name, proxy.Addr, proxy.Type, proxy.UserName)
}

func (proxy *ProxyRoute) String() string {
	if proxy == nil {
		return ""
	}
	b, err := json.Marshal(proxy)
	if err != nil {
		return ""
	}
	return string(b)
}

func (p *ProxyConfig) Resolve() (map[string]*ProxyRoute, error) {
	routes := make(map[string]*ProxyRoute)

	if p.GFWList != "" && len(p.GFWProxy) > 0 {
		gfwProxy := make(map[string]*ProxyTunnel)

		for _, s := range p.GFWProxy {
			if tunnel, ok := p.Proxy[s]; ok {
				gfwProxy[tunnel.Name] = &tunnel
			}
		}
		if len(gfwProxy) <= 0 {
			goto CustomRule
		}
		resp, err := http.Get(p.GFWList)

		if err != nil {
			logs.Error("获取 GFW 规则失败 ->", err)
			return nil, err
		}
		defer safeClose(resp.Body)
		decoder := base64.NewDecoder(base64.StdEncoding, resp.Body)

		reader := bufio.NewReader(decoder)

		rules, err := ParseRules(reader)

		if err != nil {
			return nil, err
		}

		for _, rule := range rules {
			if route, ok := routes[rule.Raw]; ok {
				for k, v := range gfwProxy {
					route.Channel[k] = v
				}
			} else {
				routes[rule.Raw] = &ProxyRoute{
					Rule:    rule,
					Channel: gfwProxy,
				}
			}
		}
	}
	goto CustomRule
CustomRule:
	for name, rule := range p.Rules {
		if len(rule.Pattern) <= 0 {
			continue
		}
		proxy, ok := p.Proxy[name]

		if !ok {
			logs.Warn("代理不存在 ->", name)
			continue
		}

		for _, pattern := range rule.Pattern {
			if rule, err := ParseRule(pattern); err == nil {
				if route, ok := routes[rule.Raw]; ok {
					route.Channel[proxy.Name] = &proxy
				} else {
					routes[rule.Raw] = &ProxyRoute{
						Rule:    rule,
						Channel: map[string]*ProxyTunnel{proxy.Name: &proxy},
					}
				}
			} else {
				logs.Warn("解析规则失败 ->", err)
			}
		}
	}

	return routes, nil
}
