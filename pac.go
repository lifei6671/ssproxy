package ssproxy

import "log"

var sources map[string]string

func registerTemplate(name string, source string) {
	if sources == nil {
		sources = make(map[string]string)
	}
	_, ok := sources[name]
	if ok {
		log.Fatalf("ERROR: duplicate template %s", name)
	}
	sources[name] = source
}

func init() {

	registerTemplate("proxy.pac.tpl", `function FindProxyForURL(url, host) {
    var DEFAULT_PROXY = "DIRECT";
{{$ServerName :=.Server}}
    if (host == "127.0.0.1" ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return DEFAULT_PROXY;
    }
    
    var RUNNING_PROXY = "{{with .Proxy }}{{range .}} {{.Category}} {{.Address}};{{end}}{{end}}{{with .Ssh}}{{range .}} SOCKS {{$ServerName}}:{{.}};{{end}}{{end}}DIRECT";
    {{with .Role}}{{range .}}
    if({{MacPacFormat .Name}}.test(url)){ return {{if myeq .Category  "a" }}RUNNING_PROXY{{else}}DEFAULT_PROXY{{end}} }
    {{end}}{{end}}
   {{with .GFW}}{{range .}}
   if({{MacPacFormat .}}.test(url)){ return  RUNNING_PROXY;  }
   {{end}}{{end}}
    return DEFAULT_PROXY;
    
}`)

	registerTemplate("android.pac.tpl", `function FindProxyForURL(url, host) {
    var DEFAULT_PROXY = DIRECT;
{{$ServerName :=.Server}}
    
    var RUNNING_PROXY = "{{with .Proxy }}{{range .}} {{.Category}} {{.Address}};{{end}}{{end}}{{with .Ssh}}{{range .}} SOCKS {{$ServerName}}:{{.}};{{end}}{{end}}DIRECT";
    {{with .Role}}{{range .}}
    if( dnsDomainIs(host, ".{{.Name}}") ){ return {{if myeq .Category  "a" }}RUNNING_PROXY{{else}}DEFAULT_PROXY{{end}} }
    {{end}}{{end}}
   {{with .GFW}}{{range .}}
   if( dnsDomainIs(host, ".{{.}}") ){ return  RUNNING_PROXY;  }
   {{end}}{{end}}
    return DEFAULT_PROXY;
    
}`)
}
