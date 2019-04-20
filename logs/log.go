package logs

import (
	log "github.com/cihub/seelog"
)

var root log.LoggerInterface

func init() {
	root = NewLogger(`<seelog type="asynctimer" asyncinterval="1000000" minlevel="debug" maxlevel="error">
    <outputs formatid="main">
        <!-- 仅输出到终端 -->
        <console/>
    </outputs>
    <formats>
        <!-- 设置格式 -->
        <format id="main" format="%UTCDate %UTCTime - [%LEVEL] - %File:%Line - %Msg%n"/>
    </formats>
</seelog>`)
}

func NewLogger(config string) log.LoggerInterface {
	seelog, err := log.LoggerFromConfigAsString(config)

	if err != nil {
		panic(err)
	}
	return seelog
}

// we should never really use these . . . always prefer logging through a prefix logger
func Debug(args ...interface{}) {
	root.Debug(args...)
}
func Debugf(format string, args ...interface{}) {
	root.Debugf(format, args...)
}

func Info(args ...interface{}) {
	root.Info(args...)
}
func Infof(format string, args ...interface{}) {
	root.Infof(format, args...)
}
func Warn(args ...interface{}) {
	_ = root.Warn(args...)
}
func Warnf(format string, args ...interface{}) {
	_ = root.Warnf(format, args...)
}
func Error(args ...interface{}) {
	_ = root.Error(args...)
}
func Errorf(format string, args ...interface{}) {
	_ = root.Errorf(format, args...)
}

func Flush() {
	log.Flush()
}
