package ssproxy

type Logger interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
	Println(v ...interface{})
	Fatal(v ...interface{})
	Fatalf(format string, v ...interface{})
	Fatalln(v ...interface{})
	Panic(v ...interface{})
	Panicln(v ...interface{})
	Panicf(format string, v ...interface{})
}

type emptyLog struct {
}

func (l *emptyLog) Print(v ...interface{})                 {}
func (l *emptyLog) Printf(format string, v ...interface{}) {}
func (l *emptyLog) Println(v ...interface{})               {}
func (l *emptyLog) Fatal(v ...interface{})                 {}
func (l *emptyLog) Fatalf(format string, v ...interface{}) {}
func (l *emptyLog) Fatalln(v ...interface{})               {}
func (l *emptyLog) Panic(v ...interface{})                 {}
func (l *emptyLog) Panicln(v ...interface{})               {}
func (l *emptyLog) Panicf(format string, v ...interface{}) {}
