package ssproxy

import (
	logs "log"
	"os"
)

// Logger exported
var GeneralLogger *logs.Logger

// ErrorLogger exported
var ErrorLogger *logs.Logger

func init() {
	GeneralLogger = logs.New(os.Stderr, "General Logger: ", logs.Ldate|logs.Ltime|logs.Lshortfile)
	ErrorLogger = logs.New(os.Stderr, "Error Logger: ", logs.Ldate|logs.Ltime|logs.Lshortfile)
}
