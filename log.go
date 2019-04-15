package ssproxy

import (
	"log"
	"os"
)

// Logger exported
var GeneralLogger *log.Logger

// ErrorLogger exported
var ErrorLogger *log.Logger

func init() {
	GeneralLogger = log.New(os.Stderr, "General Logger: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(os.Stderr, "Error Logger: ", log.Ldate|log.Ltime|log.Lshortfile)
}
