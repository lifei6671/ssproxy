package ssproxy

import (
	"errors"
	"io"
	"log"
	"strconv"
)

const (
	AuthUsernamePasswordVersion = 0x01
	AuthStatusSucceeded         = 0x00
)

type SocksVersion uint8

const (
	Socks5Version SocksVersion = 0x05
	Socks4Version SocksVersion = 0x04
)

// An AuthMethod represents a SOCKS authentication method.
type AuthMethod uint8

// Wire protocol constants.
const (
	AddrTypeIPv4 = 0x01
	AddrTypeFQDN = 0x03
	AddrTypeIPv6 = 0x04

	CmdConnect Command = 0x01 // establishes an active-open forward proxy connection
	CmdBind    Command = 0x02 // establishes a passive-open forward proxy connection
	CmdUdp             = 0x03

	AuthMethodNotRequired         AuthMethod = 0x00 // no authentication required
	AuthMethodUsernamePassword    AuthMethod = 0x02 // use username/password
	AuthMethodNoAcceptableMethods AuthMethod = 0xff // no acceptable authentication methods

	StatusSucceeded Reply = 0x00
)

// A Command represents a SOCKS command.
type Command int

func (cmd Command) String() string {
	switch cmd {
	case CmdConnect:
		return "socks connect"
	case CmdBind:
		return "socks bind"
	default:
		return "socks " + strconv.Itoa(int(cmd))
	}
}

type PasswordHandle func(user string) (password string, err error)

// A Reply represents a SOCKS command reply code.
type Reply uint8

func (code Reply) String() string {
	switch code {
	case StatusSucceeded:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown code: " + strconv.Itoa(int(code))
	}
}

type UsernamePassword struct {
	Username string
	Password string
}

func (up *UsernamePassword) Authenticate(rw io.ReadWriter, auth AuthMethod) error {
	switch auth {
	case AuthMethodNotRequired:
		return nil
	case AuthMethodUsernamePassword:
		if len(up.Username) == 0 || len(up.Username) > 255 || len(up.Password) == 0 || len(up.Password) > 255 {
			return errors.New("invalid username/password")
		}
		b := []byte{AuthUsernamePasswordVersion}
		b = append(b, byte(len(up.Username)))
		b = append(b, up.Username...)
		b = append(b, byte(len(up.Password)))
		b = append(b, up.Password...)

		log.Println(b)
		if _, err := rw.Write(b); err != nil {
			return err
		}
		log.Println("正在等待远端校验")
		if _, err := io.ReadFull(rw, b[:2]); err != nil {
			return err
		}
		log.Println("校验结果 ", b)
		if b[0] != AuthUsernamePasswordVersion {
			return errors.New("invalid username/password version")
		}
		if b[1] != AuthStatusSucceeded {
			return errors.New("username/password authentication failed")
		}
		return nil
	}
	return errors.New("unsupported authentication method " + strconv.Itoa(int(auth)))
}
