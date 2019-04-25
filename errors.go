package ssproxy

import (
	"errors"
)

var (
	ErrAddrType               = errors.New("socks addr type not supported")
	ErrVer                    = errors.New("socks version not supported")
	ErrMethod                 = errors.New("socks only support 1 method now")
	ErrAuthExtraData          = errors.New("socks authentication get extra data")
	ErrReqExtraData           = errors.New("socks request get extra data")
	ErrCmd                    = errors.New("socks command not supported")
	ErrNoSupportedAuth        = errors.New("socks no supported authentication mechanism")
	ErrNoSupportedAccountAuth = errors.New("socks no supported account authentication")
	ErrClientNoResponse       = errors.New("socks client no response")
	ErrDomainForbidConnect    = errors.New("forbid domain connect")
	ErrUserAuthFailed         = errors.New("socks user authentication failed")
	ErrUnrecognizedAddrType   = errors.New("socks unrecognized address type")
	ErrEmptyPassword          = errors.New("socks authentication password is empty")
	ErrProxyClosed            = errors.New("proxy server closed")
	ErrNoSupportedProxyType   = errors.New("no supported proxy type")
)
