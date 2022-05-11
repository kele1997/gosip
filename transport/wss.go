package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/ghettovoice/gosip/log"
	"github.com/ghettovoice/gosip/sip"
)

type wssProtocol struct {
	wsProtocol
}

func NewWssProtocol(
	output chan<- sip.Message,
	errs chan<- error,
	cancel <-chan struct{},
	msgMapper sip.MessageMapper,
	logger log.Logger,
) Protocol {
	p := new(wssProtocol)
	p.network = "wss"
	p.reliable = true
	p.streamed = true
	p.conns = make(chan Connection)
	p.log = logger.
		WithPrefix("transport.Protocol").
		WithFields(log.Fields{
			"protocol_ptr": fmt.Sprintf("%p", p),
		})
	//TODO: add separate errs chan to listen errors from pool for reconnection?
	p.listeners = NewListenerPool(p.conns, errs, cancel, p.Log())
	p.connections = NewConnectionPool(output, errs, cancel, msgMapper, p.Log())
	p.listen = func(addr *net.TCPAddr, options ...ListenOption) (net.Listener, error) {
		if len(options) == 0 {
			return net.ListenTCP("tcp", addr)
		}
		optsHash := ListenOptions{}
		for _, opt := range options {
			opt.ApplyListen(&optsHash)
		}
		cert, err := tls.LoadX509KeyPair(optsHash.TLSConfig.Cert, optsHash.TLSConfig.Key)
		if err != nil {
			return nil, fmt.Errorf("load TLS certficate %s: %w", optsHash.TLSConfig.Cert, err)
		}
		return tls.Listen("tcp", addr.String(), &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	}
	p.resolveAddr = p.defaultResolveAddr
	p.dialer.Protocols = []string{wsSubProtocol}
	p.dialer.Timeout = time.Minute
	p.dialer.TLSConfig = &tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},
	}
	//pipe listener and connection pools
	go p.pipePools()

	return p
}

func (p *wssProtocol) Send(target *Target, msg sip.Message) error {
	target = FillTargetHostAndPort(p.Network(), target)

	//validate remote address
	if target.Host == "" {
		return &ProtocolError{
			fmt.Errorf("empty remote target host"),
			fmt.Sprintf("send SIP message to %s %s", p.Network(), target.Addr()),
			fmt.Sprintf("%p", p),
		}
	}

	//find or create connection
	conn, err := p.getOrCreateConnection(target)
	if err != nil {
		return &ProtocolError{
			Err:      err,
			Op:       fmt.Sprintf("get or create %s connection", p.Network()),
			ProtoPtr: fmt.Sprintf("%p", p),
		}
	}

	logger := log.AddFieldsFrom(p.Log(), conn, msg)
	logger.Tracef("writing SIP message to %s %s", p.Network(), target)

	//send message
	_, err = conn.Write([]byte(msg.String()))
	if err != nil {
		err = &ProtocolError{
			Err:      err,
			Op:       fmt.Sprintf("write SIP message to the %s connection", conn.Key()),
			ProtoPtr: fmt.Sprintf("%p", p),
		}
	}

	return err
}

func (p *wssProtocol) getOrCreateConnection(target *Target) (Connection, error) {
	key := ConnectionKey(p.network + ":" + target.Addr())
	conn, err := p.connections.Get(key)
	if err != nil {
		p.Log().Debugf("connection for address %s %s not found; create a new one", p.Network(), target.Addr())

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		url := fmt.Sprintf("%s://%s", p.network, target.Addr())
		baseConn, _, _, err := p.dialer.Dial(ctx, url)
		if err == nil {
			baseConn = &wsConn{
				Conn:   baseConn,
				client: true,
			}
		} else {
			if baseConn == nil {
				return nil, fmt.Errorf("dial to %s %s: %w", p.Network(), target.Addr(), err)
			}

			p.Log().Warnf("fallback to TCP connection due to WS upgrade error: %s", err)
		}

		conn = NewConnection(baseConn, key, p.network, p.Log())

		if err := p.connections.Put(conn, sockTTL); err != nil {
			return conn, fmt.Errorf("put %s connection to the pool: %w", conn.Key(), err)
		}
	}

	return conn, nil
}
