package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

/* The buffer (6M) is used after successful authentication between the connections. */
const ConnectionBuffer = 1024 * 1024 * 6

/* The buffer (256 KB) is used for parsing SOCKS5. */
const Socks5Buffer = 256 * 1024

var bytePool = sync.Pool{
	New: func() interface{} {
		bytes := make([]byte, ConnectionBuffer)
		return bytes
	},
}

type Service struct {
	ListenAddr   *net.TCPAddr
	ServerAdders []*net.TCPAddr
	StableServer *net.TCPAddr
}

type server struct {
	*Service
	targetAddr      *net.TCPAddr
	serverTLSConfig *tls.Config
	clientTLSConfig *tls.Config
	serverPEM       string
	serverKEY       string
	clientPEM       string
	clientKEY       string
}

func (s *Service) TLSWrite(conn net.Conn, buf []byte) error {
	nWrite := 0
	nBuffer := len(buf)

	for nWrite < nBuffer {
		n, err := conn.Write(buf[nWrite:])

		if err != nil {
			return err
		}

		nWrite += n
	}

	return nil
}

func (s *Service) TransferToTCP(cliConn net.Conn, dstConn *net.TCPConn) error {
	buf := make([]byte, ConnectionBuffer)
	for {
		nRead, errRead := cliConn.Read(buf)

		if errRead != nil {
			return errRead
		}

		if nRead > 0 {
			_, errWrite := dstConn.Write(buf[0:nRead])

			if errWrite != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) TransferForwardTLS(dstConn net.Conn, srcConn net.Conn) error {
	buf := bytePool.Get().([]byte)

	for {
		nRead, errRead := srcConn.Read(buf)

		if errRead != nil {
			bytePool.Put(buf)

			return errRead
		}

		if nRead > 0 {
			errWrite := s.TLSWrite(dstConn, buf[0:nRead])

			if errWrite != nil {
				bytePool.Put(buf)

				return errWrite
			}
		}
	}
}

func (s *Service) TransferToTLS(dstConn *net.TCPConn, srcConn net.Conn) error {
	buf := bytePool.Get().([]byte)

	for {
		nRead, errRead := dstConn.Read(buf)

		if errRead != nil {
			bytePool.Put(buf)

			return errRead
		}

		if nRead > 0 {
			errWrite := s.TLSWrite(srcConn, buf[0:nRead])

			if errWrite != nil {
				bytePool.Put(buf)

				return errWrite
			}
		}
	}
}

func (s *Service) ParseSOCKS5FromTLS(cliConn net.Conn) (*net.TCPAddr, error) {
	buf := make([]byte, Socks5Buffer)

	nRead, errRead := cliConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, errors.New("the service failed to read SOCKS5 during the initial handshake phase")
	}

	if nRead > 0 {
		if buf[0] != 0x05 {
			/* The version of the protocol. */
			return &net.TCPAddr{}, errors.New("currently only supporting SOCKS5 protocol")
		} else {
			/* [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00})
			if errWrite != nil {
				return &net.TCPAddr{}, errors.New("the service failed to respond to the client during the SOCKS5 initial handshake phase")
			}
		}
	}

	nRead, errRead = cliConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, errors.New("the service failed to read SOCKS5 during the second handshake phase")
	}

	if nRead > 0 {
		if buf[1] != 0x01 {
			return &net.TCPAddr{}, errors.New("currently only supporting the CONNECT command in SOCKS5")
		}

		var dstIP []byte
		switch buf[3] { /* Checking the address field. */
		case 0x01: /* The version-4 IP address. */
			dstIP = buf[4 : 4+net.IPv4len]

		case 0x03: /* The fully-qualified domain name. */
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:nRead-2]))
			if err != nil {
				return &net.TCPAddr{}, errors.New("the service failed to parse the domain name")
			}
			dstIP = ipAddr.IP
		case 0x04: /* The version-6 IP address. */
			dstIP = buf[4 : 4+net.IPv6len]
		default:
			return &net.TCPAddr{}, errors.New("the received address field is incorrect")
		}

		dstPort := buf[nRead-2 : nRead]

		if buf[1] == 0x01 {
			/* The TCP over SOCKS5. */
			dstAddr := &net.TCPAddr{
				IP:   dstIP,
				Port: int(binary.BigEndian.Uint16(dstPort)),
			}

			return dstAddr, errRead
		}
	}

	return &net.TCPAddr{}, errors.New("the service failed to parse the SOCKS5 protocol")
}

func (s *Service) DialSrv(targetAddr *net.TCPAddr, conf *tls.Config) (net.Conn, error) {
	srvConn, err := tls.Dial("tcp", targetAddr.String(), conf)
	if err != nil {
		log.Printf("The service failed to connect to the server %s failed: %s.", s.StableServer.String(), err)

		/* Attempting to connect to another server. */
		for _, srv := range s.ServerAdders {
			log.Printf("Try to connect to another server: %s.", srv.String())

			srvConn, err := tls.Dial("tcp", srv.String(), conf)
			if err == nil {
				s.StableServer = srv

				return srvConn, nil
			}
		}

		return nil, errors.New(fmt.Sprintf("all attempts to connect to servers have failed"))
	}

	log.Printf("Connection to target server %s successful.", targetAddr.String())

	return srvConn, nil
}

func NewServer(listenAddr string, targetAddr string, serverPEM string, serverKEY string, clientPEM string, clientKEY string) *server {
	listenTCPAddr, _ := net.ResolveTCPAddr("tcp", listenAddr)
	targetTCPAddr, _ := net.ResolveTCPAddr("tcp", targetAddr)

	return &server{
		&Service{
			ListenAddr: listenTCPAddr,
		},
		targetTCPAddr,
		nil,
		nil,
		serverPEM,
		serverKEY,
		clientPEM,
		clientKEY,
	}
}

var targetPool = make(chan net.Conn, 32)

func init() {
	go func() {
		for range time.Tick(5 * time.Second) {
			/* Discard the idle connection. */
			p := <-targetPool
			_ = p.Close()
		}
	}()
}

func (s *server) newTargetConn(targetAddr *net.TCPAddr) (net.Conn, error) {
	if len(targetPool) < 32 {
		go func() {
			for i := len(targetPool); i < 32; i++ {
				target, err := s.DialSrv(targetAddr, s.clientTLSConfig)

				if err != nil {
					log.Println("The forward-server failed to connect to the target server.")
					return
				}

				targetPool <- target
			}
		}()
	}

	select {
	case pc := <-targetPool:
		return pc, nil
	default:
		return s.DialSrv(targetAddr, s.clientTLSConfig)
	}
}

func (s *server) ListenTLS() error {
	log.Printf("The ss5-forward's listening address is %s.", s.ListenAddr.String())

	/* Try to read and parse public/private key pairs from the file. */
	serverCert, err := tls.LoadX509KeyPair(s.serverPEM, s.serverKEY)
	if err != nil {
		log.Println("The ss5-forward failed to read and parse public/private key pairs of the server end from the file.")

		return err
	}

	serverCertBytes, err := os.ReadFile(s.clientPEM)
	if err != nil {
		log.Println("The ss5-forward failed to read the client's PEM file.")

		return err
	}

	serverCertPool := x509.NewCertPool()
	/* Try to attempt to parse the PEM encoded certificates. */
	ok := serverCertPool.AppendCertsFromPEM(serverCertBytes)
	if !ok {
		return errors.New("the ss5-forward failed to parse the PEM-encoded certificates of the server end")
	}

	s.serverTLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS10,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    serverCertPool,
	}

	/* Try to read and parse the public/private key pairs from the file. */
	clientCert, err := tls.LoadX509KeyPair(s.clientPEM, s.clientKEY)
	if err != nil {
		log.Println("The ss5-forward failed to read and parse public/private key pairs of the client end from the file.")

		return nil
	}

	clientCertBytes, err := os.ReadFile(s.clientPEM)
	if err != nil {
		log.Println("The ss5-forward failed to read the client's PEM file.")

		return nil
	}

	clientCertPool := x509.NewCertPool()

	/* Try to attempt to parse the PEM encoded certificates. */
	ok = clientCertPool.AppendCertsFromPEM(clientCertBytes)
	if !ok {
		log.Println("The ss5-forward failed to parse the PEM-encoded certificates of the client end.")

		return nil
	}

	s.clientTLSConfig = &tls.Config{
		RootCAs:            clientCertPool,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
	}

	listener, err := tls.Listen("tcp", s.ListenAddr.String(), s.serverTLSConfig)
	if err != nil {
		log.Printf("Failed to start the ss5-forward listening on %s.", s.ListenAddr.String())

		return err
	} else {
		log.Printf("The ss5-forward successfully started listening on %s.", s.ListenAddr.String())
	}
	defer listener.Close()

	for {
		cliConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleTLSConn(cliConn)
	}
}

func (s *server) handleTLSConn(cliConn net.Conn) {
	/* Parsing the SOCKS5 over TLS connection. */
	targetConn, err := s.newTargetConn(s.targetAddr)
	if err != nil {
		_ = targetConn.Close()

		log.Println("The forward-server failed to connect to the target server.")

		return
	}

	go func() {
		/* The ss5-forward and target server communicate using the TLS connection. */
		errTransfer := s.TransferForwardTLS(cliConn, targetConn)

		if errTransfer != nil {
			_ = cliConn.Close()
			_ = targetConn.Close()
		}
	}()

	/* The ss5-forward and client communicate using the TLS connection. */
	_ = s.TransferForwardTLS(targetConn, cliConn)
}

func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".ss5-forward.json", "The server configuration file.")
	flag.Parse()

	bytes, err := os.ReadFile(conf)
	if err != nil {
		log.Fatalf("The ss5-forward failed to read the configuration file.")
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("The ss5-forward failed to parse the configuration file: %s .", conf)
	}

	serverPEM := config["server_pem"].(string)
	serverKEY := config["server_key"].(string)
	clientPEM := config["client_pem"].(string)
	clientKEY := config["client_key"].(string)

	s := NewServer(config["listen_addr"].(string), config["target_addr"].(string), serverPEM, serverKEY, clientPEM, clientKEY)

	s.ListenTLS()
}
