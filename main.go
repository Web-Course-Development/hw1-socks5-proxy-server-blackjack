package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Auth methods (RFC 1928 §3)
const (
	methodNoAuth       byte = 0x00
	methodUserPass     byte = 0x02
	methodNoAcceptable byte = 0xFF
)

// SOCKS5 protocol constants
const (
	socks5Ver  = byte(0x05)
	cmdConnect = byte(0x01)
)

// Address types
const (
	atypIPv4   = byte(0x01)
	atypDomain = byte(0x03)
)

// Reply codes (RFC 1928 §6)
const (
	repSuccess          = byte(0x00)
	repFailure          = byte(0x01)
	repNetUnreachable   = byte(0x03)
	repHostUnreachable  = byte(0x04)
	repRefused          = byte(0x05)
	repCmdNotSupported  = byte(0x07)
	repAddrNotSupported = byte(0x08)
)

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	defer listener.Close()
	log.Printf("SOCKS5 proxy listening on %s (auth=%v)", addr, proxyUser() != "")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

// ---------------------------------------------------------------------------
// Credential helpers  (read once per call so tests can set env at any time)
// ---------------------------------------------------------------------------

func proxyUser() string { return os.Getenv("PROXY_USER") }
func proxyPass() string { return os.Getenv("PROXY_PASS") }

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("[%s] negotiateAuth: %v", conn.RemoteAddr(), err)
		return
	}

	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("[%s] authenticateUserPass: %v", conn.RemoteAddr(), err)
			return
		}
	}

	if err := handleConnect(conn); err != nil {
		log.Printf("[%s] handleConnect: %v", conn.RemoteAddr(), err)
	}
}

// ---------------------------------------------------------------------------
// Step 1 — Method negotiation (RFC 1928 §3)
// ---------------------------------------------------------------------------

// negotiateAuth reads the client greeting and writes the chosen method.
// Returns the selected method byte, or an error if negotiation failed.
func negotiateAuth(conn net.Conn) (byte, error) {
	// VER | NMETHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, fmt.Errorf("read greeting header: %w", err)
	}
	if hdr[0] != socks5Ver {
		return 0, fmt.Errorf("unsupported SOCKS version 0x%02x", hdr[0])
	}

	nmethods := int(hdr[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, fmt.Errorf("read methods: %w", err)
	}

	authRequired := proxyUser() != ""
	chosen := methodNoAcceptable

	if authRequired {
		for _, m := range methods {
			if m == methodUserPass {
				chosen = methodUserPass
				break
			}
		}
	} else {
		for _, m := range methods {
			if m == methodNoAuth {
				chosen = methodNoAuth
				break
			}
		}
	}

	// Always send the method selection, even 0xFF
	if _, err := conn.Write([]byte{socks5Ver, chosen}); err != nil {
		return 0, fmt.Errorf("write method selection: %w", err)
	}
	if chosen == methodNoAcceptable {
		return 0, fmt.Errorf("no acceptable auth method offered by client")
	}
	return chosen, nil
}

// ---------------------------------------------------------------------------
// Step 2 — Username/password sub-negotiation (RFC 1929)
// ---------------------------------------------------------------------------

// authenticateUserPass handles the RFC 1929 sub-protocol.
// NOTE: the version byte here is 0x01, NOT 0x05.
func authenticateUserPass(conn net.Conn) error {
	// VER(0x01) | ULEN
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read userpass header: %w", err)
	}
	if hdr[0] != 0x01 {
		return fmt.Errorf("unexpected userpass VER 0x%02x (want 0x01)", hdr[0])
	}

	uname := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	// PLEN | PASSWD
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return fmt.Errorf("read plen: %w", err)
	}
	passwd := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	if string(uname) == proxyUser() && string(passwd) == proxyPass() {
		_, err := conn.Write([]byte{0x01, 0x00}) // success
		return err
	}

	// Send failure status (non-zero) before returning
	conn.Write([]byte{0x01, 0x01}) //nolint:errcheck
	return fmt.Errorf("invalid credentials for user %q", string(uname))
}

// ---------------------------------------------------------------------------
// Step 3 — CONNECT request + relay (RFC 1928 §4, §5, §6)
// ---------------------------------------------------------------------------

// handleConnect reads the CONNECT request, dials the target, sends the reply,
// and relays data bidirectionally.
func handleConnect(conn net.Conn) error {
	// VER | CMD | RSV | ATYP
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != socks5Ver {
		return fmt.Errorf("unexpected request VER 0x%02x", hdr[0])
	}
	if hdr[1] != cmdConnect {
		sendReply(conn, repCmdNotSupported)
		return fmt.Errorf("unsupported CMD 0x%02x", hdr[1])
	}
	// hdr[2] is RSV — ignore per spec

	targetHost, err := readAddress(conn, hdr[3])
	if err != nil {
		if err == errAddrType {
			sendReply(conn, repAddrNotSupported)
		} else {
			sendReply(conn, repFailure)
		}
		return err
	}

	// DST.PORT — big-endian uint16
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		sendReply(conn, repFailure)
		return fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)
	targetAddr := fmt.Sprintf("%s:%d", targetHost, port)

	// Dial the target
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendReply(conn, dialErrToRep(err))
		return fmt.Errorf("dial %s: %w", targetAddr, err)
	}
	defer target.Close()

	// Successful connection — send success reply
	sendReply(conn, repSuccess)

	// Bidirectional relay
	relay(conn, target)
	return nil
}

// errAddrType is a sentinel for unsupported ATYP.
var errAddrType = errors.New("unsupported address type")

// readAddress reads DST.ADDR based on the given ATYP byte.
func readAddress(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		return net.IP(buf).String(), nil

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		return string(domain), nil

	default:
		return "", errAddrType
	}
}

// ---------------------------------------------------------------------------
// Reply helper
// ---------------------------------------------------------------------------

// sendReply writes a SOCKS5 reply with the given REP code.
// BND.ADDR = 0.0.0.0, BND.PORT = 0 (valid per RFC 1928 §6).
func sendReply(conn net.Conn, rep byte) {
	conn.Write([]byte{ //nolint:errcheck
		socks5Ver, rep, 0x00, // VER REP RSV
		atypIPv4,               // ATYP = IPv4
		0x00, 0x00, 0x00, 0x00, // BND.ADDR
		0x00, 0x00, // BND.PORT
	})
}

// ---------------------------------------------------------------------------
// Bidirectional relay
// ---------------------------------------------------------------------------

// relay copies data between client and target concurrently in both directions.
// Uses sync.WaitGroup and CloseWrite so both sides receive proper EOF.
func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client → target
	go func() {
		defer wg.Done()
		io.Copy(target, client) //nolint:errcheck
		closeWrite(target)
	}()

	// target → client
	go func() {
		defer wg.Done()
		io.Copy(client, target) //nolint:errcheck
		closeWrite(client)
	}()

	wg.Wait()
}

// closeWrite calls CloseWrite on TCP connections to signal EOF to the peer.
func closeWrite(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck
	}
}

// ---------------------------------------------------------------------------
// Error → REP code mapping
// ---------------------------------------------------------------------------

// dialErrToRep converts a net.Dial error into the appropriate SOCKS5 REP byte.
func dialErrToRep(err error) byte {
	if err == nil {
		return repSuccess
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var syscallErr *os.SyscallError
		if errors.As(opErr.Err, &syscallErr) {
			errno, ok := syscallErr.Err.(syscall.Errno)
			if ok {
				switch errno {
				case syscall.ECONNREFUSED:
					return repRefused
				case syscall.ENETUNREACH:
					return repNetUnreachable
				case syscall.EHOSTUNREACH, syscall.ETIMEDOUT:
					return repHostUnreachable
				}
			}
		}
		// DNS / lookup failures → host unreachable
		if opErr.Op == "dial" || opErr.Op == "lookup" {
			return repHostUnreachable
		}
	}
	return repFailure
}
