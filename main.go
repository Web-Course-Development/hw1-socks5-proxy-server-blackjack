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

// no auth = 0x00, user/pass = 0x02, nothing works = 0xFF
const (
	noAuth    byte = 0x00
	userPass  byte = 0x02
	noMethods byte = 0xFF
)

// socks5 version is always 5, and we only support CONNECT command
const (
	version    = byte(0x05)
	cmdConnect = byte(0x01)
)

// address types the client can send us
const (
	ipv4Addr   = byte(0x01)
	domainAddr = byte(0x03)
)

// reply codes we send back to the client
const (
	replyOK          = byte(0x00)
	replyFail        = byte(0x01)
	replyNetUnreach  = byte(0x03)
	replyHostUnreach = byte(0x04)
	replyConnRefused = byte(0x05)
	replyCmdUnknown  = byte(0x07)
	replyAddrUnknown = byte(0x08)
)

func main() {
	port := flag.Int("port", 1080, "which port to run on")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("could not start listener: %v", err)
	}
	defer ln.Close()

	log.Printf("proxy is up on %s (needs auth: %v)", addr, getUser() != "")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept failed: %v", err)
			continue
		}
		go handleClient(conn)
	}
}

// read credentials from environment each time so tests can change them
func getUser() string { return os.Getenv("PROXY_USER") }
func getPass() string { return os.Getenv("PROXY_PASS") }

// handleClient runs the full socks5 flow for one connection
func handleClient(conn net.Conn) {
	defer conn.Close()

	// step 1 - figure out which auth method to use
	method, err := doMethodSelect(conn)
	if err != nil {
		log.Printf("[%s] method select failed: %v", conn.RemoteAddr(), err)
		return
	}

	// step 2 - if we picked user/pass, verify the credentials
	if method == userPass {
		if err := checkCredentials(conn); err != nil {
			log.Printf("[%s] auth failed: %v", conn.RemoteAddr(), err)
			return
		}
	}

	// step 3 - handle the actual CONNECT and start relaying
	if err := doConnect(conn); err != nil {
		log.Printf("[%s] connect failed: %v", conn.RemoteAddr(), err)
	}
}

// doMethodSelect reads what methods the client supports and picks one
func doMethodSelect(conn net.Conn) (byte, error) {
	// first two bytes are version + number of methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, fmt.Errorf("could not read greeting: %w", err)
	}

	if buf[0] != version {
		return 0, fmt.Errorf("wrong socks version: 0x%02x", buf[0])
	}

	// read all the methods the client is offering
	numMethods := int(buf[1])
	offered := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, offered); err != nil {
		return 0, fmt.Errorf("could not read method list: %w", err)
	}

	needsAuth := getUser() != ""
	picked := noMethods

	if needsAuth {
		// look for user/pass method
		for _, m := range offered {
			if m == userPass {
				picked = userPass
				break
			}
		}
	} else {
		// look for no-auth method
		for _, m := range offered {
			if m == noAuth {
				picked = noAuth
				break
			}
		}
	}

	// tell client which method we chose (even if it's 0xFF = none)
	if _, err := conn.Write([]byte{version, picked}); err != nil {
		return 0, fmt.Errorf("could not send method choice: %w", err)
	}

	if picked == noMethods {
		return 0, fmt.Errorf("client did not offer any method we support")
	}

	return picked, nil
}

// checkCredentials does the RFC 1929 username/password check
// note: this sub-protocol uses version 0x01 not 0x05
func checkCredentials(conn net.Conn) error {
	// read version byte (must be 0x01) and username length
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("could not read auth header: %w", err)
	}

	if buf[0] != 0x01 {
		return fmt.Errorf("bad auth version 0x%02x, expected 0x01", buf[0])
	}

	// read the username
	username := make([]byte, int(buf[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("could not read username: %w", err)
	}

	// read password length then password
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return fmt.Errorf("could not read password length: %w", err)
	}
	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("could not read password: %w", err)
	}

	// check if credentials match
	if string(username) == getUser() && string(password) == getPass() {
		_, err := conn.Write([]byte{0x01, 0x00}) // 0x00 = success
		return err
	}

	// wrong credentials - send failure then bail
	conn.Write([]byte{0x01, 0x01}) //nolint:errcheck
	return fmt.Errorf("wrong credentials for user %q", string(username))
}

// doConnect reads the CONNECT request, dials the target, and starts the relay
func doConnect(conn net.Conn) error {
	// read the 4 byte request header: VER CMD RSV ATYP
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("could not read request header: %w", err)
	}

	if hdr[0] != version {
		return fmt.Errorf("wrong version in request: 0x%02x", hdr[0])
	}

	// we only support CONNECT, reject anything else
	if hdr[1] != cmdConnect {
		writeReply(conn, replyCmdUnknown)
		return fmt.Errorf("command 0x%02x is not supported", hdr[1])
	}

	// hdr[2] is reserved, ignore it
	// hdr[3] is the address type
	host, err := parseAddress(conn, hdr[3])
	if err != nil {
		if err == errBadAddrType {
			writeReply(conn, replyAddrUnknown)
		} else {
			writeReply(conn, replyFail)
		}
		return err
	}

	// read the 2 byte port (big endian)
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		writeReply(conn, replyFail)
		return fmt.Errorf("could not read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)
	destination := fmt.Sprintf("%s:%d", host, port)

	// try to connect to the target server
	remote, err := net.Dial("tcp", destination)
	if err != nil {
		writeReply(conn, mapDialError(err))
		return fmt.Errorf("could not reach %s: %w", destination, err)
	}
	defer remote.Close()

	// tell client we connected successfully
	writeReply(conn, replyOK)

	// now just pipe data back and forth until done
	pipeData(conn, remote)
	return nil
}

// errBadAddrType is returned when the client sends an address type we don't know
var errBadAddrType = errors.New("address type not supported")

// parseAddress reads the destination address from the connection
func parseAddress(conn net.Conn, addrType byte) (string, error) {
	switch addrType {

	case ipv4Addr:
		// IPv4 is just 4 raw bytes
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", fmt.Errorf("could not read ipv4 address: %w", err)
		}
		return net.IP(ip).String(), nil

	case domainAddr:
		// domain name: first byte is the length, then that many bytes
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("could not read domain length: %w", err)
		}
		name := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", fmt.Errorf("could not read domain name: %w", err)
		}
		return string(name), nil

	default:
		return "", errBadAddrType
	}
}

// writeReply sends a socks5 reply back to the client
// we always use 0.0.0.0:0 as the bound address since we don't need it
func writeReply(conn net.Conn, code byte) {
	conn.Write([]byte{ //nolint:errcheck
		version, code, 0x00, // VER REP RSV
		ipv4Addr,               // ATYP
		0x00, 0x00, 0x00, 0x00, // BND.ADDR (all zeros)
		0x00, 0x00, // BND.PORT (zero)
	})
}

// pipeData copies data between client and remote in both directions at the same time
func pipeData(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client sends data to remote
	go func() {
		defer wg.Done()
		io.Copy(remote, client) //nolint:errcheck
		halfClose(remote)
	}()

	// remote sends data back to client
	go func() {
		defer wg.Done()
		io.Copy(client, remote) //nolint:errcheck
		halfClose(client)
	}()

	wg.Wait()
}

// halfClose signals EOF in one direction without closing the whole connection
func halfClose(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck
	}
}

// mapDialError converts a connection error into the right socks5 reply code
func mapDialError(err error) byte {
	if err == nil {
		return replyOK
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			errno, ok := sysErr.Err.(syscall.Errno)
			if ok {
				switch errno {
				case syscall.ECONNREFUSED:
					return replyConnRefused
				case syscall.ENETUNREACH:
					return replyNetUnreach
				case syscall.EHOSTUNREACH, syscall.ETIMEDOUT:
					return replyHostUnreach
				}
			}
		}
		// DNS failures and other dial errors -> host unreachable
		if opErr.Op == "dial" || opErr.Op == "lookup" {
			return replyHostUnreach
		}
	}

	return replyFail
}
