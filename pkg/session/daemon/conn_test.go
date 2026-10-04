package daemon_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	sessionv1alpha1 "github.com/confidential-dot-ai/c8s/api/session/v1alpha1"
	"github.com/confidential-dot-ai/c8s/pkg/session/daemon"
)

// carrier is a daemon that carries a stream to whatever a test puts at its
// other end.
type carrier struct {
	sessionv1alpha1.UnimplementedSessionsServer
	connect func(td string, stream sessionv1alpha1.Sessions_ConnectServer) error
}

func (c *carrier) Connect(stream sessionv1alpha1.Sessions_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	return c.connect(first.GetTd(), stream)
}

// serve runs a daemon whose Connect is connect, and returns a client of it.
func serve(t *testing.T, connect func(td string, stream sessionv1alpha1.Sessions_ConnectServer) error) *daemon.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "daemon"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})))
	sessionv1alpha1.RegisterSessionsServer(srv, &carrier{connect: connect})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	client, err := daemon.Dial(daemon.Options{Address: ln.Addr().String(), RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// echo sends back every frame, and ends the stream in order when the caller
// has sent all it will.
func echo(_ string, stream sessionv1alpha1.Sessions_ConnectServer) error {
	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&sessionv1alpha1.Bytes{Data: frame.GetData()}); err != nil {
			return err
		}
	}
}

func dial(t *testing.T, client *daemon.Client, td string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.Dialer(td)(ctx, "tcp", "ignored:1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// A megabyte crosses in both directions in order, in frames of the adapter's
// own cutting, with a writer far ahead of its reader.
func TestConnCarriesBytesInOrder(t *testing.T) {
	named := make(chan string, 1)
	client := serve(t, func(td string, stream sessionv1alpha1.Sessions_ConnectServer) error {
		named <- td
		return echo(td, stream)
	})
	conn := dial(t, client, "td-1")
	sent := make([]byte, 1<<20)
	if _, err := rand.Read(sent); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		if n, err := conn.Write(sent); err != nil || n != len(sent) {
			t.Errorf("write: %d, %v", n, err)
		}
		if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Errorf("close the sending side: %v", err)
		}
	})
	got, err := io.ReadAll(conn)
	wg.Wait()
	if err != nil || !bytes.Equal(got, sent) {
		t.Fatalf("read back %d of %d bytes: %v", len(got), len(sent), err)
	}
	if td := <-named; td != "td-1" {
		t.Fatalf("the daemon was told TD %q", td)
	}
}

// The end of a stream is io.EOF only when the daemon ended it in order, which
// it does when the guest closed the connection. Any other end is an error, so
// that a cut is never taken for the guest's word.
func TestConnTellsAnEndFromACut(t *testing.T) {
	client := serve(t, func(td string, stream sessionv1alpha1.Sessions_ConnectServer) error {
		if err := stream.Send(&sessionv1alpha1.Bytes{Data: []byte("last words")}); err != nil {
			return err
		}
		if td == "cut" {
			return status.Error(codes.Aborted, "the TD ended")
		}
		return nil
	})
	ended := dial(t, client, "ends")
	if got, err := io.ReadAll(ended); err != nil || string(got) != "last words" {
		t.Fatalf("a stream the guest ended: %q, %v", got, err)
	}
	cut := dial(t, client, "cut")
	got, err := io.ReadAll(cut)
	if status.Code(err) != codes.Aborted || string(got) != "last words" {
		t.Fatalf("a stream that was cut: %q, %v", got, err)
	}
}

// Closing sends what was written and then the end of this side, in that
// order: a TLS session's close_notify reaches the guest as its last bytes.
func TestConnCloseIsInOrder(t *testing.T) {
	type end struct {
		got []byte
		err error
	}
	seen := make(chan end, 1)
	client := serve(t, func(_ string, stream sessionv1alpha1.Sessions_ConnectServer) error {
		var got []byte
		for {
			frame, err := stream.Recv()
			if err != nil {
				seen <- end{got, err}
				return nil
			}
			got = append(got, frame.GetData()...)
		}
	})
	conn := dial(t, client, "td-1")
	if _, err := conn.Write([]byte("goodbye")); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-seen:
		if string(e.got) != "goodbye" || !errors.Is(e.err, io.EOF) {
			t.Fatalf("the daemon saw %q, then %v", e.got, e.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon never saw the end")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a closed connection was read from")
	}
	if _, err := conn.Write([]byte("more")); err == nil {
		t.Fatal("a closed connection was written to")
	}
}

// A read gives up at its deadline and works again once the deadline is
// lifted, as net.Conn promises and as the session client relies on.
func TestConnReadDeadline(t *testing.T) {
	release := make(chan struct{})
	client := serve(t, func(_ string, stream sessionv1alpha1.Sessions_ConnectServer) error {
		<-release
		if err := stream.Send(&sessionv1alpha1.Bytes{Data: []byte("late")}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	})
	conn := dial(t, client, "td-1")
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	began := time.Now()
	_, err := conn.Read(make([]byte, 8))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a read past its deadline: %v", err)
	}
	if waited := time.Since(began); waited < 40*time.Millisecond || waited > 5*time.Second {
		t.Fatalf("the read gave up after %s", waited)
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("the deadline's error is no timeout: %v", err)
	}
	// A deadline in the past fails at once, and lifting it lets the read wait.
	_ = conn.SetDeadline(time.Now().Add(-time.Second))
	if _, err := conn.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a read under a past deadline: %v", err)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write under a past deadline: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	close(release)
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "late" {
		t.Fatalf("a read after the deadline was lifted: %q, %v", buf[:n], err)
	}
}

// A write that waits on a daemon that takes nothing gives up at its
// deadline, and the connection is over.
func TestConnWriteDeadline(t *testing.T) {
	client := serve(t, func(_ string, stream sessionv1alpha1.Sessions_ConnectServer) error {
		// Takes nothing: the caller's frames queue up until its window is full.
		<-stream.Context().Done()
		return nil
	})
	conn := dial(t, client, "td-1")
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	began := time.Now()
	_, err := conn.Write(make([]byte, 64<<20))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write nobody takes: %v", err)
	}
	if waited := time.Since(began); waited > 10*time.Second {
		t.Fatalf("the write gave up after %s", waited)
	}
}

// A dial ends with its context.
func TestDialEndsWithItsContext(t *testing.T) {
	client := serve(t, echo)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := client.Dialer("td-1")(ctx, "tcp", "ignored:1"); err == nil {
		conn.Close()
		t.Fatal("a dial under an ended context returned a connection")
	}
}
