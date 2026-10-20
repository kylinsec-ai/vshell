package c2engine

import (
	"bufio"
	"net"
	"net/http"
	"time"
)
// BufferedIO wraps buffered protocol I/O.
type BufferedIO struct {
	conn   net.Conn
	reader *bufio.Reader
}
// NewBufferedIO creates a buffered I/O wrapper over a connection.
func NewBufferedIO(conn net.Conn) *BufferedIO {
	return &BufferedIO{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
}
// BufferreadRequest reads an HTTP request from the buffered reader.
func (b *BufferedIO) BufferreadRequest() (*http.Request, error) {
	return http.ReadRequest(b.reader)
}
// UnreadByte unreads the last byte read from the buffered reader.
func (b *BufferedIO) UnreadByte() error {
	return b.reader.UnreadByte()
}
// UnreadRune unreads the last rune read from the buffered reader.
func (b *BufferedIO) UnreadRune() error {
	return b.reader.UnreadRune()
}
// Buffered returns the number of bytes buffered in the reader.
func (b *BufferedIO) Buffered() int {
	return b.reader.Buffered()
}
// Read reads from the underlying buffered reader.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).Read.
func (b *BufferedIO) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}
// ReadByte reads a single byte.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).ReadByte.
func (b *BufferedIO) ReadByte() (byte, error) {
	return b.reader.ReadByte()
}
// Peek returns the next n bytes without advancing the reader.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).Peek.
func (b *BufferedIO) Peek(n int) ([]byte, error) {
	return b.reader.Peek(n)
}
// Reader exposes the underlying buffered reader.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).Reader.
func (b *BufferedIO) Reader() *bufio.Reader {
	return b.reader
}
// GetReq reads an HTTP request from the buffered reader (alias).
// Original binary: Xq5KwGZr4i.(*KAJqdSn).GetReq.
func (b *BufferedIO) GetReq() (*http.Request, error) {
	return http.ReadRequest(b.reader)
}
// LocalAddr returns the local address of the underlying connection.
func (b *BufferedIO) LocalAddr() net.Addr {
	return b.conn.LocalAddr()
}
// RemoteAddr returns the remote address of the underlying connection.
func (b *BufferedIO) RemoteAddr() net.Addr {
	return b.conn.RemoteAddr()
}

// SetDeadline sets the deadline of the underlying connection.
func (b *BufferedIO) SetDeadline(t time.Time) error {
	return b.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline of the underlying connection.
func (b *BufferedIO) SetReadDeadline(t time.Time) error {
	return b.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline of the underlying connection.
func (b *BufferedIO) SetWriteDeadline(t time.Time) error {
	return b.conn.SetWriteDeadline(t)
}
