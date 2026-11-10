package identity

import (
	"bytes"
	cryptoRand "crypto/rand"
	"errors"
	"io"
	"net/http"
)

func readAndRestoreBody(r *http.Request, max int64) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("request body exceeds limit")
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

func randRead(b []byte) (int, error) { return cryptoRand.Read(b) }
