package files

import "crypto/rand"

func ioReadFull(b []byte) (int, error) { return rand.Read(b) }
