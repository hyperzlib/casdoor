package cred

import (
	"fmt"
	"testing"
)

func TestGetBookstackSaltedPassword(t *testing.T) {
	password := ""
	salt := "mLE_GuV3ncHylZuSJSPuQ5iC2kSqoOLk_SnHqcP-f6jrhrbS-3C7Ey5a9yXRiuampMjC$15$2df8945dbe411c4f7d29bf652ba7cc44746c52cc0de5f2db0985687cce6c01e8"
	cm := NewBookstackSaltCredManager()
	fmt.Printf("%s -> %s\n", password, cm.GetSealedPassword(password, salt, ""))
	fmt.Printf("Original Hash: b14eca867a549f4699b122298984581b03e04c31239e1d1f440db95c\n")
}