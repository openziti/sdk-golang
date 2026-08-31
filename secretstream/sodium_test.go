//go:build compat_test

package secretstream

import (
	"testing"
)

func TestToSodium(t *testing.T) {
	common_test(t, NewEncryptor, NewSodiumRecvStream)
}

func TestFromSodium(t *testing.T) {
	common_test(t, NewSodiumSendStream, NewDecryptor)
}

func TestSodium2Sodium(t *testing.T) {
	common_test(t, NewSodiumSendStream, NewSodiumRecvStream)
}
