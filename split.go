package squad

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// ShamirGaloisField is a GF(2^8) field which uses the standard
// AES polynomial and generators, PolyAES (0x11B) and GenAES (0x03).
//
// This is the default Galois Field used for Shamir Secret Sharing.
var ShamirGaloisField = New256(PolyAES, GenAES)

// Split takes the secret and splits it into n shares,
// where at least k are required to recreate the secret.
//
// Shares are indexed in the map from 1 to n. When you
// combine shares, the key/value pairs must match, aside
// from omitting up to (n-k) key/value pairs. For example,
// you cannot swap the values for shares[1] and shares[3],
// as the key denotes the x value used in the underlying
// algorithm, and the value is the coefficient for that key.
// shares[0] is not used, as this is where the secret lies.
//
// If your use case requires that it be possible to
// determine if the secret was properly recreated later,
// you should add information to the secret that allows
// you to test for garbage output. For example, you could
// make the first 8 bytes all zeros. The combination step
// is unaware of situations where < k shares are combined.
//
// Constraints:
//   - 2 <= k <= 255
//   - k <= n <= 255
//
// Reference: https://en.wikipedia.org/wiki/Shamir's_secret_sharing
func Split(secret []byte, k, n byte) (map[byte][]byte, error) {
	return SplitWithField(ShamirGaloisField, secret, k, n)
}

func SplitWithField(gf *GF256, secret []byte, k, n byte) (map[byte][]byte, error) {
	if gf == nil {
		return nil, errors.New("galois field is nil")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret is empty")
	}
	if k < 2 {
		panic("k must be at least 2")
	}
	if n < k {
		panic("n must not be less than k")
	}

	degree := k - 1

	shares := map[byte][]byte{}
	for i := byte(1); i <= n; i++ {
		shares[i] = make([]byte, len(secret))
	}

	for i := 0; i < len(secret); i++ {
		coefficients, err := makePolynomial(rand.Reader, secret[i], degree)
		if err != nil {
			return nil, fmt.Errorf("generating polynomial: %w", err)
		}

		for x := byte(1); x <= n; x++ {
			y := gf.Evaluate(coefficients, x)
			shares[x][i] = y
		}
	}

	return shares, nil
}

func SplitTagged(secret []byte, k, n byte) (map[byte][]byte, error) {
	return SplitTaggedWithField(ShamirGaloisField, secret, k, n)
}

func SplitTaggedWithField(gf *GF256, secret []byte, k, n byte) (map[byte][]byte, error) {
	if gf == nil {
		return nil, errors.New("galois field is nil")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret is empty")
	}
	if k < 2 {
		panic("k must be at least 2")
	}
	if n < k {
		panic("n must not be less than k")
	}

	degree := k - 1

	shares := map[byte][]byte{}
	for i := byte(1); i <= n; i++ {
		shares[i] = make([]byte, len(secret)+TagLength)
	}

	// encode tag
	for i := 0; i < TagLength; i++ {
		coefficients, err := makePolynomial(rand.Reader, 0, degree)
		if err != nil {
			return nil, fmt.Errorf("generating polynomial: %w", err)
		}

		for x := byte(1); x <= n; x++ {
			y := gf.Evaluate(coefficients, x)
			shares[x][i] = y
		}
	}

	// encode secret
	for i := 0; i < len(secret); i++ {
		coefficients, err := makePolynomial(rand.Reader, secret[i], degree)
		if err != nil {
			return nil, fmt.Errorf("generating polynomial: %w", err)
		}

		for x := byte(1); x <= n; x++ {
			y := gf.Evaluate(coefficients, x)
			shares[x][i+TagLength] = y
		}
	}

	return shares, nil
}
