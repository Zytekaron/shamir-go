package squad

import (
	"fmt"
	"io"
)

const TagLength = 8

// makePolynomial generates a random polynomial of
// the provided degree with the provided intercept.
//
// (crypto/rand).Reader is an ideal CSPRNG for rng.
func makePolynomial(rng io.Reader, intercept, degree uint8) ([]byte, error) {
	coefficients := make([]byte, degree+1)
	coefficients[0] = intercept

	_, err := rng.Read(coefficients[1:])
	if err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return coefficients, nil
}
