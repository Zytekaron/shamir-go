package shamir

import (
	"errors"

	"github.com/zytekaron/galois-go"
)

// Combine takes the available shares and attempts
// to use them to recreate the original secret.
//
// At least k of the original shares must be present
// for this operation to succeed, otherwise it will
// silently fail by returning garbage output.
func Combine(shares map[byte][]byte) []byte {
	return CombineWithField(GaloisField, shares)
}

func CombineWithField(gf *galois.GF256, shares map[byte][]byte) []byte {
	var secretLength int
	for _, share := range shares {
		secretLength = len(share)
		break
	}
	if secretLength == 0 {
		return nil
	}

	// unlock secret
	samples := make([]galois.Point, len(shares))
	secret := make([]byte, secretLength)
	for i := 0; i < secretLength; i++ {
		sampleIndex := 0
		for x := range shares {
			samples[sampleIndex] = galois.Point{X: x, Y: shares[x][i]}
			sampleIndex++
		}

		secret[i] = gf.Interpolate(samples, 0)
	}

	return secret
}

// CombineTagged takes the available shares and
// uses them to recreate the original secret.
//
// At least k of the original shares must be present
// for this operation to succeed, otherwise it will
// produce an error due to a tag mismatch caused by
// the underlying algorithm producing garbage output.
func CombineTagged(shares map[byte][]byte) ([]byte, error) {
	return CombineTaggedWithField(GaloisField, shares)
}

func CombineTaggedWithField(gf *galois.GF256, shares map[byte][]byte) ([]byte, error) {
	var secretLength int
	for _, share := range shares {
		secretLength = len(share) - TagLength
		break
	}
	if secretLength == 0 {
		return nil, nil
	}

	samples := make([]galois.Point, len(shares))

	// verify tag
	for i := 0; i < TagLength; i++ {
		sampleIndex := 0
		for x := range shares {
			samples[sampleIndex] = galois.Point{X: x, Y: shares[x][i]}
			sampleIndex++
		}

		if gf.Interpolate(samples, 0) != 0 {
			return nil, errors.New("tag mismatch")
		}
	}

	// unlock secret
	secret := make([]byte, secretLength)
	for i := 0; i < secretLength; i++ {
		sampleIndex := 0
		for x := range shares {
			samples[sampleIndex] = galois.Point{X: x, Y: shares[x][i+TagLength]}
			sampleIndex++
		}

		secret[i] = gf.Interpolate(samples, 0)
	}

	return secret, nil
}
