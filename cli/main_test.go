package main

import (
	"testing"
)

func TestTags(t *testing.T) {
	//secret := []byte("Hello, World!")
	//
	//gf := galois.New256(galois.Poly256ReedSolomon, galois.Gen256ReedSolomon)
	//
	//shares, err := shamir.SplitWithField(gf, secret, 3, 5)
	//if err != nil {
	//	t.Fatal(err)
	//}

	//newShares := map[byte][]byte{
	//	1: shares[1],
	//	2: shares[2],
	//	//3: shares[3],
	//	4: shares[4],
	//	//5: shares[5],
	//}

	//sharesBest := map[byte]io.Reader{
	//	1: bytes.NewBuffer(shares[1]),
	//	2: bytes.NewBuffer(shares[2]),
	//	//3: bytes.NewBuffer(shares[3]),
	//	4: bytes.NewBuffer(shares[4]),
	//	//5: bytes.NewBuffer(shares[5]),
	//}
	//
	//sec, err := io.ReadAll(reader)
	////sec, err := squad.CombineTaggedWithField(gf, newShares)
	//if err != nil {
	//	fmt.Println("error combining:", err)
	//} else {
	//	fmt.Println("success combining; slices should match:", slices.Equal(secret, sec))
	//	fmt.Println(string(sec))
	//}
}
