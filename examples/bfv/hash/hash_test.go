package hash

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHasher_Hash(t *testing.T) {
	// Set up FV parameters
	paramsDef := bfv.PN13QP218
	paramsDef.T = 0x3ee0001

	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	// Set up FV scheme
	encoder := bfv.NewEncoder(params)
	kgen := bfv.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	pk = pk
	encryptorSk := bfv.NewEncryptor(params, sk)
	//encryptorPk := bfv.NewEncryptor(params, pk)
	//decryptor := bfv.NewDecryptor(params, sk)
	//evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{})

	msg := make([]uint64, 1<<params.LogN())
	for i := uint64(0); i < uint64(len(msg)); i++ {
		msg[i] = i
	}
	ptxt := bfv.NewPlaintext(params)
	encoder.EncodeUint(msg, ptxt)

	// Test Hasher
	hasher := HasherNew(params)

	// Test if Hash() is deterministic for the same key (alpha, beta)
	ctxt := encryptorSk.EncryptNew(ptxt)
	h1 := hasher.Hash(ctxt)
	h2 := hasher.Hash(ctxt)

	require.Equal(t, h1, h2)

	// Test if Hash() is universal one-way
	for i := 0; i < 100; i++ {
		encryptorSk.Encrypt(ptxt, ctxt)
		hNew := hasher.Hash(ctxt)
		require.NotEqual(t, h1, hNew)
	}
}
