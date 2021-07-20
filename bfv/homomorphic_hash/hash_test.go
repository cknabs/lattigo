package homomorphic_hash

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"github.com/stretchr/testify/require"
	"testing"
)

func getParams() bfv.Parameters {
	// Set up FV parameters
	paramsDef := bfv.PN13QP218
	paramsDef.T = 0x3ee0001

	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}
	return params
}

func getPRNG() utils.PRNG {
	prng, err := utils.NewKeyedPRNG([]byte{42})
	if err != nil {
		panic(err)
	}
	return prng
}

func TestHasher_Hash(t *testing.T) {
	params := getParams()
	encoder := bfv.NewEncoder(params)
	kgen := bfv.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	encryptorSk := bfv.NewEncryptor(params, sk)

	hasher := NewHasher(params)

	msg := make([]uint64, 1<<params.LogN())
	for i := uint64(0); i < uint64(len(msg)); i++ {
		msg[i] = i
	}
	ptxt := bfv.NewPlaintext(params)
	encoder.EncodeUint(msg, ptxt)

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

func TestHash_Add(t *testing.T) {
	// Test if Hash() is homomorphic w.r.t. addition
	params := getParams()
	prng := getPRNG()
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{})
	hasher := NewHasher(params)

	for i := 0; i < 1; i++ {
		c1 := bfv.NewCiphertextRandom(prng, params, 1)
		c2 := bfv.NewCiphertextRandom(prng, params, 1)

		h1 := hasher.Hash(c1)
		h2 := hasher.Hash(c2)

		hAdd := h1.Add(h2)
		cAdd := evaluator.AddNew(c1, c2)
		require.Equal(t, hAdd, hasher.Hash(cAdd))
	}
}

// TODO: fails
func TestHash_Mul(t *testing.T) {
	// Test if Hash() is homomorphic w.r.t. multiplications
	params := getParams()
	prng := getPRNG()

	kgen := bfv.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	rk := kgen.GenRelinearizationKey(sk, 1)
	ek := rlwe.EvaluationKey{Rlk: rk}
	evaluator := bfv.NewEvaluator(params, ek)
	hasher := NewHasher(params)

	for i := 0; i < 1; i++ {
		c1 := bfv.NewCiphertextRandom(prng, params, 1)
		c2 := bfv.NewCiphertextRandom(prng, params, 1)

		h1 := hasher.Hash(c1)
		h2 := hasher.Hash(c2)

		hMul := h1.Mul(h2)
		cMul := evaluator.RelinearizeNew(evaluator.MulNew(c1, c2))
		//cMul := evaluator.MulNew(c1, c2)
		require.Equal(t, hMul, hasher.Hash(cMul))
	}
}
