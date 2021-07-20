// Package hash implements homomorphic hash functions for FV ciphertexts as introduced by Fiore et al.
// in "Efficiently Verifiable Computation on Encrypted Data".
package hash

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"math"
)

type Hasher interface {
	Hash(ctxt *bfv.Ciphertext) (h Hash)
	Eval()
}

type hasher struct {
	params bfv.Parameters
	alpha  uint64
	beta   uint64
}

type Hash struct {
	Value uint64
}

func HasherNew(params bfv.Parameters) Hasher {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	// TODO: Very inefficient (but correct) sampling from Z_q
	sampler := ring.NewUniformSampler(prng, params.RingQ())
	alpha := sampler.ReadNew().Coeffs[0][0]
	beta := sampler.ReadNew().Coeffs[0][1]

	return &hasher{params, alpha, beta}
}

// Hash maps a FV ciphertext (interpreted as a polynomial in Zq[X][Y]) to Zq
// This is the simple construction (without bilinear pairings) that is homomorphic and universal one-way, but not collision-resistant.
func (hasher *hasher) Hash(ctxt *bfv.Ciphertext) Hash {
	// ctxt \in Z_q[X][Y]
	N := ctxt.Value[0].Degree() // deg_X(ctxt)
	c := ctxt.Degree()          // deg_Y(ctxt)

	if c != 1 {
		panic(nil)
	}

	// TODO: handle different levels/moduli products
	qIdx := 0

	// hash = ctxt[X][Y] evaluated at Y = alpha, X = beta
	// TODO: figure out order of exponents
	hash := uint64(0)
	for j := 0; j < c; j++ {
		alphaPowJ := uint64(math.Pow(float64(hasher.alpha), float64(j)))
		coeffJ := ctxt.Value[j].Coeffs[qIdx]
		for i := 0; i < N; i++ {
			betaPowI := uint64(math.Pow(float64(hasher.beta), float64(i)))
			coeffIJ := coeffJ[i]

			hash = (hash + coeffIJ*alphaPowJ*betaPowI) % hasher.params.Q()[qIdx]
		}
	}

	return Hash{hash}
}

func (hasher *hasher) Eval() {

}
