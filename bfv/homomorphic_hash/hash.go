// Package homomorphic_hash implements homomorphic hash functions for FV ciphertexts as introduced by Fiore et al.
// in "Efficiently Verifiable Computation on Encrypted Data".
package homomorphic_hash

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"github.com/stretchr/testify/require"
	"math/big"
)

type Hasher interface {
	Hash(*bfv.Ciphertext) *hash
}

type hasher struct {
	params bfv.Parameters
	alpha  uint64
	beta   uint64
}

type Hash interface {
	Add(*Hash) *Hash
	Mul(*Hash) *Hash
}

type hash struct {
	Values []*big.Int
	Q      []uint64
}

func (h1 *hash) Add(h2 *hash) *hash {
	require.Equal(nil, h1.Q, h2.Q)

	res := make([]*big.Int, len(h1.Q))
	for k := 0; k < len(res); k++ {
		res[k] = new(big.Int)
		res[k] = res[k].Add(h1.Values[k], h2.Values[k])
		res[k] = res[k].Mod(res[k], big.NewInt(int64(h1.Q[k])))
	}

	return &hash{res, h1.Q}
}

func (h1 *hash) Mul(h2 *hash) *hash {
	require.Equal(nil, h1.Q, h2.Q)

	res := make([]*big.Int, len(h1.Q))
	for k := 0; k < len(res); k++ {
		res[k] = new(big.Int)
		res[k] = res[k].Mul(h1.Values[k], h2.Values[k])
		res[k] = res[k].Mod(res[k], big.NewInt(int64(h1.Q[k])))
	}

	return &hash{res, h1.Q}
}

func NewHasher(params bfv.Parameters) Hasher {
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
func (hasher *hasher) Hash(ctxt *bfv.Ciphertext) *hash {
	// ctxt \in Z_q[X][Y]
	N := ctxt.Value[0].Degree() // deg_X(ctxt)
	c := ctxt.Degree()          // deg_Y(ctxt)
	Q := hasher.params.Q()

	//if c != 1 {
	//	panic(nil)
	//}

	// hash = ctxt[X][Y] evaluated at Y = alpha, X = beta
	// TODO: figure out order of exponents
	hs := make([]*big.Int, len(Q))
	for i := 0; i < len(hs); i++ {
		hs[i] = big.NewInt(0)
	}

	for j := 0; j < c; j++ {

		for i := 0; i < N; i++ {
			for k := 0; k < len(Q); k++ {
				alphaPowJ := big.NewInt(int64(hasher.alpha))
				alphaPowJ = alphaPowJ.Exp(alphaPowJ, big.NewInt(int64(j)), big.NewInt(int64(Q[k])))

				betaPowI := big.NewInt(int64(hasher.beta))
				betaPowI = betaPowI.Exp(betaPowI, big.NewInt(int64(i)), big.NewInt(int64(Q[k])))

				coeffIJK := big.NewInt(int64(ctxt.Value[j].Coeffs[k][i]))
				m := coeffIJK
				m = m.Mul(m, alphaPowJ)
				m = m.Mul(m, betaPowI)
				m = m.Mod(m, big.NewInt(int64(Q[k])))

				hs[k] = hs[k].Add(hs[k], m)
				hs[k] = hs[k].Mod(hs[k], big.NewInt(int64(Q[k])))
			}
		}
	}

	return &hash{hs, hasher.params.Q()}
}
