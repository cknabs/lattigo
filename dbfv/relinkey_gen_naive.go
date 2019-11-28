package dbfv

import (
	"math"

	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
)

type pkgProtocolNaiveContext struct {
	// Polynomial degree
	n uint64

	// Ternary and Gaussian samplers
	gaussianSampler *ring.KYSampler

	// Polynomial contexts
	contextQ *ring.Context

	contextKeys  *ring.Context
	contextPKeys *ring.Context
	alpha        uint64
	beta         uint64
}

func newPkgProtocolNaiveContext(params *bfv.Parameters) *pkgProtocolNaiveContext {
	n := params.N

	contextQ := ring.NewContext()
	contextQ.SetParameters(n, params.Qi)
	err := contextQ.GenNTTParams()
	if err != nil {
		panic(err)
	}

	contextKeys := ring.NewContext()
	contextKeys.SetParameters(n, append(params.Qi, params.KeySwitchPrimes...))
	err = contextKeys.GenNTTParams()
	if err != nil {
		panic(err)
	}

	contextPKeys := ring.NewContext()
	contextPKeys.SetParameters(n, params.KeySwitchPrimes)
	err = contextPKeys.GenNTTParams()
	if err != nil {
		panic(err)
	}

	specialPrimes := make([]uint64, len(params.KeySwitchPrimes))
	for i := range params.KeySwitchPrimes {
		specialPrimes[i] = params.KeySwitchPrimes[i]
	}

	alpha := uint64(len(specialPrimes))
	beta := uint64(math.Ceil(float64(len(params.Qi)) / float64(alpha)))

	gaussianSampler := contextKeys.NewKYSampler(params.Sigma, int(6*params.Sigma))

	return &pkgProtocolNaiveContext{
		n:               n,
		gaussianSampler: gaussianSampler,
		contextQ:        contextQ,
		contextKeys:     contextKeys,
		contextPKeys:    contextPKeys,
		alpha:           alpha,
		beta:            beta,
	}
}

// RKGProtocolNaive is a structure storing the parameters for the naive EKG protocol.
type RKGProtocolNaive struct {
	context         *pkgProtocolNaiveContext
	gaussianSampler *ring.KYSampler
	polypool        *ring.Poly
}

// NewRKGProtocolNaive creates a new RKGProtocolNaive object that will be used to generate a collective evaluation-key
// among j parties in the given context with the given bit-decomposition.
func NewRKGProtocolNaive(params *bfv.Parameters) (rkg *RKGProtocolNaive) {
	context := newPkgProtocolNaiveContext(params)

	rkg = new(RKGProtocolNaive)
	rkg.context = context
	rkg.gaussianSampler = context.gaussianSampler
	rkg.polypool = context.contextKeys.NewPoly()
	return
}

// RKGNaiveShareRoundOne is a struct holding the round one shares of the RKG Naive protocol.
type RKGNaiveShareRoundOne [][2]*ring.Poly

// RKGNaiveShareRoundTwo is a struct holding the round two shares of the RKG Naive protocol.
type RKGNaiveShareRoundTwo [][2]*ring.Poly

// AllocateShares shares allocates the shares of the RKG Naive protocol
func (rkg *RKGProtocolNaive) AllocateShares() (r1 RKGNaiveShareRoundOne, r2 RKGNaiveShareRoundTwo) {
	contextKeys := rkg.context.contextKeys

	r1 = make([][2]*ring.Poly, rkg.context.beta)
	r2 = make([][2]*ring.Poly, rkg.context.beta)

	for i := uint64(0); i < rkg.context.beta; i++ {
		r1[i][0] = contextKeys.NewPoly()
		r1[i][1] = contextKeys.NewPoly()

		r2[i][0] = contextKeys.NewPoly()
		r2[i][1] = contextKeys.NewPoly()
	}

	return
}

// GenShareRoundOne is the first of two rounds of the naive EKG protocol. Using the shared public key "cpk",
// each party generates a pseudo-encryption of s*w of the form :
//
// [cpk[0]*u_i + s_i * w + e_0i, cpk[1]*u_i + e_1i]
//
// and broadcasts it to all other j-1 parties.
func (rkg *RKGProtocolNaive) GenShareRoundOne(sk *ring.Poly, pk [2]*ring.Poly, shareOut RKGNaiveShareRoundOne) {

	contextKeys := rkg.context.contextKeys

	rkg.polypool.Copy(sk)

	contextKeys.MulScalarBigint(rkg.polypool, rkg.context.contextPKeys.ModulusBigint, rkg.polypool)

	contextKeys.InvMForm(rkg.polypool, rkg.polypool)

	var index uint64

	for i := uint64(0); i < rkg.context.beta; i++ {
		// h_0 = e0
		rkg.gaussianSampler.SampleNTT(shareOut[i][0])
		// h_1 = e1
		rkg.gaussianSampler.SampleNTT(shareOut[i][0])

		// h_0 = e0 + [sk*P*(qiBarre*qiStar)%qi = sk*P, else 0]

		for j := uint64(0); j < rkg.context.alpha; j++ {

			index = i*rkg.context.alpha + j

			qi := contextKeys.Modulus[index]

			tmp0 := rkg.polypool.Coeffs[index]
			tmp1 := shareOut[i][0].Coeffs[index]

			for w := uint64(0); w < contextKeys.N; w++ {
				tmp1[w] = ring.CRed(tmp1[w]+tmp0[w], qi)
			}

			// Handles the case where nb pj does not divides nb qi
			if index >= uint64(len(rkg.context.contextQ.Modulus)-1) {
				break
			}
		}
	}

	for i := uint64(0); i < rkg.context.beta; i++ {
		// u
		contextKeys.SampleTernaryMontgomeryNTT(rkg.polypool, 0.5)
		// h_0 = pk_0 * u + e0 + P * sk * (qiBarre*qiStar)%qi
		contextKeys.MulCoeffsMontgomeryAndAdd(pk[0], rkg.polypool, shareOut[i][0])
		// h_1 = pk_1 * u + e1 + P * sk * (qiBarre*qiStar)%qi
		contextKeys.MulCoeffsMontgomeryAndAdd(pk[1], rkg.polypool, shareOut[i][1])
	}

	rkg.polypool.Zero()
}

// AggregateShareRoundOne is the second part of the first round of the naive EKG protocol. Upon receiving the j-1 elements, each party computes :
//
// [sum(cpk[0] * u_j + P * s_j + e_0j), sum(cpk[1] * u_j + e_1j)]
//
// = [cpk[0] * u + P * s + e_0, cpk[1]*u + e_1]
func (rkg *RKGProtocolNaive) AggregateShareRoundOne(share1, share2, shareOut RKGNaiveShareRoundOne) {

	contextKeys := rkg.context.contextKeys

	for i := uint64(0); i < rkg.context.beta; i++ {
		contextKeys.Add(share1[i][0], share2[i][0], shareOut[i][0])
		contextKeys.Add(share1[i][1], share2[i][1], shareOut[i][1])
	}

}

// GenShareRoundTwo is the first part of the second round, each party computes :
//
// [s_i * (cpk[0] * u + P * s + e_0) + v_i * cpk[0] + e_2i, s_i * (cpk[1] * u + e_1) + cpk[1] * v_i + e_3i]
//
// = [ cpk[0] * (u * s_i) + P * (s * s_i) + (s_i * e_0) + v_i*cpk[0] + e_2i, cpk[1] * u * s_i + (s_i * e_1) + cpk[1] * v_i + e_3i]
//
// And party broadcast this last result to the other j-1 parties.
func (rkg *RKGProtocolNaive) GenShareRoundTwo(round1 RKGNaiveShareRoundOne, sk *ring.Poly, pk [2]*ring.Poly, shareOut RKGNaiveShareRoundTwo) {

	contextKeys := rkg.context.contextKeys

	for i := uint64(0); i < rkg.context.beta; i++ {

		// h_0 = sum(samples[0]) * sk
		// h_1 = sum(samples[1]) * sk
		contextKeys.MulCoeffsMontgomery(round1[i][0], sk, shareOut[i][0])
		contextKeys.MulCoeffsMontgomery(round1[i][1], sk, shareOut[i][1])

		// v
		contextKeys.SampleTernaryMontgomeryNTT(rkg.polypool, 0.5)

		// h_0 = sum(samples[0]) * sk + pk0 * v
		contextKeys.MulCoeffsMontgomeryAndAdd(pk[0], rkg.polypool, shareOut[i][0])

		// h_1 = sum(samples[1]) * sk + pk1 * v
		contextKeys.MulCoeffsMontgomeryAndAdd(pk[1], rkg.polypool, shareOut[i][1])

		// h_0 = sum(samples[0]) * sk + pk0 * v + e2
		rkg.gaussianSampler.SampleNTT(rkg.polypool)
		contextKeys.Add(shareOut[i][0], rkg.polypool, shareOut[i][0])

		// h_1 = sum(samples[1]) * sk + pk1 * v + e3
		rkg.gaussianSampler.SampleNTT(rkg.polypool)
		contextKeys.Add(shareOut[i][1], rkg.polypool, shareOut[i][1])

	}

	rkg.polypool.Zero()
}

// AggregateShareRoundTwo is the second part of the second and last round of the naive EKG protocol. Uppon receiving the j-1 elements,
// each party computes :
//
// [ sum(cpk[0] * (u*s_i) + P * (s*s_i) + (s_i*e_0) + v_i*cpk[0] + e_2i), sum(cpk[1]*u*s_i + (s_i*e_1) + cpk[1] * v_i + e_3i)]
//
// = [cpk[0] * (s*u + v) + (P * s^2 ) + s*e_0 + e_2, ckp[1] * (s*u + v) + s*e_1 + e_3]
//
// = [-s*b + P * s^2 - (s*u + b) * e_cpk + s*e_0 + e_2, b + s*e_1 + e_3]
func (rkg *RKGProtocolNaive) AggregateShareRoundTwo(share1, share2, shareOut RKGNaiveShareRoundTwo) {

	contextKeys := rkg.context.contextKeys

	for i := uint64(0); i < rkg.context.beta; i++ {
		contextKeys.Add(share1[i][0], share2[i][0], shareOut[i][0])
		contextKeys.Add(share1[i][1], share2[i][1], shareOut[i][1])
	}
}

// GenRelinearizationKey finalizes the protocol and returns the common EvaluationKey.
func (rkg *RKGProtocolNaive) GenRelinearizationKey(round2 RKGNaiveShareRoundTwo, evalKeyOut *bfv.EvaluationKey) {

	contextKeys := rkg.context.contextKeys

	key := evalKeyOut.Get()[0].Get()
	for i := uint64(0); i < rkg.context.beta; i++ {

		key[i][0].Copy(round2[i][0])
		key[i][1].Copy(round2[i][1])

		contextKeys.MForm(key[i][0], key[i][0])
		contextKeys.MForm(key[i][1], key[i][1])

	}
}
