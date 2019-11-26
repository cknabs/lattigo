package dbfv

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"github.com/ldsec/lattigo/utils"
	"log"
	"math/big"
	"testing"
)

func check(t *testing.T, err error) {
	if err != nil {
		t.Error(err)
	}
}

type dbfvContext struct {
	bfvContext *bfv.Context
	encoder    *bfv.Encoder
	kgen       *bfv.KeyGenerator

	sk0Shards []*bfv.SecretKey
	sk0       *bfv.SecretKey

	sk1       *bfv.SecretKey
	sk1Shards []*bfv.SecretKey

	pk0 *bfv.PublicKey
	pk1 *bfv.PublicKey

	encryptorPk0 *bfv.Encryptor
	decryptorSk0 *bfv.Decryptor
	decryptorSk1 *bfv.Decryptor
	evaluator    *bfv.Evaluator
}

type dbfvTestParameters struct {
	parties uint64

	contexts []bfv.Parameters
}

var err error
var testParams = new(dbfvTestParameters)

func init() {
	testParams.parties = 3

	testParams.contexts = bfv.DefaultParams
}

func Test_DBFV(t *testing.T) {
	t.Run("PublicKeyGen", testPublicKeyGen)
	t.Run("RelinKeyGen", testRelinKeyGen)
	t.Run("RelinKeyGenNaive", testRelinKeyGenNaive)
	t.Run("KeySwitching", testKeyswitching)
	t.Run("PublicKeySwitching", testPublicKeySwitching)
	t.Run("RotKeyGenRotRows", testRotKeyGenRotRows)
	t.Run("RotKeyGenRotCols", testRotKeyGenRotCols)
	t.Run("Refresh", testRefresh)

}

func genDBFVContext(contextParameters *bfv.Parameters) (params *dbfvContext) {

	params = new(dbfvContext)

	params.bfvContext = bfv.NewContextWithParam(contextParameters)

	params.encoder = params.bfvContext.NewEncoder()
	params.evaluator = params.bfvContext.NewEvaluator()

	kgen := params.bfvContext.NewKeyGenerator()

	// SecretKeys
	params.sk0Shards = make([]*bfv.SecretKey, testParams.parties)
	params.sk1Shards = make([]*bfv.SecretKey, testParams.parties)
	tmp0 := params.bfvContext.ContextKeys().NewPoly()
	tmp1 := params.bfvContext.ContextKeys().NewPoly()

	for j := uint64(0); j < testParams.parties; j++ {
		params.sk0Shards[j] = kgen.NewSecretKey()
		params.sk1Shards[j] = kgen.NewSecretKey()
		params.bfvContext.ContextKeys().Add(tmp0, params.sk0Shards[j].Get(), tmp0)
		params.bfvContext.ContextKeys().Add(tmp1, params.sk1Shards[j].Get(), tmp1)
	}

	params.sk0 = new(bfv.SecretKey)
	params.sk1 = new(bfv.SecretKey)

	params.sk0.Set(tmp0)
	params.sk1.Set(tmp1)

	// Publickeys
	params.pk0 = kgen.NewPublicKey(params.sk0)
	params.pk1 = kgen.NewPublicKey(params.sk1)

	params.encryptorPk0 = params.bfvContext.NewEncryptorFromPk(params.pk0)
	params.decryptorSk0 = params.bfvContext.NewDecryptor(params.sk0)
	params.decryptorSk1 = params.bfvContext.NewDecryptor(params.sk1)

	return
}

func testPublicKeyGen(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := bfvContext.ContextKeys()
		sk0Shards := params.sk0Shards
		decryptorSk0 := params.decryptorSk0

		t.Run(fmt.Sprintf("N=%d/logQ=%d", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			crpGenerator := ring.NewCRPGenerator(nil, contextKeys)
			crpGenerator.Seed([]byte{})
			crp := crpGenerator.Clock()

			type Party struct {
				*CKGProtocol
				s  *ring.Poly
				s1 CKGShare
			}

			ckgParties := make([]*Party, parties)
			for i := uint64(0); i < parties; i++ {
				p := new(Party)
				p.CKGProtocol = NewCKGProtocol(bfvContext)
				p.s = sk0Shards[i].Get()
				p.s1 = p.AllocateShares()
				ckgParties[i] = p
			}
			P0 := ckgParties[0]

			// Each party creates a new CKGProtocol instance
			for i, p := range ckgParties {
				p.GenShare(p.s, crp, p.s1)
				if i > 0 {
					P0.AggregateShares(p.s1, P0.s1, P0.s1)
				}
			}

			pk := &bfv.PublicKey{}
			P0.GenPublicKey(P0.s1, crp, pk)

			// Verifies that decrypt((encryptp(collectiveSk, m), collectivePk) = m
			encryptorTest := bfvContext.NewEncryptorFromPk(pk)

			coeffs, _, ciphertext := newTestVectors(params, encryptorTest, t)

			verifyTestVectors(params, decryptorSk0, coeffs, ciphertext, t)
		})
	}
}

func testRelinKeyGen(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := bfvContext.ContextKeys()
		sk0Shards := params.sk0Shards
		encryptorPk0 := params.encryptorPk0
		decryptorSk0 := params.decryptorSk0
		evaluator := params.evaluator

		t.Run(fmt.Sprintf("N=%d/logQ=%d", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			type Party struct {
				*RKGProtocol
				u      *ring.Poly
				s      *ring.Poly
				share1 RKGShareRoundOne
				share2 RKGShareRoundTwo
				share3 RKGShareRoundThree
			}

			rkgParties := make([]*Party, parties)

			for i := range rkgParties {
				p := new(Party)
				p.RKGProtocol = NewEkgProtocol(bfvContext)
				p.u = p.RKGProtocol.NewEphemeralKey(1.0 / 3.0)
				p.s = sk0Shards[i].Get()
				p.share1, p.share2, p.share3 = p.RKGProtocol.AllocateShares()
				rkgParties[i] = p
			}

			P0 := rkgParties[0]

			crpGenerator := ring.NewCRPGenerator(nil, bfvContext.ContextKeys())
			crpGenerator.Seed([]byte{})
			crp := make([]*ring.Poly, bfvContext.Beta())

			for i := uint64(0); i < bfvContext.Beta(); i++ {
				crp[i] = crpGenerator.Clock()
			}

			// ROUND 1
			for i, p := range rkgParties {
				p.GenShareRoundOne(p.u, p.s, crp, p.share1)
				if i > 0 {
					P0.AggregateShareRoundOne(p.share1, P0.share1, P0.share1)
				}
			}

			//ROUND 2
			for i, p := range rkgParties {
				p.GenShareRoundTwo(P0.share1, p.s, crp, p.share2)
				if i > 0 {
					P0.AggregateShareRoundTwo(p.share2, P0.share2, P0.share2)
				}
			}

			// ROUND 3
			for i, p := range rkgParties {
				p.GenShareRoundThree(P0.share2, p.u, p.s, p.share3)
				if i > 0 {
					P0.AggregateShareRoundThree(p.share3, P0.share3, P0.share3)
				}
			}

			evk := bfvContext.NewRelinKey(1)
			P0.GenRelinearizationKey(P0.share2, P0.share3, evk)

			coeffs, _, ciphertext := newTestVectors(params, encryptorPk0, t)

			for i := range coeffs {
				coeffs[i] *= coeffs[i]
				coeffs[i] %= bfvContext.ContextT().Modulus[0]
			}

			ciphertextMul := bfvContext.NewCiphertext(ciphertext.Degree() * 2)
			evaluator.Mul(ciphertext, ciphertext, ciphertextMul)

			res := bfvContext.NewCiphertext(1)
			evaluator.Relinearize(ciphertextMul, evk, res)

			verifyTestVectors(params, decryptorSk0, coeffs, ciphertextMul, t)
		})
	}
}

func testRelinKeyGenNaive(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := bfvContext.ContextKeys()
		evaluator := params.evaluator
		pk0 := params.pk0
		encryptorPk0 := params.encryptorPk0
		decryptorSk0 := params.decryptorSk0
		sk0Shards := params.sk0Shards

		t.Run(fmt.Sprintf("N=%d/logQ=%d", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			type Party struct {
				*RKGProtocolNaive
				u      *ring.Poly
				s      *ring.Poly
				share1 RKGNaiveShareRoundOne
				share2 RKGNaiveShareRoundTwo
			}

			rkgParties := make([]*Party, parties)

			for i := range rkgParties {
				p := new(Party)
				p.RKGProtocolNaive = NewRKGProtocolNaive(bfvContext)
				p.s = sk0Shards[i].Get()
				p.share1, p.share2 = p.AllocateShares()
				rkgParties[i] = p
			}

			P0 := rkgParties[0]

			// ROUND 1
			for i, p := range rkgParties {
				rkgParties[i].GenShareRoundOne(p.s, pk0.Get(), p.share1)
				if i > 0 {
					P0.AggregateShareRoundOne(p.share1, P0.share1, P0.share1)
				}
			}

			// ROUND 2
			for i, p := range rkgParties {
				rkgParties[i].GenShareRoundTwo(P0.share1, p.s, pk0.Get(), p.share2)
				if i > 0 {
					P0.AggregateShareRoundTwo(p.share2, P0.share2, P0.share2)
				}
			}

			evk := bfvContext.NewRelinKey(1)
			P0.GenRelinearizationKey(P0.share2, evk)

			coeffs, _, ciphertext := newTestVectors(params, encryptorPk0, t)

			for i := range coeffs {
				coeffs[i] *= coeffs[i]
				coeffs[i] %= bfvContext.ContextT().Modulus[0]
			}

			ciphertextMul := bfvContext.NewCiphertext(ciphertext.Degree() * 2)
			evaluator.Mul(ciphertext, ciphertext, ciphertextMul)

			res := bfvContext.NewCiphertext(1)
			evaluator.Relinearize(ciphertextMul, evk, res)

			verifyTestVectors(params, decryptorSk0, coeffs, ciphertextMul, t)
		})
	}
}

func testKeyswitching(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := bfvContext.ContextKeys()
		sk0Shards := params.sk0Shards
		sk1Shards := params.sk1Shards
		encryptorPk0 := params.encryptorPk0
		decryptorSk1 := params.decryptorSk1

		t.Run(fmt.Sprintf("N=%d/logQ=%d", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			type Party struct {
				*CKSProtocol
				s0    *ring.Poly
				s1    *ring.Poly
				share CKSShare
			}

			cksParties := make([]*Party, parties)
			for i := uint64(0); i < parties; i++ {
				p := new(Party)
				p.CKSProtocol = NewCKSProtocol(bfvContext, 6.36)
				p.s0 = sk0Shards[i].Get()
				p.s1 = sk1Shards[i].Get()
				p.share = p.AllocateShare()
				cksParties[i] = p
			}
			P0 := cksParties[0]

			coeffs, _, ciphertext := newTestVectors(params, encryptorPk0, t)

			// Each party creates its CKSProtocol instance with tmp = si-si'
			for i, p := range cksParties {
				p.GenShare(p.s0, p.s1, ciphertext, p.share)
				if i > 0 {
					P0.AggregateShares(p.share, P0.share, P0.share)
				}
			}

			ksCiphertext := bfvContext.NewCiphertext(1)
			P0.KeySwitch(P0.share, ciphertext, ksCiphertext)

			verifyTestVectors(params, decryptorSk1, coeffs, ksCiphertext, t)

			P0.KeySwitch(P0.share, ciphertext, ciphertext)

			verifyTestVectors(params, decryptorSk1, coeffs, ciphertext, t)

		})
	}
}

func testPublicKeySwitching(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := bfvContext.ContextKeys()
		sk0Shards := params.sk0Shards
		pk1 := params.pk1
		encryptorPk0 := params.encryptorPk0
		decryptorSk1 := params.decryptorSk1

		t.Run(fmt.Sprintf("N=%d/logQ=%d", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			type Party struct {
				*PCKSProtocol
				s     *ring.Poly
				share PCKSShare
			}

			pcksParties := make([]*Party, parties)
			for i := uint64(0); i < parties; i++ {
				p := new(Party)
				p.PCKSProtocol = NewPCKSProtocol(bfvContext, 6.36)
				p.s = sk0Shards[i].Get()
				p.share = p.AllocateShares()
				pcksParties[i] = p
			}
			P0 := pcksParties[0]

			coeffs, _, ciphertext := newTestVectors(params, encryptorPk0, t)

			ciphertextSwitched := bfvContext.NewCiphertext(1)

			for i, p := range pcksParties {
				p.GenShare(p.s, pk1, ciphertext, p.share)
				if i > 0 {
					P0.AggregateShares(p.share, P0.share, P0.share)
				}
			}

			P0.KeySwitch(P0.share, ciphertext, ciphertextSwitched)

			verifyTestVectors(params, decryptorSk1, coeffs, ciphertextSwitched, t)
		})
	}
}

func testRotKeyGenRotRows(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := bfvContext.ContextKeys()
		evaluator := params.evaluator
		encryptorPk0 := params.encryptorPk0
		decryptorSk0 := params.decryptorSk0
		sk0Shards := params.sk0Shards

		t.Run(fmt.Sprintf("N=%d/logQ=%d", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			type Party struct {
				*RTGProtocol
				s     *ring.Poly
				share RTGShare
			}

			pcksParties := make([]*Party, parties)
			for i := uint64(0); i < parties; i++ {
				p := new(Party)
				p.RTGProtocol = NewRotKGProtocol(bfvContext)
				p.s = sk0Shards[i].Get()
				p.share = p.AllocateShare()
				pcksParties[i] = p
			}
			P0 := pcksParties[0]

			crpGenerator := ring.NewCRPGenerator(nil, bfvContext.ContextKeys())
			crpGenerator.Seed([]byte{})
			crp := make([]*ring.Poly, bfvContext.Beta())

			for i := uint64(0); i < bfvContext.Beta(); i++ {
				crp[i] = crpGenerator.Clock()
			}

			for i, p := range pcksParties {
				p.GenShare(bfv.RotationRow, 0, p.s, crp, &p.share)
				if i > 0 {
					P0.Aggregate(p.share, P0.share, P0.share)
				}
			}

			rotkey := bfvContext.NewRotationKeys()
			P0.Finalize(P0.share, crp, rotkey)

			coeffs, _, ciphertext := newTestVectors(params, encryptorPk0, t)

			evaluator.RotateRows(ciphertext, rotkey, ciphertext)

			coeffs = append(coeffs[contextKeys.N>>1:], coeffs[:contextKeys.N>>1]...)

			verifyTestVectors(params, decryptorSk0, coeffs, ciphertext, t)

		})
	}

}

func testRotKeyGenRotCols(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := bfvContext.ContextKeys()
		evaluator := params.evaluator
		encryptorPk0 := params.encryptorPk0
		decryptorSk0 := params.decryptorSk0
		sk0Shards := params.sk0Shards

		t.Run(fmt.Sprintf("N=%d/logQ=%d", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			type Party struct {
				*RTGProtocol
				s     *ring.Poly
				share RTGShare
			}

			pcksParties := make([]*Party, parties)
			for i := uint64(0); i < parties; i++ {
				p := new(Party)
				p.RTGProtocol = NewRotKGProtocol(bfvContext)
				p.s = sk0Shards[i].Get()
				p.share = p.AllocateShare()
				pcksParties[i] = p
			}

			P0 := pcksParties[0]

			crpGenerator := ring.NewCRPGenerator(nil, contextKeys)
			crpGenerator.Seed([]byte{})
			crp := make([]*ring.Poly, bfvContext.Beta())

			for i := uint64(0); i < bfvContext.Beta(); i++ {
				crp[i] = crpGenerator.Clock()
			}

			mask := (contextKeys.N >> 1) - 1

			coeffs, _, ciphertext := newTestVectors(params, encryptorPk0, t)

			receiver := bfvContext.NewCiphertext(ciphertext.Degree())

			for k := uint64(1); k < contextKeys.N>>1; k <<= 1 {

				for i, p := range pcksParties {
					p.GenShare(bfv.RotationLeft, k, p.s, crp, &p.share)
					if i > 0 {
						P0.Aggregate(p.share, P0.share, P0.share)
					}
				}

				rotkey := bfvContext.NewRotationKeys()
				P0.Finalize(P0.share, crp, rotkey)

				evaluator.RotateColumns(ciphertext, k, rotkey, receiver)

				coeffsWant := make([]uint64, contextKeys.N)

				for i := uint64(0); i < contextKeys.N>>1; i++ {
					coeffsWant[i] = coeffs[(i+k)&mask]
					coeffsWant[i+(contextKeys.N>>1)] = coeffs[((i+k)&mask)+(contextKeys.N>>1)]
				}

				verifyTestVectors(params, decryptorSk0, coeffsWant, receiver, t)
			}
		})
	}
}

func testRefresh(t *testing.T) {

	parties := testParams.parties

	for _, parameters := range testParams.contexts {

		params := genDBFVContext(&parameters)

		bfvContext := params.bfvContext
		contextKeys := params.bfvContext.ContextKeys()
		encryptorPk0 := params.encryptorPk0
		sk0Shards := params.sk0Shards
		encoder := params.encoder
		decryptorSk0 := params.decryptorSk0

		kgen := bfvContext.NewKeyGenerator()

		rlk := kgen.NewRelinKey(params.sk0, 2)

		t.Run(fmt.Sprintf("N=%d/logQ=%d/Refresh", contextKeys.N, contextKeys.ModulusBigint.BitLen()), func(t *testing.T) {

			type Party struct {
				*RefreshProtocol
				s       *ring.Poly
				share   RefreshShare
				ptShare *bfv.Plaintext
			}

			RefreshParties := make([]*Party, parties)
			for i := uint64(0); i < parties; i++ {
				p := new(Party)
				p.RefreshProtocol = NewRefreshProtocol(bfvContext)
				p.s = sk0Shards[i].Get()
				p.share = p.AllocateShares()
				p.ptShare = bfvContext.NewPlaintext()
				RefreshParties[i] = p
			}

			P0 := RefreshParties[0]

			crpGenerator := ring.NewCRPGenerator(nil, bfvContext.ContextKeys())
			crpGenerator.Seed([]byte{})
			crp := crpGenerator.Clock()

			coeffs, _, ciphertext := newTestVectors(params, encryptorPk0, t)

			maxDepth := 0

			ciphertextTmp := ciphertext.CopyNew().Ciphertext()
			coeffsTmp := make([]uint64, len(coeffs))

			for i := range coeffs {
				coeffsTmp[i] = coeffs[i]
			}

			// Finds the maximum multiplicative depth
			for true {

				params.evaluator.Relinearize(params.evaluator.MulNew(ciphertextTmp, ciphertextTmp), rlk, ciphertextTmp)

				for j := range coeffsTmp {
					coeffsTmp[j] = ring.BRed(coeffsTmp[j], coeffsTmp[j], bfvContext.ContextT().Modulus[0], bfvContext.ContextT().GetBredParams()[0])
				}

				if utils.EqualSliceUint64(coeffsTmp, encoder.DecodeUint(decryptorSk0.DecryptNew(ciphertextTmp))) {
					maxDepth++
				} else {
					break
				}
			}

			// Simulated added error of size Q/(T^2) and add it to the fresh ciphertext
			coeffsBigint := make([]*big.Int, bfvContext.N())
			bfvContext.ContextQ().PolyToBigint(ciphertext.Value()[0], coeffsBigint)

			errorRange := new(big.Int).Set(bfvContext.ContextQ().ModulusBigint)
			errorRange.Quo(errorRange, bfvContext.ContextT().ModulusBigint)
			errorRange.Quo(errorRange, bfvContext.ContextT().ModulusBigint)

			for i := uint64(0); i < bfvContext.N(); i++ {
				coeffsBigint[i].Add(coeffsBigint[i], ring.RandInt(errorRange))
			}

			bfvContext.ContextQ().SetCoefficientsBigint(coeffsBigint, ciphertext.Value()[0])

			for i, p := range RefreshParties {
				p.GenShares(p.s, ciphertext, crp, p.share)
				if i > 0 {
					P0.Aggregate(p.share, P0.share, P0.share)
				}
			}

			// We refresh the ciphertext with the simulated error
			P0.Decrypt(ciphertext, P0.share.RefreshShareDecrypt, P0.ptShare.Value()[0])      // Masked decryption
			P0.Recode(P0.ptShare.Value()[0], P0.ptShare.Value()[0])                          // Masked re-encoding
			P0.Recrypt(P0.ptShare.Value()[0], crp, P0.share.RefreshShareRecrypt, ciphertext) // Masked re-encryption$

			// The refresh also be called all at once with P0.Finalize(ciphertext, crp, P0.share, ctOut)

			// Square the refreshed ciphertext up to the maximum depth-1
			for i := 0; i < maxDepth-1; i++ {

				params.evaluator.Relinearize(params.evaluator.MulNew(ciphertext, ciphertext), rlk, ciphertext)

				for j := range coeffs {
					coeffs[j] = ring.BRed(coeffs[j], coeffs[j], bfvContext.ContextT().Modulus[0], bfvContext.ContextT().GetBredParams()[0])
				}
			}

			//Decrypts and compare
			if utils.EqualSliceUint64(coeffs, encoder.DecodeUint(decryptorSk0.DecryptNew(ciphertext))) != true {
				t.Errorf("error : BOOT")
			}
		})
	}
}

func newTestVectors(contextParams *dbfvContext, encryptor *bfv.Encryptor, t *testing.T) (coeffs []uint64, plaintext *bfv.Plaintext, ciphertext *bfv.Ciphertext) {
	coeffsPol := contextParams.bfvContext.ContextT().NewUniformPoly()
	plaintext = contextParams.bfvContext.NewPlaintext()
	contextParams.encoder.EncodeUint(coeffsPol.Coeffs[0], plaintext)
	ciphertext = encryptor.EncryptNew(plaintext)
	return coeffsPol.Coeffs[0], plaintext, ciphertext
}

func verifyTestVectors(contextParams *dbfvContext, decryptor *bfv.Decryptor, coeffs []uint64, ciphertext *bfv.Ciphertext, t *testing.T) {
	if utils.EqualSliceUint64(coeffs, contextParams.encoder.DecodeUint(decryptor.DecryptNew(ciphertext))) != true {
		t.Errorf("decryption error")
	}
}

func Test_Marshalling(t *testing.T) {

	//verify if the un.marshalling works properly
	bfvCtx := bfv.NewContextWithParam(&bfv.DefaultParams[1])
	KeyGenerator := bfvCtx.NewKeyGenerator()
	crsGen := ring.NewCRPGenerator([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'}, bfvCtx.ContextKeys())
	sk := KeyGenerator.NewSecretKey()
	crs := crsGen.Clock()
	contextQ := bfvCtx.ContextQ()
	contextPKeys := bfvCtx.ContextPKeys()

	Ciphertext := bfvCtx.NewRandomCiphertext(1)

	t.Run(fmt.Sprintf("CPK/N=%d/limbQ=%d/limbsP=%d", contextQ.N, len(contextQ.Modulus), len(contextPKeys.Modulus)), func(t *testing.T) {
		keygenProtocol := NewCKGProtocol(bfvCtx)
		KeyGenShareBefore := keygenProtocol.AllocateShares()
		keygenProtocol.GenShare(sk.Get(), crs, KeyGenShareBefore)
		//now we marshall it
		data, err := KeyGenShareBefore.MarshalBinary()

		fmt.Println("CPK Data (kB) :", len(data)/1000)

		if err != nil {
			log.Fatal("Could not marshal the CKGShare : ", err)

		}

		KeyGenShareAfter := new(CKGShare)
		err = KeyGenShareAfter.UnmarshalBinary(data)
		if err != nil {
			log.Fatal("Could not unmarshal the CKGShare : ", err)

		}

		//comparing the results
		if KeyGenShareBefore.GetDegree() != KeyGenShareAfter.GetDegree() || KeyGenShareBefore.GetLenModuli() != KeyGenShareAfter.GetLenModuli() {
			log.Print("Unmatched degree or moduli length on key gen shares")
			t.Fail()
		}

		for i := 0; i < KeyGenShareBefore.GetLenModuli(); i++ {
			if !utils.EqualSliceUint64(KeyGenShareAfter.Coeffs[i], KeyGenShareBefore.Coeffs[i]) {
				log.Print("Non equal slices in CKGShare")
				t.Fail()
			}

		}
	})

	t.Run(fmt.Sprintf("PCKS/N=%d/limbQ=%d/limbsP=%d", contextQ.N, len(contextQ.Modulus), len(contextPKeys.Modulus)), func(t *testing.T) {
		//Check marshalling for the PCKS

		KeySwitchProtocol := NewPCKSProtocol(bfvCtx, bfvCtx.Sigma())
		SwitchShare := KeySwitchProtocol.AllocateShares()
		pk := KeyGenerator.NewPublicKey(sk)
		KeySwitchProtocol.GenShare(sk.Get(), pk, Ciphertext, SwitchShare)

		data, err := SwitchShare.MarshalBinary()
		fmt.Println("PCKS Data (kB) :", len(data)/1000)
		if err != nil {
			log.Print("Error on PCKSShare marshalling : ", err)
			t.Fail()
		}
		SwitchShareReceiver := new(PCKSShare)
		err = SwitchShareReceiver.UnmarshalBinary(data)
		if err != nil {
			log.Print("Error on PCKSShare unmarshalling : ", err)
			t.Fail()
		}

		for i := 0; i < 2; i++ {
			//compare the shares.
			ringBefore := SwitchShare[i]
			ringAfter := SwitchShareReceiver[i]
			if ringBefore.GetDegree() != ringAfter.GetDegree() {
				log.Print("Error on degree matching")
				t.Fail()
			}
			for d := 0; d < ringAfter.GetLenModuli(); d++ {
				if !utils.EqualSliceUint64(ringAfter.Coeffs[d], ringBefore.Coeffs[d]) {
					log.Print("Non equal slices in PCKSShare")
					t.Fail()
				}
			}

		}
	})

	t.Run(fmt.Sprintf("CKS/N=%d/limbQ=%d/limbsP=%d", contextQ.N, len(contextQ.Modulus), len(contextPKeys.Modulus)), func(t *testing.T) {

		//Now for CKSShare ~ its similar to PKSShare
		cksp := NewCKSProtocol(bfvCtx, bfvCtx.Sigma())
		cksshare := cksp.AllocateShare()
		skIn := KeyGenerator.NewSecretKey()
		skOut := KeyGenerator.NewSecretKey()
		cksp.GenShare(skIn.Get(), skOut.Get(), Ciphertext, cksshare)

		data, err := cksshare.MarshalBinary()
		fmt.Println("CKS Data (kB) :", len(data)/1000)
		if err != nil {
			log.Print("Error on marshalling CKSShare : ", err)
			t.Fail()
		}
		cksshareAfter := new(CKSShare)
		err = cksshareAfter.UnmarshalBinary(data)
		if err != nil {
			log.Print("Error on unmarshalling CKSShare : ", err)
			t.Fail()
		}

		//now compare both shares.

		if cksshare.GetDegree() != cksshareAfter.GetDegree() || cksshare.GetLenModuli() != cksshareAfter.GetLenModuli() {
			log.Print("Unmatched degree or moduli lenght on CKSShare")
			t.Fail()
		}

		for i := 0; i < cksshare.GetLenModuli(); i++ {
			if !utils.EqualSliceUint64(cksshare.Coeffs[i], cksshareAfter.Coeffs[i]) {
				log.Print("Non equal slices in CKSShare")
				t.Fail()
			}

		}
	})

	t.Run(fmt.Sprintf("Refresh/N=%d/limbQ=%d/limbsP=%d", contextQ.N, len(contextQ.Modulus), len(contextPKeys.Modulus)), func(t *testing.T) {

		//testing refresh shares
		refreshproto := NewRefreshProtocol(bfvCtx)
		refreshshare := refreshproto.AllocateShares()
		refreshproto.GenShares(sk.Get(), Ciphertext, crs, refreshshare)

		data, err := refreshshare.MarshalBinary()
		fmt.Println("Refresh Data (kB) :", len(data)/1000)
		if err != nil {
			log.Fatal("Could not marshal RefreshShare", err)
		}
		resRefreshShare := new(RefreshShare)
		err = resRefreshShare.UnmarshalBinary(data)

		if err != nil {
			log.Fatal("Could not unmarshal RefreshShare", err)
		}
		for i, r := range refreshshare.RefreshShareDecrypt.Coeffs {
			if !utils.EqualSliceUint64(resRefreshShare.RefreshShareDecrypt.Coeffs[i], r) {
				log.Fatal("Resulting of marshalling not the same as original : RefreshShare")
			}

		}
		for i, r := range refreshshare.RefreshShareRecrypt.Coeffs {
			if !utils.EqualSliceUint64(resRefreshShare.RefreshShareRecrypt.Coeffs[i], r) {
				log.Fatal("Resulting of marshalling not the same as original : RefreshShare")
			}

		}
	})

	t.Run(fmt.Sprintf("RTG/N=%d/limbQ=%d/limbsP=%d", contextQ.N, len(contextQ.Modulus), len(contextPKeys.Modulus)), func(t *testing.T) {

		//check RTGShare
		crpGenerator := ring.NewCRPGenerator(nil, bfvCtx.ContextKeys())
		modulus := (bfvCtx.ContextQ().Modulus)
		crp := make([]*ring.Poly, len(modulus))
		for j := 0; j < len(modulus); j++ {
			crp[j] = crpGenerator.Clock() //make([]*ring.Poly, bitLog)

		}

		rotProto := NewRotKGProtocol(bfvCtx)
		rtgShare := rotProto.AllocateShare()
		rotProto.GenShare(1, 64, sk.Get(), crp, &rtgShare)

		data, err := rtgShare.MarshalBinary()
		fmt.Println("RTG Data (kB) :", len(data)/1000)
		if err != nil {
			log.Fatal("could not marshal RTGshare :", err)
		}

		resRTGShare := new(RTGShare)
		err = resRTGShare.UnmarshalBinary(data)
		if err != nil {
			log.Fatal("Could not unmarshal RTGShare: ", err)
		}

		if resRTGShare.Type != rtgShare.Type || resRTGShare.K != rtgShare.K || len(resRTGShare.Value) != len(rtgShare.Value) {
			log.Fatal("result after marshalling is not the same as before marshalling for RTGSahre")
		}

		for i, val := range rtgShare.Value {
			ring1 := val
			ring2 := resRTGShare.Value[i]
			if len(ring1.Coeffs) != len(ring2.Coeffs) {
				log.Fatal("result after marshalling is not the same as before marshalling for RTGSahre")
			}

			for j, elem := range ring1.Coeffs {
				if !utils.EqualSliceUint64(ring2.Coeffs[j], elem) {
					log.Fatal("result after marshalling is not the same as before marshalling for RTGSahre")

				}
			}

		}
	})

}

func Test_Relin_Marshalling(t *testing.T) {

	bfvCtx := bfv.NewContextWithParam(&bfv.DefaultParams[1])
	contextQ := bfvCtx.ContextQ()
	contextPKeys := bfvCtx.ContextPKeys()
	modulus := bfvCtx.ContextQ().Modulus

	crpGenerator := ring.NewCRPGenerator(nil, bfvCtx.ContextKeys())

	crp := make([]*ring.Poly, len(modulus))
	for j := 0; j < len(modulus); j++ {
		crp[j] = crpGenerator.Clock() //make([]*ring.Poly, bitLog)
		//for u := uint64(0); u < bitLog; u++ {
		//	crp[j][u] = crpGenerator.Clock()
		//}
	}

	t.Run(fmt.Sprintf("RLKG/N=%d/limbQ=%d/limbsP=%d", contextQ.N, len(contextQ.Modulus), len(contextPKeys.Modulus)), func(t *testing.T) {

		rlk := NewEkgProtocol(bfvCtx)
		u := rlk.NewEphemeralKey(1 / 3.0)
		sk := bfvCtx.NewKeyGenerator().NewSecretKey()
		log.Print("Starting to test marshalling for share one")

		r1, r2, r3 := rlk.AllocateShares()
		rlk.GenShareRoundOne(u, sk.Get(), crp, r1)
		data, err := r1.MarshalBinary()
		fmt.Println("RKG R1 Data (kB) :", len(data)/1000)
		if err != nil {
			log.Print("Error in marshalling round 1 key : ", err)
			t.Fail()
		}

		r1After := new(RKGShareRoundOne)
		err = r1After.UnmarshalBinary(data)
		if err != nil {
			log.Print("Error in unmarshalling round 1 key : ", err)
			t.Fail()
		}

		log.Print("Now comparing keys for round 1 ")

		for i := 0; i < (len(r1)); i++ {
			a := r1[i]
			b := (*r1After)[i]
			for k := 0; k < a.GetLenModuli(); k++ {
				if !utils.EqualSliceUint64(a.Coeffs[k], b.Coeffs[k]) {
					log.Print("Error : coeffs of rings do not match")
					t.Fail()
				}
			}
		}

		log.Print("Sucess : relin key round 1 ok ")

		log.Print("Starting to test marshalling for share two")
		rlk.GenShareRoundTwo(r1, sk.Get(), crp, r2)

		data, err = r2.MarshalBinary()
		fmt.Println("RKG R2 Data (kB) :", len(data)/1000)
		if err != nil {
			log.Print("Error on marshalling relin key round 2 : ", err)
			t.Fail()
		}

		r2After := new(RKGShareRoundTwo)
		err = r2After.UnmarshalBinary(data)
		if err != nil {
			log.Print("Error on unmarshalling relin key round 2 : ", err)
			t.Fail()
		}

		log.Print("Now comparing keys for round 2 ")

		for i := 0; i < (len(r2)); i++ {
			for idx := 0; idx < 2; idx++ {
				a := r2[i][idx]
				b := (*r2After)[i][idx]
				for k := 0; k < a.GetLenModuli(); k++ {
					if !utils.EqualSliceUint64(a.Coeffs[k], b.Coeffs[k]) {
						log.Print("Error : coeffs of rings do not match")
						t.Fail()
					}
				}
			}

		}

		log.Print("Success : reling key round 2 ok ")

		log.Print("Starting to test marshalling for share three")

		rlk.GenShareRoundThree(r2, u, sk.Get(), r3)

		data, err = r3.MarshalBinary()
		fmt.Println("RKG R3 Data (kB) :", len(data)/1000)
		if err != nil {
			log.Print("Error in marshalling round 3 key : ", err)
			t.Fail()
		}

		r3After := new(RKGShareRoundThree)
		err = r3After.UnmarshalBinary(data)
		if err != nil {
			log.Print("Error in unmarshalling round 3 key : ", err)
			t.Fail()
		}

		log.Print("Now comparing keys for round 3 ")

		for i := 0; i < (len(r3)); i++ {
			a := r3[i]
			b := (*r3After)[i]
			for k := 0; k < a.GetLenModuli(); k++ {
				if !utils.EqualSliceUint64(a.Coeffs[k], b.Coeffs[k]) {
					log.Print("Error : coeffs of rings do not match")
					t.Fail()
				}
			}

		}

		log.Print("Success : relin key for round 3 ok ")

		log.Print("All marshalling is passed for relin keys")
	})

}
