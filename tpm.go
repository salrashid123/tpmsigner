// Creates a crypto.Signer() for TPM based credentials
//   Support RSA, ECC and keys with policiyPCR
// Also fulfils TLSCertificate() interface for use with TLS

package tpmsigner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const ()

// Configures and manages Singer configuration
//

type TPM struct {
	_ crypto.Signer
	//_ crypto.MessageSigner // introduced in https://tip.golang.org/doc/go1.25#cryptopkgcrypto

	ECCRawOutput bool // for ECC keys, output raw signatures. If false, signature is ans1 formatted
	refreshMutex sync.Mutex

	// X509Certificate raw x509 certificate for the signer. Used for TLS
	X509Certificate *x509.Certificate // public x509 certificate for the signer
	publicKey       crypto.PublicKey
	tpmPublic       tpm2.TPMTPublic

	//NamedHandle      *tpm2.NamedHandle  // the name handle to the key to use
	Handle           tpm2.TPMHandle // the name handle to the key to use
	name             tpm2.TPM2BName
	AuthSession      Session            // If the key needs a session, supply `Session` from this repo
	TpmDevice        io.ReadWriteCloser // TPM read closer
	EncryptionHandle tpm2.TPMHandle     // (optional) handle to use for transit encryption
}

// Configure a new TPM crypto.Signer

func NewTPMCrypto(conf *TPM) (TPM, error) {

	if conf.TpmDevice == nil {
		return TPM{}, fmt.Errorf("salrashid123/signer: TpmDevice must be specified")
	}

	rwr := transport.FromReadWriter(conf.TpmDevice)

	// todo: we should supply the encrypted session here, if set
	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMIDHObject(conf.Handle.HandleValue()),
	}.Execute(rwr)
	if err != nil {
		return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public data from TPM: %v", err)
	}
	conf.name = pub.Name

	pc, err := pub.OutPublic.Contents()
	if err != nil {
		return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public content TPM: %v", err)
	}
	conf.tpmPublic = *pc
	if pc.Type == tpm2.TPMAlgRSA {
		rsaDetail, err := pc.Parameters.RSADetail()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public rsa parameters TPM: %v", err)
		}

		rsaUnique, err := pc.Unique.RSA()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public rsa unique TPM: %v", err)
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to create RSAPublic TPM: %v", err)
		}

		conf.publicKey = rsaPub
	} else if pc.Type == tpm2.TPMAlgECC {
		ecDetail, err := pc.Parameters.ECCDetail()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public ec parameters TPM: %v", err)
		}
		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public ec curve TPM: %v", err)
		}
		eccUnique, err := pc.Unique.ECC()
		if err != nil {
			return TPM{}, fmt.Errorf("salrashid123/signer: Unable to Read Public ec unique TPM: %v", err)
		}
		conf.publicKey = &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
	} else {
		return TPM{}, fmt.Errorf("salrashid123/signer: Unsupported key type: %v", pc.Type)
	}

	return *conf, nil
}

func (t TPM) Public() crypto.PublicKey {
	return t.publicKey
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	rwr := transport.FromReadWriter(t.TpmDevice)

	var sess []tpm2.Session

	if t.EncryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: t.EncryptionHandle,
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		ePubName, err := encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, err
		}
		sess = append(sess, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(t.EncryptionHandle, *ePubName)))
	} else {
		sess = append(sess, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn)))
	}

	var algid tpm2.TPMIAlgHash

	if opts == nil {
		algid = tpm2.TPMAlgSHA256
	} else {
		if opts.HashFunc() == crypto.SHA256 {
			algid = tpm2.TPMAlgSHA256
		} else if opts.HashFunc() == crypto.SHA384 {
			algid = tpm2.TPMAlgSHA384
		} else if opts.HashFunc() == crypto.SHA512 {
			algid = tpm2.TPMAlgSHA512
		} else {
			return nil, fmt.Errorf("signer: unknown hash function %v", opts.HashFunc())
		}
	}

	var se tpm2.Session
	if t.AuthSession != nil {
		var err error
		var closer func() error
		se, closer, err = t.AuthSession.GetSession()
		if err != nil {
			return nil, fmt.Errorf("signer: error getting session %s", err)
		}
		defer closer()
		if se.IsDecryption() {
			sess = nil
		}
	} else {
		se = tpm2.PasswordAuth(nil)
	}

	var tsig []byte
	switch t.publicKey.(type) {
	case *rsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("signer: can't error getting rsa details %v", err)
		}
		sigScheme := rd.Scheme.Scheme
		_, ok := opts.(*rsa.PSSOptions)
		if ok {
			switch sigScheme {
			case tpm2.TPMAlgNull:
				sigScheme = tpm2.TPMAlgRSAPSS
			case tpm2.TPMAlgRSASSA:
				return nil, fmt.Errorf("signer: error TPM Key has TPMAlgRSASSA signature defined while PSSOption was requested")
			}
		} else {
			switch sigScheme {
			case tpm2.TPMAlgNull:
				sigScheme = tpm2.TPMAlgRSASSA // default signature scheme if no signerOpts are specified and the tpm key itself is null
			case tpm2.TPMAlgRSAPSS:
				return nil, fmt.Errorf("signer: error TPM Key has TPMAlgRSAPSS signature defined while no PSSOption was requested")
			}
		}

		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: t.Handle,
				Name:   t.name,
				Auth:   se,
			},

			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: sigScheme,
				Details: tpm2.NewTPMUSigScheme(sigScheme, &tpm2.TPMSSchemeHash{
					HashAlg: algid,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(rwr, sess...)
		if err != nil {
			return nil, fmt.Errorf("signer: can't Sign: %v", err)
		}

		var rsig *tpm2.TPMSSignatureRSA
		switch rspSign.Signature.SigAlg {
		case tpm2.TPMAlgRSASSA:
			rsig, err = rspSign.Signature.Signature.RSASSA()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa ssa signature: %v", err)
			}
		case tpm2.TPMAlgRSAPSS:
			rsig, err = rspSign.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa pss signature: %v", err)
			}
		default:
			return nil, fmt.Errorf("signer: unsupported signature algorithm't Sign: %v", err)
		}

		tsig = rsig.Sig.Buffer
	case *ecdsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: t.Handle,
				Name:   t.name,
				Auth:   se,
			},

			Digest: tpm2.TPM2BDigest{
				Buffer: digest[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rd.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(rd.Scheme.Scheme, &tpm2.TPMSSchemeHash{
					HashAlg: algid,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(rwr, sess...)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: can't Sign: %v", err)
		}

		rsig, err := rspSign.Signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: error getting ecc signature: %v", err)
		}
		if t.ECCRawOutput {
			tsig = append(rsig.SignatureR.Buffer, rsig.SignatureS.Buffer...)
		} else {
			r := big.NewInt(0).SetBytes(rsig.SignatureR.Buffer)
			s := big.NewInt(0).SetBytes(rsig.SignatureS.Buffer)
			sigStruct := struct{ R, S *big.Int }{r, s}
			return asn1.Marshal(sigStruct)
		}
	}
	return tsig, nil
}

func (t TPM) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	rwr := transport.FromReadWriter(t.TpmDevice)

	var sess []tpm2.Session

	if t.EncryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: t.EncryptionHandle,
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		ePubName, err := encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, err
		}
		sess = append(sess, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(t.EncryptionHandle, *ePubName)))
	} else {
		sess = append(sess, tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn)))
	}

	var tpmHalg tpm2.TPMIAlgHash

	if opts == nil {
		tpmHalg = tpm2.TPMAlgSHA256
	} else {
		if opts.HashFunc() == crypto.SHA256 {
			tpmHalg = tpm2.TPMAlgSHA256
		} else if opts.HashFunc() == crypto.SHA384 {
			tpmHalg = tpm2.TPMAlgSHA384
		} else if opts.HashFunc() == crypto.SHA512 {
			tpmHalg = tpm2.TPMAlgSHA512
		} else {
			return nil, fmt.Errorf("signer: unknown hash function %v", opts.HashFunc())
		}
	}

	maxDigestBuffer := 1024
	var hsh []byte
	var val []byte

	if len(msg) > maxDigestBuffer {
		pss := make([]byte, 32)
		_, err := rand.Read(pss)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: failed to generate random for hash %v", err)
		}

		rspHSS, err := tpm2.HashSequenceStart{
			Auth: tpm2.TPM2BAuth{
				Buffer: pss,
			},
			HashAlg: tpmHalg,
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: failed to generate hash from TPM HashSequenceStart %v", err)
		}

		authHandle := tpm2.AuthHandle{
			Handle: rspHSS.SequenceHandle,
			Name: tpm2.TPM2BName{
				Buffer: pss,
			},
			Auth: tpm2.PasswordAuth(pss),
		}

		for len(msg) > maxDigestBuffer {
			_, err := tpm2.SequenceUpdate{
				SequenceHandle: authHandle,
				Buffer: tpm2.TPM2BMaxBuffer{
					Buffer: msg[:maxDigestBuffer],
				},
			}.Execute(rwr, sess...)
			if err != nil {
				return nil, fmt.Errorf("tpmjwt: failed to generate hash SequenceUpdate  %v", err)
			}

			msg = msg[maxDigestBuffer:]
		}

		rspSC, err := tpm2.SequenceComplete{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: msg,
			},
			Hierarchy: tpm2.TPMRHEndorsement,
		}.Execute(rwr, sess...)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: failed to generate hash from TPM SequenceComplete %v", err)
		}

		hsh = rspSC.Result.Buffer
		val = rspSC.Validation.Digest.Buffer
	} else {
		h, err := tpm2.Hash{
			Hierarchy: tpm2.TPMRHEndorsement,
			HashAlg:   tpmHalg,
			Data: tpm2.TPM2BMaxBuffer{
				Buffer: msg,
			},
		}.Execute(rwr, sess...)
		if err != nil {
			return nil, fmt.Errorf("tpmjwt: failed to generate hash from TPM %v", err)
		}

		hsh = h.OutHash.Buffer
		val = h.Validation.Digest.Buffer
	}
	var se tpm2.Session
	if t.AuthSession != nil {
		var err error
		var closer func() error
		se, closer, err = t.AuthSession.GetSession()
		if err != nil {
			return nil, fmt.Errorf("signer: error getting session %s", err)
		}
		defer closer()
		if se.IsDecryption() {
			sess = nil
		}
	} else {
		se = tpm2.PasswordAuth(nil)
	}

	var tsig []byte
	switch t.publicKey.(type) {
	case *rsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("signer: can't error getting rsa details %v", err)
		}
		sigScheme := rd.Scheme.Scheme
		_, ok := opts.(*rsa.PSSOptions)
		if ok {
			if sigScheme == tpm2.TPMAlgNull {
				sigScheme = tpm2.TPMAlgRSAPSS
			}
			if sigScheme == tpm2.TPMAlgRSASSA {
				return nil, fmt.Errorf("signer: error TPM Key has TPMAlgRSASSA signature defined while PSSOption was requested")
			}
		} else {
			if sigScheme == tpm2.TPMAlgNull {
				sigScheme = tpm2.TPMAlgRSASSA // default signature scheme if no signerOpts are specified and the tpm key itself is null
			}
		}

		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: t.Handle,
				Name:   t.name,
				Auth:   se,
			},

			Digest: tpm2.TPM2BDigest{
				Buffer: hsh[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: sigScheme,
				Details: tpm2.NewTPMUSigScheme(sigScheme, &tpm2.TPMSSchemeHash{
					HashAlg: tpmHalg,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag:       tpm2.TPMSTHashCheck,
				Hierarchy: tpm2.TPMRHEndorsement,
				Digest: tpm2.TPM2BDigest{
					Buffer: val,
				},
			},
		}.Execute(rwr, sess...)
		if err != nil {
			return nil, fmt.Errorf("signer: can't Sign: %v", err)
		}

		var rsig *tpm2.TPMSSignatureRSA
		switch rspSign.Signature.SigAlg {
		case tpm2.TPMAlgRSASSA:
			rsig, err = rspSign.Signature.Signature.RSASSA()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa ssa signature: %v", err)
			}
		case tpm2.TPMAlgRSAPSS:
			rsig, err = rspSign.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("signer: error getting rsa pss signature: %v", err)
			}
		default:
			return nil, fmt.Errorf("signer: unsupported signature algorithm't Sign: %v", err)
		}

		tsig = rsig.Sig.Buffer
	case *ecdsa.PublicKey:
		rd, err := t.tpmPublic.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("signer: can't error getting rsa details %v", err)
		}
		rspSign, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: t.Handle,
				Name:   t.name,
				Auth:   se,
			},

			Digest: tpm2.TPM2BDigest{
				Buffer: hsh[:],
			},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: rd.Scheme.Scheme,
				Details: tpm2.NewTPMUSigScheme(rd.Scheme.Scheme, &tpm2.TPMSSchemeHash{
					HashAlg: tpmHalg,
				}),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag:       tpm2.TPMSTHashCheck,
				Hierarchy: tpm2.TPMRHEndorsement,
				Digest: tpm2.TPM2BDigest{
					Buffer: val,
				},
			},
		}.Execute(rwr, sess...)
		if err != nil {
			return nil, fmt.Errorf("signer: can't Sign: %v", err)
		}

		rsig, err := rspSign.Signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("signer: error getting ecc signature: %v", err)
		}
		if t.ECCRawOutput {
			tsig = append(rsig.SignatureR.Buffer, rsig.SignatureS.Buffer...)
		} else {
			r := big.NewInt(0).SetBytes(rsig.SignatureR.Buffer)
			s := big.NewInt(0).SetBytes(rsig.SignatureS.Buffer)
			sigStruct := struct{ R, S *big.Int }{r, s}
			return asn1.Marshal(sigStruct)
		}
	}
	return tsig, nil
}

func (t TPM) TLSCertificate() (tls.Certificate, error) {

	if t.X509Certificate == nil {
		return tls.Certificate{}, fmt.Errorf("X509Certificate cannot be nil if used for TLS")
	}

	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        t.X509Certificate,
		Certificate: [][]byte{t.X509Certificate.Raw},
	}, nil
}

type Session interface {
	GetSession() (auth tpm2.Session, closer func() error, err error) // this supplies the session handle to the library
}

// for pcr sessions
type PCRSession struct {
	rwr              transport.TPM
	sel              []tpm2.TPMSPCRSelection
	digest           tpm2.TPM2BDigest
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PCRSession)(nil)

// Sets up a PCR session.  THe digest parameter signals what PCR digest to expect explicitly.
// Normally, just setting the pcr bank numbers (i.e tpm2.TPMSPCRSelection) will enforce pcr compliance
//
//	useing the original PCR values the key was bound to
//
// If you specify the pcrselection and digest, the digest value you specify is checked explictly vs implictly.
//
//	The digest value lets you 'see' the digest the key is bound to upfront.
//	if the digest is incorrect, you'll see
//	  "tpmjwt: error getting session TPM_RC_VALUE (parameter 1): value is out of range or is not correct for the context"
func NewPCRSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, digest tpm2.TPM2BDigest, encryptionHandle tpm2.TPMHandle) (PCRSession, error) {
	return PCRSession{rwr, sel, digest, encryptionHandle}, nil
}

func (p PCRSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pcr_sess tpm2.Session
	var pcr_cleanup func() error

	if p.encryptionHandle != 0 {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}

	return pcr_sess, pcr_cleanup, nil
}

// for password sessions
type PasswordAuthSession struct {
	rwr              transport.TPM
	password         []byte
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PasswordAuthSession)(nil)

func NewPasswordAuthSession(rwr transport.TPM, password []byte, encryptionHandle tpm2.TPMHandle) (PasswordAuthSession, error) {
	return PasswordAuthSession{rwr, password, encryptionHandle}, nil
}

func (p PasswordAuthSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	c := func() error { return nil }
	return tpm2.PasswordAuth(p.password), c, nil
}

// for password sessions
type PolicyPasswordSession struct {
	rwr              transport.TPM
	password         []byte
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PolicyPasswordSession)(nil)

func NewPolicyPasswordSession(rwr transport.TPM, password []byte, encryptionHandle tpm2.TPMHandle) (PolicyPasswordSession, error) {
	return PolicyPasswordSession{rwr, password, encryptionHandle}, nil
}

func (p PolicyPasswordSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}
	// tpm2.Salted(p.encryptionHandle, *ePubName)
	sess, c, err := tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password)), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(p.encryptionHandle, *ePubName)}...)
	if err != nil {
		return nil, nil, err
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, c, err
	}

	return sess, c, nil
}

type PolicyAuthValueDuplicateSelectSession struct {
	rwr              transport.TPM
	password         []byte
	dupEKName        tpm2.TPM2BName
	encryptionHandle tpm2.TPMHandle
}

func NewPolicyAuthValueAndDuplicateSelectSession(rwr transport.TPM, password []byte, dupEKName tpm2.TPM2BName, encryptionHandle tpm2.TPMHandle) (PolicyAuthValueDuplicateSelectSession, error) {
	return PolicyAuthValueDuplicateSelectSession{rwr, password, dupEKName, encryptionHandle}, nil
}

func (p PolicyAuthValueDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pa_sess tpm2.Session
	var pa_cleanup func() error

	if p.encryptionHandle != 0 {
		pa_sess, pa_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pa_sess, pa_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, pa_cleanup, err
	}

	papgd, err := tpm2.PolicyGetDigest{
		PolicySession: pa_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, pa_cleanup, err
	}
	err = pa_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var dupselect_sess tpm2.Session
	var dupselect_cleanup func() error
	// as the "new parent"

	if p.encryptionHandle != 0 {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: tpm2.TPM2BName(p.dupEKName),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var or_sess tpm2.Session
	var or_cleanup func() error
	// now create an OR session with the two above policies above

	if p.encryptionHandle != 0 {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password)), tpm2.Salted(p.encryptionHandle, *ePubName)}...)
		if err != nil {
			return nil, nil, err
		}
	} else {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: or_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}
	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{papgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	return or_sess, or_cleanup, nil
}

type PCRAndDuplicateSelectSession struct {
	rwr              transport.TPM
	sel              []tpm2.TPMSPCRSelection
	digest           tpm2.TPM2BDigest
	password         []byte
	dupEKName        tpm2.TPM2BName
	encryptionHandle tpm2.TPMHandle
}

func NewPCRAndDuplicateSelectSession(rwr transport.TPM, sel []tpm2.TPMSPCRSelection, digest tpm2.TPM2BDigest, password []byte, dupEKName tpm2.TPM2BName, encryptionHandle tpm2.TPMHandle) (PCRAndDuplicateSelectSession, error) {
	return PCRAndDuplicateSelectSession{rwr, sel, digest, password, dupEKName, encryptionHandle}, nil
}

func (p PCRAndDuplicateSelectSession) GetSession() (auth tpm2.Session, closer func() error, err error) {

	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pcr_sess tpm2.Session
	var pcr_cleanup func() error

	if p.encryptionHandle != 0 {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: pcr_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}

	pcrpgd, err := tpm2.PolicyGetDigest{
		PolicySession: pcr_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}
	err = pcr_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var dupselect_sess tpm2.Session
	var dupselect_cleanup func() error
	// as the "new parent"

	if p.encryptionHandle != 0 {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		dupselect_sess, dupselect_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyDuplicationSelect{
		PolicySession: dupselect_sess.Handle(),
		NewParentName: tpm2.TPM2BName(p.dupEKName),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}

	// calculate the digest
	dupselpgd, err := tpm2.PolicyGetDigest{
		PolicySession: dupselect_sess.Handle(),
	}.Execute(p.rwr)
	if err != nil {
		return nil, dupselect_cleanup, err
	}
	err = dupselect_cleanup()
	if err != nil {
		return nil, nil, err
	}

	var or_sess tpm2.Session
	var or_cleanup func() error
	// now create an OR session with the two above policies above

	if p.encryptionHandle != 0 {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password)), tpm2.Salted(p.encryptionHandle, *ePubName)}...)
		if err != nil {
			return nil, nil, err
		}
	} else {
		or_sess, or_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(p.password))}...)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: or_sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: p.sel,
		},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	_, err = tpm2.PolicyOr{
		PolicySession: or_sess.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{pcrpgd.PolicyDigest, dupselpgd.PolicyDigest}},
	}.Execute(p.rwr)
	if err != nil {
		return nil, or_cleanup, err
	}

	return or_sess, or_cleanup, nil
}

type PolicySecretSession struct {
	rwr              transport.TPM
	authHandle       tpm2.AuthHandle
	encryptionHandle tpm2.TPMHandle
}

var _ Session = (*PolicySecretSession)(nil)

func NewPolicySecretSession(rwr transport.TPM, authHandle tpm2.AuthHandle, encryptionHandle tpm2.TPMHandle) (PolicySecretSession, error) {
	return PolicySecretSession{rwr, authHandle, encryptionHandle}, nil
}

func (p PolicySecretSession) GetSession() (auth tpm2.Session, closer func() error, err error) {
	var ePubName *tpm2.TPMTPublic
	if p.encryptionHandle != 0 {
		encryptionPub, err := tpm2.ReadPublic{
			ObjectHandle: p.encryptionHandle,
		}.Execute(p.rwr)
		if err != nil {
			return nil, nil, err
		}
		ePubName, err = encryptionPub.OutPublic.Contents()
		if err != nil {
			return nil, nil, err
		}
	}

	var pcr_sess tpm2.Session
	var pcr_cleanup func() error

	if p.encryptionHandle != 0 {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(p.encryptionHandle, *ePubName))
		if err != nil {
			return nil, nil, err
		}
	} else {
		pcr_sess, pcr_cleanup, err = tpm2.PolicySession(p.rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicySecret{
		PolicySession: pcr_sess.Handle(),
		AuthHandle:    p.authHandle,
	}.Execute(p.rwr)
	if err != nil {
		return nil, pcr_cleanup, err
	}

	return pcr_sess, pcr_cleanup, nil
}
