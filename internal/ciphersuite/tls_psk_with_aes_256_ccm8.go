package ciphersuite

import (
	"github.com/fredwangwang/dtls/pkg/crypto/ciphersuite"
	"github.com/fredwangwang/dtls/pkg/crypto/clientcertificate"
)

// NewTLSPskWithAes256Ccm8 returns the TLS_PSK_WITH_AES_256_CCM_8 CipherSuite
func NewTLSPskWithAes256Ccm8() *Aes256Ccm {
	return newAes256Ccm(clientcertificate.Type(0), TLS_PSK_WITH_AES_256_CCM_8, true, ciphersuite.CCMTagLength8, KeyExchangeAlgorithmPsk, false)
}
