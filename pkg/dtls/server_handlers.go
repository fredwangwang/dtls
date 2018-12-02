package dtls

import (
	"bytes"
	"fmt"
)

func serverExcludeRules() map[flightVal]handshakeCacheExcludeRule {
	// ClientHello and HelloVerifyRequest MUST NOT be included in the CertificateVerify
	return map[flightVal]handshakeCacheExcludeRule{
		flight0: {isLocal: true, isRemote: true},
		flight1: {isLocal: true, isRemote: true},
		flight2: {isLocal: true, isRemote: false},
	}
}

func serverHandshakeHandler(c *Conn) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	for out, fragEpoch := c.fragmentBuffer.pop(); out != nil; out, fragEpoch = c.fragmentBuffer.pop() {
		rawHandshake := &handshake{}
		if err := rawHandshake.Unmarshal(out); err != nil {
			return err
		}
		c.handshakeCache.push(out, fragEpoch, rawHandshake.handshakeHeader.messageSequence /* isLocal */, false, c.currFlight.get())

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageClientHello:
			if c.currFlight.get() == flight2 {
				if !bytes.Equal(c.cookie, h.cookie) {
					return errCookieMismatch
				}
				c.localSequenceNumber = 1
				c.currFlight.set(flight4)
				break
			}

			c.remoteRandom = h.random
			if len(h.cipherSuites) == 0 {
				return errCipherSuiteNoIntersection
			}
			c.cipherSuite = h.cipherSuites[0]
			c.currFlight.set(flight2)

		case *handshakeMessageCertificate:
			if c.currFlight.get() == flight4 {
				c.remoteCertificate = h.certificate
			}

		case *handshakeMessageClientKeyExchange:
			if c.currFlight.get() == flight4 {
				c.remoteKeypair = &namedCurveKeypair{namedCurveX25519, h.publicKey, nil}

				serverRandom, err := c.localRandom.Marshal()
				if err != nil {
					return err
				}
				clientRandom, err := c.remoteRandom.Marshal()
				if err != nil {
					return err
				}

				preMasterSecret, err := prfPreMasterSecret(c.remoteKeypair.publicKey, c.localKeypair.privateKey, c.localKeypair.curve)
				if err != nil {
					return err
				}

				c.keys = prfEncryptionKeys(prfMasterSecret(preMasterSecret, clientRandom, serverRandom), clientRandom, serverRandom)
				c.remoteGCM, err = newAESGCM(c.keys.clientWriteKey)
				if err != nil {
					return err
				}

				c.localGCM, err = newAESGCM(c.keys.serverWriteKey)
				if err != nil {
					return err
				}
			}

		case *handshakeMessageFinished:
			if c.currFlight.get() == flight4 {
				expectedVerifyData := prfVerifyDataClient(c.keys.masterSecret, c.handshakeCache.combinedHandshake(serverExcludeRules(), true))
				if !bytes.Equal(expectedVerifyData, h.verifyData) {
					return errVerifyDataMismatch
				}
				c.localEpoch = 1
				c.localSequenceNumber = 5
				c.currFlight.set(flight6)
			}

		default:
			return fmt.Errorf("Unhandled handshake %d", h.handshakeType())
		}
	}

	return nil
}

func serverFlightHandler(c *Conn) (bool, error) {
	switch c.currFlight.get() {
	case flight0:
		// Waiting for ClientHello
	case flight2:
		c.lock.RLock()
		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  c.localSequenceNumber,
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				handshakeHeader: handshakeHeader{
					messageSequence: uint16(c.localSequenceNumber),
				},
				handshakeMessage: &handshakeMessageHelloVerifyRequest{
					version: protocolVersion1_2,
					cookie:  c.cookie,
				},
			},
		}, false)
		c.lock.RUnlock()

	case flight4:
		c.lock.RLock()
		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  c.localSequenceNumber,
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				handshakeHeader: handshakeHeader{
					messageSequence: uint16(c.localSequenceNumber),
				},
				handshakeMessage: &handshakeMessageServerHello{
					version:           protocolVersion1_2,
					random:            c.localRandom,
					cipherSuite:       defaultCipherSuites[0],       // TODO: Pick correct cipher suite
					compressionMethod: defaultCompressionMethods[0], // TODO: Pick correct cipher suite
					extensions: []extension{
						&extensionSupportedEllipticCurves{
							ellipticCurves: []namedCurve{namedCurveX25519, namedCurveP256},
						},
						&extensionUseSRTP{
							protectionProfiles: []srtpProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
						},
						&extensionSupportedPointFormats{
							pointFormats: []ellipticCurvePointFormat{ellipticCurvePointFormatUncompressed},
						},
					},
				}},
		}, false)

		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  c.localSequenceNumber + 1,
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				handshakeHeader: handshakeHeader{
					messageSequence: uint16(c.localSequenceNumber + 1),
				},
				handshakeMessage: &handshakeMessageCertificate{
					certificate: c.localCertificate,
				}},
		}, false)

		serverRandom, err := c.localRandom.Marshal()
		if err != nil {
			return false, err
		}
		clientRandom, err := c.remoteRandom.Marshal()
		if err != nil {
			return false, err
		}

		signature, err := generateKeySignature(clientRandom, serverRandom, c.localKeypair.publicKey, namedCurveX25519, c.localPrivateKey)
		if err != nil {
			return false, err
		}

		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  c.localSequenceNumber + 2,
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				handshakeHeader: handshakeHeader{
					messageSequence: uint16(c.localSequenceNumber + 2),
				},
				handshakeMessage: &handshakeMessageServerKeyExchange{
					ellipticCurveType:  ellipticCurveTypeNamedCurve,
					namedCurve:         namedCurveX25519,
					publicKey:          c.localKeypair.publicKey,
					hashAlgorithm:      HashAlgorithmSHA256,
					signatureAlgorithm: signatureAlgorithmECDSA,
					signature:          signature,
				}},
		}, false)

		// TODO: CertificateRequest

		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  c.localSequenceNumber + 3,
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				handshakeHeader: handshakeHeader{
					messageSequence: uint16(c.localSequenceNumber + 3),
				},
				handshakeMessage: &handshakeMessageServerHelloDone{},
			},
		}, false)

		c.lock.RUnlock()

	case flight6:
		c.lock.RLock()
		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  c.localSequenceNumber,
				protocolVersion: protocolVersion1_2,
			},
			content: &changeCipherSpec{},
		}, false)

		if len(c.localVerifyData) == 0 {
			c.localVerifyData = prfVerifyDataServer(c.keys.masterSecret, c.handshakeCache.combinedHandshake(serverExcludeRules(), false))
		}

		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				epoch:           1,
				sequenceNumber:  0, // sequenceNumber restarts per epoch
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				handshakeHeader: handshakeHeader{
					messageSequence: uint16(c.localSequenceNumber), // KeyExchange + 1
				},

				handshakeMessage: &handshakeMessageFinished{
					verifyData: c.localVerifyData,
				}},
		}, true)
		c.lock.RUnlock()

		// Signal handshake completed
		select {
		case <-c.handshakeCompleted:
		default:
			close(c.handshakeCompleted)
		}

		// TODO: Better way to end handshake
		return true, nil
	default:
		return false, fmt.Errorf("Unhandled flight %s", c.currFlight.get())
	}
	return false, nil
}
