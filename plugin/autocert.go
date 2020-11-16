/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/drk1wi/Modlishka/config"
	"github.com/drk1wi/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/drk1wi/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----
MIIFXTCCBEWgAwIBAgISA8sxdp8aZgb9J5JYiSKe9nYQMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDExMTUxNzEyMDNaFw0y
MTAyMTMxNzEyMDNaMB4xHDAaBgNVBAMMEyoudHJkdHJhbnNwb3J0ZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtrk7pt57dtA+o2MVrWB3GZFqm
sZfxU/iZ5ilNDlsEjWiMaCCzldbAb0uAnXietytlSk6ufUmAaElAJk8Tze0M9tnN
gaEa0Nq4/YYdwfzLp0/vIkNwhHniteyaBDaIJVruBOvuhPC/G/urT6lMdDv8Ek5z
7UfJz7krMSRve2E2hKsXtwOJk8bLsgEmrebSGs09NP+vQfKf+mid6YS+8/INhdxu
Zh6LPcJsqzWu/xZVICGfIpiE32my52J3BBWLGo14jTQuO9NlJNSYAxGC3cm6un86
TavJy4zu6l3sVN5pkgXr8zC5XU3Afhlj4w+YPW41+IV895Ki6Tbn78UBFnARAgMB
AAGjggJnMIICYzAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGf9QuAvvRI375RHETzM
+Clq8BhIMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUF
BwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZy8wHgYDVR0RBBcwFYITKi50cmR0cmFuc3BvcnRlLmNvbTBMBgNVHSAE
RTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIBFhpodHRw
Oi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2
AG9Tdqwx8DEZ2JkApFEV/3cVHBHZAsEAKQaNsgiaN9kTAAABdc0bW6kAAAQDAEcw
RQIgHS0sF5w1UznmH48VfEkUYIXAvG/p4cFvKoCihkUD1rACIQCE+00SAn2DKXTx
35AeTb51TP68W6sGy59lXnRW4LXqxQB1AH0+8viP/4hVaCTCwMqeUol5K8UOeAl/
LmqXaJl+IvDXAAABdc0bW40AAAQDAEYwRAIgaJZQXw6BQA+K7bGi56AjsHbJqqiI
g+PIg+pBvkDdjzECICgR8fe0hPp6Nml4IBmMjS6b2VxXAL3pmSWSAO4dZMWQMA0G
CSqGSIb3DQEBCwUAA4IBAQBxMrlt2Khzzjd0r7VX3W8c+qoACz/FLOIQJBLaEiwR
czbcIQU6houq1o+vqXdqlAzon5di26TaJHahdp7cYuoUFUsjKU3wokJtmVVy66zt
QUciPgMWYzYwm90KATPAUCfgG5LWiMwULWKpDeMEAtSVKqTpCPS4WNHwglmQOiMR
n3Tj4k36xjWluXoINioQD2vJHWgvx1v3XNwnnA2LGCQnhft/0EwAoyl11LEry14Z
sQoV7owIIa1A6sZxUNe8eLr/PZpNiIBv0Gz3xnMYTxzKEmEJD1UwaliTCncsfr4d
IQ6iu+U1rfIqaLmBUb4J9h4+1o/Ny4RSeqZFtdlkvrJ4
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCtrk7pt57dtA+o
2MVrWB3GZFqmsZfxU/iZ5ilNDlsEjWiMaCCzldbAb0uAnXietytlSk6ufUmAaElA
Jk8Tze0M9tnNgaEa0Nq4/YYdwfzLp0/vIkNwhHniteyaBDaIJVruBOvuhPC/G/ur
T6lMdDv8Ek5z7UfJz7krMSRve2E2hKsXtwOJk8bLsgEmrebSGs09NP+vQfKf+mid
6YS+8/INhdxuZh6LPcJsqzWu/xZVICGfIpiE32my52J3BBWLGo14jTQuO9NlJNSY
AxGC3cm6un86TavJy4zu6l3sVN5pkgXr8zC5XU3Afhlj4w+YPW41+IV895Ki6Tbn
78UBFnARAgMBAAECggEAFenxYQHfFKAcfbRkLGgg0aBl47RytGtg6aIlweg2ybtB
3r1gqugUAZHJWAAGcRgxbIVUqiV6ua3u2B49SgVojIM09f4OIsEJZ9/tJSIN0HBa
4JRVKAQ/EMDdio1PiBwWfgO29RBnA+X2+iWB+fiMfQCeT3g335nLBk0cCMjreiJL
u165FmfqN7hHVyzk5Wv6IKrB9Zmf4hlTPAmqKlUhg5LONTnd6YenUFVinpm2amF2
8Qrp1ukkbhFXaweQFbOpr/Icb+N4Feu0HydC4V2kDmfln16LWkfFpE54QUJHRCCO
G5mTveChKto/iivXYbj3nxy5XsIqBL/8ThS0945OpQKBgQDmpT8gbGIm59uIYaYA
UyLAsBtvvULqaCDJOhFDLVP1vKq2VYYZXScbQK80i13jBThTq0XI/h7yo/uw5hca
4cSXoFXlx8mXUgaFhmBL8XTHGBqHIy+Nvl+qMCSyBulnzLXE4r4b4kv0bWP8JFaa
83+ZCpdPMlLGKoE6F8m641M46wKBgQDAxftLQZIS0jTtAbQHvHUbPJwor5ofKtdC
aK1u/FzHQuI22FLAAV29Xqxw9qq8PayhwiWZUpYiMXJxcEO5BSsCFeSCkOzFbX6H
M7W3tb1sJGAheWhF1RWi58In3UrBHlYh4uu6nIszwaTMZrsf7BdbALUggzB2MLR8
TNng/pv78wKBgQDFrEp2F23nuj9Em6wSCy51xnk9Qw/epm+zBrlUwbx7l78XliTg
CB5EFSQT/H3y275ytw+QO3t6qWBFNG4I9AXxjdEQpjH4JqzAM3LEo6RaHiZeO6G9
8bM7wRcyHQpdk+0VWN9mNoSycC6JIvu2wYpSN+mGTrLyc+tdRpX2Pm5NEQKBgQCN
/sd1zZzdhD07/y8vK6BPKbwVNBQgtRvObPCjefyVQi0DHSEHEXqNDPmUU/27nupU
VIABihXQpf+Yk4su9CGT7bBehIYDfv3edTZ7VcFrsPemcJlgJu9DCde4KYbw7Xmg
iFf/I2ReAVt0vI9FmlAx1jmU8011IbcwgCNVWfZoBQKBgH6md/e5WqoxfpnB5AgB
Vh7Of2GA9cMw23FOXHZd1aOjGt5LroI4gnC8KmNcm6TDLe4019i92x3ITJlcXNbZ
QcovlUK6oCizWhRarCO2g82jkng41DrlldjwVzMLDTwGVZ16hIaHHDrH8J3iPu2Y
N7Z3rcEbq93PnCbIk7qO2E1J
-----END PRIVATE KEY-----`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate",*config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(5, 5, 5),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}
