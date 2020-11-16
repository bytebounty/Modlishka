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
MIID/TCCAuWgAwIBAgIUJSrsFUJDlbm9CkF49o8TWoN0bOswDQYJKoZIhvcNAQEL
BQAwgY0xCzAJBgNVBAYTAkJSMQswCQYDVQQIDAJTUDELMAkGA1UEBwwCU1AxGjAY
BgNVBAoMEU1lcmNhZG8gTGl2cmUgSW5jMQswCQYDVQQLDAJJVDEVMBMGA1UEAwwM
TWVyY2Fkb2xpdnJlMSQwIgYJKoZIhvcNAQkBFhVoZWxwQG1lcmNhZG9saWJyZS5j
b20wHhcNMjAxMTE2MjIyODE3WhcNMjMwOTA2MjIyODE3WjCBjTELMAkGA1UEBhMC
QlIxCzAJBgNVBAgMAlNQMQswCQYDVQQHDAJTUDEaMBgGA1UECgwRTWVyY2FkbyBM
aXZyZSBJbmMxCzAJBgNVBAsMAklUMRUwEwYDVQQDDAxNZXJjYWRvbGl2cmUxJDAi
BgkqhkiG9w0BCQEWFWhlbHBAbWVyY2Fkb2xpYnJlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALnlh9msLtFKbXtZvRueSiOvoqMaOx/2SaCXXvFi
CBeyiEzL37B8xtiEyxNjhx920HhTSzf/JtMyeVOpihB15Tvn14+ww3uV5A7Ny+bX
zFO31l0mvN2Yu2JMVnWOf/v++y5V5hNBQErsvckyx9uukCmJd99wcXwKH0ySTM/8
vB3qi167iCL0fABw6WLKzR5KVh7lZnwmem6NiI+SLdoimHnjV6CiXv1qY9YfwHel
TXoKOnewcBlTR/sZvic+IYbmI4o2wNojv0ZOoGmSq1Z/K4Pn6K68iBaGop6lpgs3
8ylzqr+RqECa4Q2dF8tws/X+mkBIOfM8foZbsyTE9IU5YOsCAwEAAaNTMFEwHQYD
VR0OBBYEFCY+Q5piVz61rsRBitP3x0MD6nLgMB8GA1UdIwQYMBaAFCY+Q5piVz61
rsRBitP3x0MD6nLgMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AEsgmxNKzY2zlddV00fuUGjmS21MsZxUP8LlYfnssbP6/W8954kfErOutNDNWwN9
TSqaCfonQ5soQunVUxbYXifnoSbfrGX4EVpOBOaV9uPq2PAe8Mhz8M0xYSAJBBnf
Dkcetyi7Ghn6VgggEXfhQu6sWK9PitDVQJ4wr655ER/1hBGhYCNygKteZaENN3Ds
YmGwxFCsTD1T3qKcWo6ARCTaLTKn2JarTJIw4Mt1QT24+2DhlPzSgCoJFO1dGAFh
U6MA2Dbr1V2uSR42kwLZeZH3XrGXU2pHRYrQFhfu0qaI2bHrbIAV31NWU4Eba0dR
WkkNTerUdGgdzDnmg6ModSQ=
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAueWH2awu0Upte1m9G55KI6+ioxo7H/ZJoJde8WIIF7KITMvf
sHzG2ITLE2OHH3bQeFNLN/8m0zJ5U6mKEHXlO+fXj7DDe5XkDs3L5tfMU7fWXSa8
3Zi7YkxWdY5/+/77LlXmE0FASuy9yTLH266QKYl333BxfAofTJJMz/y8HeqLXruI
IvR8AHDpYsrNHkpWHuVmfCZ6bo2Ij5It2iKYeeNXoKJe/Wpj1h/Ad6VNego6d7Bw
GVNH+xm+Jz4hhuYjijbA2iO/Rk6gaZKrVn8rg+forryIFoainqWmCzfzKXOqv5Go
QJrhDZ0Xy3Cz9f6aQEg58zx+hluzJMT0hTlg6wIDAQABAoIBACl0pWoGet5TgbzL
U1/QWepBZbyHwf2rt9mnSBX+bZ2TQ9AUewrpmJJ6cqsdO+npXi4nLRQMw4S/sczV
dyOalwdX+XtiyQVLdPNUM4+EOl3FFnnphJ7KS6dtLK7Em4f/4dYAc/GBUKwkxWIT
//venumUbXYXpkcqHra9vYF4dB8baCIG8YfH3qFUOkwh8j80WWCCcEPDgfQV6i/J
hQJoabP6nS5OG1EfxnDuG/9e8yvqN8CsGWFrtH1UmHsjVzr9AvkWtV8STRn6Q6y1
kKV8JTqZykgBgrlL6H1R8ZRGWGWM6Ou9oJsR+wNCvKuIwFhWYhxi/LvkIzEPxjg3
MpoZxckCgYEA8vrX94qhrK0ROmdB8KsSl3dd1V+tunYJjnGP66sfJdwDIuaJ0B+N
cORCN6nrJIyd3hjI9kh3BYzSpzd9m2QICg0Xt8CMuozP5ZuPMugXdKuT0898+B2V
uWOyQ7QaHoYvIXuVCKOtTrkNfACu4uZyrGYRenV9fl8YjEvXZdsAymUCgYEAw9ug
8NWJJ9Txpyn7wtazGfyS/cvHPsKwvmjX6GWIvpPryAo+yP/BYtOEgCRmBRL0K44L
A/CdqHHd9dpeKezF7YVt9KmPzHmbW3tVKPWL8V8Lq+IbaeDB76wZHaw6tAG+uKc0
7qJUjFXlhuhsGB9i1ACgEjR+0dHEHnUPfU0UoQ8CgYEAxoTt+MDacQOBxO7icCjF
at1K2+9tOKACFNBx3wGT1FHaeiRTSqjM3gSQmXwJs3Xz8abcYmQ4Yl95KMfspw3m
h5fE3gvCrxQnM5iSOexoZZldkTvABdPeJXbwCeLXSEMntLqMvF9GVMBa5QqF2Lqh
zHskIqJlot89Zjr8xKpXDgUCgYEAl1K6rzicpszNBHXYkbomWN6fhz2JrMDpo8QH
hQPlujE5i632wn9wH/YCuqrks+joBDrT4fBnLz0C3DAibswERLbBtLXJZ5dRZEYP
Dv1gaVYhA2VH/u7riEz0fsuR84AhpjNyHyoGnwLCuxAabCzbw6bUBhzPGzeyCkIx
fIMwfBsCgYBD6V0MMlDvznBIUC+H06/eUsw5aJTJ2D2w5fEIZwK9umnhkmLhcKAW
TStoqgi8HnGODLXMLfTUIfEwyYJ0nomHlv8URLnHAmNiBF+QA04YT6cgU2cG/wUW
COyWjHk8CMCvat5QTCfnXGkvGLnE5gpZiahVUzMopzj1fX2HEHVG8Q==
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
