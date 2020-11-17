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
MIIE4zCCA8ugAwIBAgIUHkc6QdTcqvwlA5XsXaW1nKUp6JwwDQYJKoZIhvcNAQEL
BQAwgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQw
MgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9y
aXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MB4XDTIwMTExNzEzMDIwMFoXDTIxMTExNzEzMDIwMFowYjEZMBcGA1UEChMQQ2xv
dWRGbGFyZSwgSW5jLjEdMBsGA1UECxMUQ2xvdWRGbGFyZSBPcmlnaW4gQ0ExJjAk
BgNVBAMTHUNsb3VkRmxhcmUgT3JpZ2luIENlcnRpZmljYXRlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyNLttgiaJBcJfgzglVFaTy89SzIJkBsPTxCU
TPNWbW/WvF9I3HPpBr11LrektWnkJZEti/vVmYOzId5aKpFxIPRAKhBqczV6agUh
wQpIvQc0En7DBS/TqU3/n6OLdjLsndYDwXmyYMVg9MpTFR+F926AesNsFJfJ6e51
LQn2LdEHLAn17vWpdowfbqtANjhm2L6GbZV3gWPwvzRhVnZHJoHaz6Pia8i18jCD
MwFfwIsZaBY6vqqqCzJ+i65zHt7YO7/26NaSs2Am2yRninA8wgbputpFftfsr2xi
qEbWTky5oNN6kVk1xQheCPcnuO05cv+p7jf+p8xfTQatwJYvWwIDAQABo4IBZTCC
AWEwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRDPqr5dBrk4ktPo+q1Chl0j0DNDTAf
BgNVHSMEGDAWgBQk6FNXXXw0QIep65TbuuEWePwppDBABggrBgEFBQcBAQQ0MDIw
MAYIKwYBBQUHMAGGJGh0dHA6Ly9vY3NwLmNsb3VkZmxhcmUuY29tL29yaWdpbl9j
YTBmBgNVHREEXzBdghoqLmNvbS5ici50cmR0cmFuc3BvcnRlLmNvbYIXKi5jb20u
dHJkdHJhbnNwb3J0ZS5jb22CEyoudHJkdHJhbnNwb3J0ZS5jb22CEXRyZHRyYW5z
cG9ydGUuY29tMDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly9jcmwuY2xvdWRmbGFy
ZS5jb20vb3JpZ2luX2NhLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAazmwz1dvPmea
5tpp/gQ0clGUMWNXqgzEPFz2BDuRA8qm/lUAQbs7RTkxSb/fdUrpakxtYuTMj47Y
laCqx1Z7zZF43TxfP0XHFfXQE3u2jvmGuIiod8Q8h+wD79MWVhvYa2qXKIJCeysS
mgiialSenxsP9+26m4jlDEPtKIu9JxYKG377QdPo4+JBJQHWvFoXQr3AI//RquwC
Cf08k7vSTPyP9PAY2W6HTepD7Nfoy3sSIZm3GQMU/dMMf4LDZG/1o69rZcdzEiKe
ndIEtJ7XoLvwnOrt3qCug8U27a0NE1QdsPZc1bg6d72TapLGY4TapAic/VI+e4XT
rJICxO8Nzg==
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDI0u22CJokFwl+
DOCVUVpPLz1LMgmQGw9PEJRM81Ztb9a8X0jcc+kGvXUut6S1aeQlkS2L+9WZg7Mh
3loqkXEg9EAqEGpzNXpqBSHBCki9BzQSfsMFL9OpTf+fo4t2Muyd1gPBebJgxWD0
ylMVH4X3boB6w2wUl8np7nUtCfYt0QcsCfXu9al2jB9uq0A2OGbYvoZtlXeBY/C/
NGFWdkcmgdrPo+JryLXyMIMzAV/AixloFjq+qqoLMn6LrnMe3tg7v/bo1pKzYCbb
JGeKcDzCBum62kV+1+yvbGKoRtZOTLmg03qRWTXFCF4I9ye47Tly/6nuN/6nzF9N
Bq3Ali9bAgMBAAECggEAOcBCoNMHdLJ1RdzxJq9+73+PulSY4GqPs/Z6F0jxBUag
s4oZO2BP1mLcVIN2J79cXxtJRFS2/88aT/aP6mbp6AalfxM6cYgi/GMealOJSGbO
aDUw4wh2b10hUiinXeXWGqulZ9mV3PNV5v9Z9hybG2UZKHSTW7as14t+AeY398N9
2HoV4tGxMVsgAqcIseLvzNj1mzX5FiVYP8DvqdaWe78nWLuoqoSoj8np0ZkpDQuc
EjaGbliwqVDCMh+h4emV7gEc0/NBLWFyCQL+ytIEn5xDgsVxvTwFmjs9jkBorDja
RpqyoudOqn5enOM2tkl0nLol7016D6VARyIKkY/NVQKBgQD/t9Hh0OQN3Qn0omVE
agaRz4jpIYYvevCk5pMHpZNHwdao37VqRj4B5KLaFfxMO+Ja+1aK2R3uxjc//yMV
7HZLn2k33SyK2Uw5nU3dC63VH1DvBuBn28W4XF4xTT2EHfK4kMkd5XSfm0dEu9qd
+9FSHiItpgIb7SKIzBCI5pw1xwKBgQDJC50yCUc95okmn8KINefm37qahFkrz5FG
vM1XZf91E1KRmZvZeeym/kI+dMacYAy1oAnZwzWNkWVkUAFiMC5fpDyulOO89TPH
721k9bnAwTNMX3Xo0g15CGH4sUVxO2UBupSqR2rGuf8GMw3VJ2Plq/4VX+2oXAl8
k4aUnwvpzQKBgQCvprujipJsN230PWykLtQuakkYInACw0bzbnKGaSSewLZLr8b0
piVHtZ5rgXiZgPT+G/EZVQQrlLo02nNmRtQHJAvpVKKZCaRDWxs2ACS65VT5q1aP
4LWS6tfEs9LSoqOsRb/wKkIOtGGjBAqqRGRHLO27P3Hpbt0u7EVbVFTu1wKBgQCP
S+/nUiWtQTxQg16sp397V8wxhlPonjH2MWxK9zB1yif4D3y+LeE3xdKBocpOe0eT
zVY4GKN7HD8gmMXjrmPfV7jI1ubcMAmQYF+grmSPtyVRMllgcReZRRhPokrUwnjk
GpEMLYs1yiyzxn/9he32LfkUUyOZ9L/uQ1iRZiufoQKBgAmJx3CUtvAzKAsQMcCk
5jz8nTZPzYUilhswkla+d2IONzKnGE3fCSznlZwwDG/WPqeowZSh7GAQ6mxsiwnk
KdvgbXzbNbhpRo9u3W+wq1+T6i3Mwk8RsOYGWy1DJrtywTAeitwsoxUKFy9aWItJ
qcDUVeB53Jtm/Yj2Ksv7H7Ze
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
