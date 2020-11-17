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
MIIErjCCA5agAwIBAgIUdD7c9GBV1Z3aHNp1zTtMhTpW070wDQYJKoZIhvcNAQEL
BQAwgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQw
MgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9y
aXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MB4XDTIwMTExNzEyMDcwMFoXDTIxMTExNzEyMDcwMFowYjEZMBcGA1UEChMQQ2xv
dWRGbGFyZSwgSW5jLjEdMBsGA1UECxMUQ2xvdWRGbGFyZSBPcmlnaW4gQ0ExJjAk
BgNVBAMTHUNsb3VkRmxhcmUgT3JpZ2luIENlcnRpZmljYXRlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwD2CkQr0kkZQjGj+SAcq0MZc0HhjTyTrgqki
Ro+bxLVXOwkV7jaIonQfecSWsLtiAK1O8jHO88W6zhRpQTJS0lfXUkau6YnSrnlx
HIruQ0gjUcfRRFQpuRlaTn+FptztGijxKEG05/Xa/dnKKXqyCT8/a3Fz+qPkCuQf
n03+QWflQhByb3o0DVJ29a/kyQb2gdONOt3DctS7YUXPK6FV18DJ5nHxIiL5nRr9
7TS79HGFiVRx6jSMVqxhP9JSRmaCjy+VNwKerS6CPW04eaX1mv8LQmm7mXdrjBXq
m3gTpLzSxN1RWGxrAE+/wRAzuMAkPXAbY6t4aHFLK1HN8DqiRwIDAQABo4IBMDCC
ASwwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTJIyv2Xf1sthI2aq+aDxapcqduDzAf
BgNVHSMEGDAWgBQk6FNXXXw0QIep65TbuuEWePwppDBABggrBgEFBQcBAQQ0MDIw
MAYIKwYBBQUHMAGGJGh0dHA6Ly9vY3NwLmNsb3VkZmxhcmUuY29tL29yaWdpbl9j
YTAxBgNVHREEKjAoghMqLnRyZHRyYW5zcG9ydGUuY29tghF0cmR0cmFuc3BvcnRl
LmNvbTA4BgNVHR8EMTAvMC2gK6AphidodHRwOi8vY3JsLmNsb3VkZmxhcmUuY29t
L29yaWdpbl9jYS5jcmwwDQYJKoZIhvcNAQELBQADggEBADuwcFnIqeZdMBMJxEX1
2BPuSrBfiFTHVFulQvOIQAeLAn0Hjoj7CxT2s6ucygmTY+azAO+9NmFw7ztYIlYS
Cbofn9M5w2wYtYZhOqqwJ+hgkIZpsIF1YrVxN3jU9mEbYSqQQdVOrCxreeGZPgs/
rJTOVnSzHQo+IluPMfwVCoalZZVk71L15B7F0iT/u2m7tRVEu5pCTY5f56Oz2hE2
pceLQbnkNP1kjnCCk31irDdinNWQPktf+vgZbztKWqQA35KwALxHgYhvjQvlCuVl
5GWBHrdKU1mwwceA5mmd0rPr1wsG1rDutP8iyefwIgJ1FqDI/BDSQHGA1klZFF/3
nnU=
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGBbM6K8NUewbW
phRMAoCPoJO39Exfh7VXYuTYZPDDUAXdzPCMWpw14cREJoXcYfivMICR2BX90L/Q
u9HqAfwaA6AHF6e2XDV1LcooBoM8K549CaLIbO7FAz+UfzExq0XsglZUAgl1v1Ox
Mx1KbIq3CBYZgLQy/E0mQMPzRbo4WZ4DIb7tLW1iRBht5S50oOB4/GDkPhM2c+MU
CfT5coCtV+C3YNspdvZRfytgX/jFz0RpWkXrsvWM0CwziohEEiyqdG1Pt4gmVClM
novi9OlCF2xA2EZXdq2+pDxF2NFwKlDbrSKhr+JIoahPa96y6iGkSIcHtFUgPk/M
cxgB78BJAgMBAAECggEAA2yEzqbZZUQNTbfTFloIDrOy6irYs+F8/V+nNPtQfb1h
T0D5uyDenkCNlrS90B4yNmvrGoUhzYuG+DJ514ck7JmPHPWdP5YfkdZIA7d9HGoP
/d6FSIbi/VgS3jFG0KTf/CNoH7gQoXm8ljib3eC7k0eaA43fT8RfXHUhOOXF6a8n
NX6R3vEs2Y6kZ614iQE9ixZQ9q4a9HvjdM7hjlr5vPJWL6i9E5L8jlXeo97r8+2h
VeAZxTtzJgTElPeVrrKxtW5f64JAMtnJKk5GWk4ijKgU0Jd+0WdsTQ+14CHe3Q2b
XWyrfrcE58jx9dBbvKFJxXa09NHLT9R0XGkiPf+RgQKBgQDpqJNb9GniIAox6tRD
rpuwS8Pur/Yn+Ya0pcR1krt7LZGnGk27Jg9xKtO8u9iAq+MXIulDpWOOKXbQaA0f
+e6I4wfS2eB1GdEVu1Sqx3Wv86yG6OG6SvS+hNqvD0IHR6KI0SpmWICIBs8pNOkO
I5d/8Uq65UOSGSqONkaX5HNGYQKBgQDY9NTKLMBtnHsy1jsnItjSktbDiN7ptjQE
9+2vUTVJhG0li7I6trEZ/ox8vujg7B5FQjN9P4VGJeGZwW/H8EpUffH2/8K7mLva
WkEIZg1IQ4tImCp9iaXiUH0+esKK/peTi9boQKJ3jrR4OtugLcwCG7VL6+aMEIFl
JG0w053y6QKBgQCwKTpAP7t8km9dRxCVnpUei2DDGcLaTJQ0qi29/sx+h9KiS4CD
MqS9y24rguwtxmnFzbpUF+NBER3U7j3G9+XRKmmBnGZPoxEx8zRYNV0TNQHEDNvy
WgS/huZgyX4cgvOVdy0iUGNHKusQxCVZVZgpC8AtvB//jB27bkw2xDPswQKBgG4d
fa8LnbNEe+cmgqlvb1sZOjXOT02Rs79d0t5ruj8RHpCy4YgZV7QY1VcvUmVukkKW
wilsxwj+iw2N910kYaWWsuupjj3G3HmL23wWx+EInzX+PXqwFWjTb235wqnnZCl4
DWCeBZfm70Qio3weInBjfdYF6mLmsbYTEfR5Q66ZAoGAP4/meGCK49/0RP5CSVyi
lquVkpU7kchojPF/K/2kENxSmaUoxaPilx/VAQFTrbdrIIwjlttF/ZfSaGEHjiGX
OzMdjpNBSVnFV+y74mPnp7rqqjbVD7afpL7U1xuLj6lt1W9C5z6cdv0hqBP3aAzX
lbgxjx8UKmueWNE1fP5plt8=
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
