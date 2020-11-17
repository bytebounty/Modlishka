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
MIIFbzCCBFegAwIBAgISA2DF1U2O+kcF0rvdluiSvotbMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDExMTcxMzIzMjZaFw0y
MTAyMTUxMzIzMjZaMBwxGjAYBgNVBAMTEXRyZHRyYW5zcG9ydGUuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUNH+HvdOn001qIQdntrRPoh1IJF
lreCFv6CTXI5gyAxl/ypmQ4gQkEMjuYh9pNU62EzKfCTRhBC+LZgtOgTevVw5Zm9
bxSrLZD4rr1pLaY/iqdOjGLDq0K9S7ZzPlnYQcfHIlpo9bFOwUqyK1glC5bc8q4v
wtW3dA2ytjOpqWXP+yh8/9yt7mSF8EngPpas0jdUsM3qwjvQa3lvIOS2WZDmkfTV
s+FTmR0lNb5SZXoKYYQhAeWx1oLOFCu5m0gayO0iUmG/skTdQRzFIqYd0fnzww3Y
Mx+ZFMfI58/ieL1wPM/A89UBQC3gxRHAm7x014Ue8y9cG5E08lY9yK78tQIDAQAB
o4ICezCCAncwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS0vJOiNoe8c0d9d0VkIiVP
uWGqBjAfBgNVHSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBvBggrBgEFBQcB
AQRjMGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlw
dC5vcmcwLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlw
dC5vcmcvMDEGA1UdEQQqMCiCEyoudHJkdHJhbnNwb3J0ZS5jb22CEXRyZHRyYW5z
cG9ydGUuY29tMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgw
JgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYB
BAHWeQIEAgSB9QSB8gDwAHUARJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2
gagAAAF11pbE1QAABAMARjBEAiAFkCzVq2IubFKoPpYPsJJzWXmfeTLag/VCn9XP
ORuf7gIgMxAU+FebLkDvu8yadxc1SKDYJH82Xwq/d5JrP325m5AAdwD2XJQv0Xcw
IhRUGAgwlFaO400TGTO/3wwvIAvMTvFk4wAAAXXWlsTuAAAEAwBIMEYCIQCywhow
JUmeq9IyZSnfgYNS4SLA2z+XOfrfqWWs6GNHPgIhAOJ/3COEVsNRawZeV5vU7XE6
2pO1mrMbESTcL7BzfElmMA0GCSqGSIb3DQEBCwUAA4IBAQBShkCg+hfCs/DcmKTO
5jFfZoqY7Vckv9TzbRuoS+ZzoZ+GgRp+d59WDKu1Rr2OazIBLwBPaZeeS6wwLWxB
PpQNxqzJQ+OPosmbpIft63UwkkDztK7gUnSb2xWJl6alL2hFvYuS7UEJVvgdtEAz
y7eQJSk2LNQU6+NB0kyFnOQxMBbq0fSq9MSinXPF6bNSjCbpgR4g/HR8/U/uqSom
6iMGE73+Yay9WDDqtZPjTx1qlKiJhmKWZr8P6d73FdieUPg/L8EYM3Nz94L6d+yS
CDpHoISyP+AlnhvU2YdMMj+wmLwdXYfeaNQY2P7p/wsq0ZJs3lN8bSuj2ohEcHis
zqIp
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtUNH+HvdOn001qIQdntrRPoh1IJFlreCFv6CTXI5gyAxl/yp
mQ4gQkEMjuYh9pNU62EzKfCTRhBC+LZgtOgTevVw5Zm9bxSrLZD4rr1pLaY/iqdO
jGLDq0K9S7ZzPlnYQcfHIlpo9bFOwUqyK1glC5bc8q4vwtW3dA2ytjOpqWXP+yh8
/9yt7mSF8EngPpas0jdUsM3qwjvQa3lvIOS2WZDmkfTVs+FTmR0lNb5SZXoKYYQh
AeWx1oLOFCu5m0gayO0iUmG/skTdQRzFIqYd0fnzww3YMx+ZFMfI58/ieL1wPM/A
89UBQC3gxRHAm7x014Ue8y9cG5E08lY9yK78tQIDAQABAoIBAE76/gUbk43EuJ09
CIdXx6nKg6shCElftGNoikZMmxqzkGh1Q0DZktzLkzlAtVPHZp0ZQT3pAYLp2wSc
Ew9AgBx3jbW9g3k/PEcif/lDtuyZH96+f89TyYZ6EhlHaneklkIzVmV1l35Wv8Yh
Ufjo81tVZPipRU5T6Re8UD5rzGVup5zNHTiSV6UKAYuogCBMrmV5tNU1l0keThBI
HGW+kGdRL4x31W1/nLPn74WDvHFuQ4+WX3zz2adsgG5eGrs7OOpIZ+GxRYctPNn0
Q3Vj9euCq36JBrsYHyRY3FymVg+VpLNegTBCCVW5HvDjg4xms5WE11U07MFBazpb
KGeQooECgYEA3iAzWUbgq3rj1ef70SaLhEQqRoqMXMLY519kxSF6JpE0P1xftTWA
Xuh+hQZfJtCjLfs90aF+lHce/iHkU0Q5cGT2jB6y4kFfKROT6/eP2B0S3+0gXD7h
6QghojBKs+9ZD5l+/k+kxDnMzP5riGCxGAettbsg8kNw9IbxwFEITSkCgYEA0OfJ
6S9cLrUJ7yFH0kTuqXMxAGOgJbG8kOrkLRU6Yh3oep8M6oNs8u/n2w2ZUQtCLdr6
wz6FiTVOunDgJpsi/xzXnuWbXU+9Cf8fX43rrXPZNXX/zAbl63bUHdiYIIjI/w44
J+IpDV629FhcGCxSZmuTKbrC6XK7aShix6v/GK0CgYBmnXGbWMcJ8Se39ge7Q5dI
b0UoeXEGmW0i1krzVtfbYVFFxCLiz+iR784jHiJvCAuafmq8oWKcq7tBo96bKPVw
GvRbHwN8yr5vd3/qjt+A80147U75zoMG6J7BEpYwMe5u6nZkfd6cWCdovFBpHGIz
u7hgMCa0RLu1+3FLayPuoQKBgDXYSJat+lifmRvlvBlaYxmR80NialjM4wmHQaDN
I+s+Qjm43R9lGKPVajFv4+CbwkcHdjL03n5rGwu7JEtPGUogKQNvswfuEY+ODowW
jHR8s7Ov4mq4LHLwgePfe/aGyyfShm7hQCuOCiIY1EP2yJZVi+zpkmuRgvSr0Cof
DvVRAoGBALnmfjSG3ISFakOXCFQfSwXPCAQOx+njyYvecRbXD9PHrZPs/SWsDRte
RSYS6KbdYs7QjxLargbpwSHB0KcvUX0np4pA6JuOWQ+SspE0GuQWZQkyspau8SkG
+EULbtxntWUM/y3sc/EjIE4rlAOl6bi5RKtkFZ5ybfZ5zJnfHeh2
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
