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

const CA_CERT = `-----BEGIN CERTIFICATE-----\nMIIFbzCCBFegAwIBAgISA2DF1U2O+kcF0rvdluiSvotbMA0GCSqGSIb3DQEBCwUA\nMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\nExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDExMTcxMzIzMjZaFw0y\nMTAyMTUxMzIzMjZaMBwxGjAYBgNVBAMTEXRyZHRyYW5zcG9ydGUuY29tMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUNH+HvdOn001qIQdntrRPoh1IJF\nlreCFv6CTXI5gyAxl/ypmQ4gQkEMjuYh9pNU62EzKfCTRhBC+LZgtOgTevVw5Zm9\nbxSrLZD4rr1pLaY/iqdOjGLDq0K9S7ZzPlnYQcfHIlpo9bFOwUqyK1glC5bc8q4v\nwtW3dA2ytjOpqWXP+yh8/9yt7mSF8EngPpas0jdUsM3qwjvQa3lvIOS2WZDmkfTV\ns+FTmR0lNb5SZXoKYYQhAeWx1oLOFCu5m0gayO0iUmG/skTdQRzFIqYd0fnzww3Y\nMx+ZFMfI58/ieL1wPM/A89UBQC3gxRHAm7x014Ue8y9cG5E08lY9yK78tQIDAQAB\no4ICezCCAncwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\nBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBS0vJOiNoe8c0d9d0VkIiVP\nuWGqBjAfBgNVHSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBvBggrBgEFBQcB\nAQRjMGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlw\ndC5vcmcwLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlw\ndC5vcmcvMDEGA1UdEQQqMCiCEyoudHJkdHJhbnNwb3J0ZS5jb22CEXRyZHRyYW5z\ncG9ydGUuY29tMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgw\nJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYB\nBAHWeQIEAgSB9QSB8gDwAHUARJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2\ngagAAAF11pbE1QAABAMARjBEAiAFkCzVq2IubFKoPpYPsJJzWXmfeTLag/VCn9XP\nORuf7gIgMxAU+FebLkDvu8yadxc1SKDYJH82Xwq/d5JrP325m5AAdwD2XJQv0Xcw\nIhRUGAgwlFaO400TGTO/3wwvIAvMTvFk4wAAAXXWlsTuAAAEAwBIMEYCIQCywhow\nJUmeq9IyZSnfgYNS4SLA2z+XOfrfqWWs6GNHPgIhAOJ/3COEVsNRawZeV5vU7XE6\n2pO1mrMbESTcL7BzfElmMA0GCSqGSIb3DQEBCwUAA4IBAQBShkCg+hfCs/DcmKTO\n5jFfZoqY7Vckv9TzbRuoS+ZzoZ+GgRp+d59WDKu1Rr2OazIBLwBPaZeeS6wwLWxB\nPpQNxqzJQ+OPosmbpIft63UwkkDztK7gUnSb2xWJl6alL2hFvYuS7UEJVvgdtEAz\ny7eQJSk2LNQU6+NB0kyFnOQxMBbq0fSq9MSinXPF6bNSjCbpgR4g/HR8/U/uqSom\n6iMGE73+Yay9WDDqtZPjTx1qlKiJhmKWZr8P6d73FdieUPg/L8EYM3Nz94L6d+yS\nCDpHoISyP+AlnhvU2YdMMj+wmLwdXYfeaNQY2P7p/wsq0ZJs3lN8bSuj2ohEcHis\nzqIp\n-----END CERTIFICATE-----\n`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtUNH+HvdOn001qIQdntrRPoh1IJFlreCFv6CTXI5gyAxl/yp\nmQ4gQkEMjuYh9pNU62EzKfCTRhBC+LZgtOgTevVw5Zm9bxSrLZD4rr1pLaY/iqdO\njGLDq0K9S7ZzPlnYQcfHIlpo9bFOwUqyK1glC5bc8q4vwtW3dA2ytjOpqWXP+yh8\n/9yt7mSF8EngPpas0jdUsM3qwjvQa3lvIOS2WZDmkfTVs+FTmR0lNb5SZXoKYYQh\nAeWx1oLOFCu5m0gayO0iUmG/skTdQRzFIqYd0fnzww3YMx+ZFMfI58/ieL1wPM/A\n89UBQC3gxRHAm7x014Ue8y9cG5E08lY9yK78tQIDAQABAoIBAE76/gUbk43EuJ09\nCIdXx6nKg6shCElftGNoikZMmxqzkGh1Q0DZktzLkzlAtVPHZp0ZQT3pAYLp2wSc\nEw9AgBx3jbW9g3k/PEcif/lDtuyZH96+f89TyYZ6EhlHaneklkIzVmV1l35Wv8Yh\nUfjo81tVZPipRU5T6Re8UD5rzGVup5zNHTiSV6UKAYuogCBMrmV5tNU1l0keThBI\nHGW+kGdRL4x31W1/nLPn74WDvHFuQ4+WX3zz2adsgG5eGrs7OOpIZ+GxRYctPNn0\nQ3Vj9euCq36JBrsYHyRY3FymVg+VpLNegTBCCVW5HvDjg4xms5WE11U07MFBazpb\nKGeQooECgYEA3iAzWUbgq3rj1ef70SaLhEQqRoqMXMLY519kxSF6JpE0P1xftTWA\nXuh+hQZfJtCjLfs90aF+lHce/iHkU0Q5cGT2jB6y4kFfKROT6/eP2B0S3+0gXD7h\n6QghojBKs+9ZD5l+/k+kxDnMzP5riGCxGAettbsg8kNw9IbxwFEITSkCgYEA0OfJ\n6S9cLrUJ7yFH0kTuqXMxAGOgJbG8kOrkLRU6Yh3oep8M6oNs8u/n2w2ZUQtCLdr6\nwz6FiTVOunDgJpsi/xzXnuWbXU+9Cf8fX43rrXPZNXX/zAbl63bUHdiYIIjI/w44\nJ+IpDV629FhcGCxSZmuTKbrC6XK7aShix6v/GK0CgYBmnXGbWMcJ8Se39ge7Q5dI\nb0UoeXEGmW0i1krzVtfbYVFFxCLiz+iR784jHiJvCAuafmq8oWKcq7tBo96bKPVw\nGvRbHwN8yr5vd3/qjt+A80147U75zoMG6J7BEpYwMe5u6nZkfd6cWCdovFBpHGIz\nu7hgMCa0RLu1+3FLayPuoQKBgDXYSJat+lifmRvlvBlaYxmR80NialjM4wmHQaDN\nI+s+Qjm43R9lGKPVajFv4+CbwkcHdjL03n5rGwu7JEtPGUogKQNvswfuEY+ODowW\njHR8s7Ov4mq4LHLwgePfe/aGyyfShm7hQCuOCiIY1EP2yJZVi+zpkmuRgvSr0Cof\nDvVRAoGBALnmfjSG3ISFakOXCFQfSwXPCAQOx+njyYvecRbXD9PHrZPs/SWsDRte\nRSYS6KbdYs7QjxLargbpwSHB0KcvUX0np4pA6JuOWQ+SspE0GuQWZQkyspau8SkG\n+EULbtxntWUM/y3sc/EjIE4rlAOl6bi5RKtkFZ5ybfZ5zJnfHeh2\n-----END RSA PRIVATE KEY-----\n`

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
