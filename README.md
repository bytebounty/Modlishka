#0
git clone https://github.com/acmesh-official/acme.sh.git
cd ./acme.sh
./acme.sh --install

#1
acme.sh --issue --force -d _.REPLACE_WITH_DOMAIN.com -d _.com.REPLACE*WITH_DOMAIN.com -d *.com.br.REPLACE*WITH_DOMAIN.com -d *.mercadolivre.com.REPLACE_WITH_DOMAIN.com -d \*.mercadolivre.com.br.REPLACE_WITH_DOMAIN.com --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please

#2
CREATE THE TXT RECORDS IT SAYS, DONT INCLUDE THE ''

#3
acme.sh --renew --force -d _.REPLACE_WITH_DOMAIN.com -d _.com.REPLACE*WITH_DOMAIN.com -d *.com.br.REPLACE*WITH_DOMAIN.com -d *.mercadolivre.com.REPLACE_WITH_DOMAIN.com -d \*.mercadolivre.com.br.REPLACE_WITH_DOMAIN.com --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please

Result:
Your cert is in /root/.acme.sh/_.REPLACE_WITH_DOMAIN.com/_.REPLACE*WITH_DOMAIN.com.cer
Your cert key is in /root/.acme.sh/*.REPLACE*WITH_DOMAIN.com/*.REPLACE*WITH_DOMAIN.com.key
The intermediate CA cert is in /root/.acme.sh/*.REPLACE*WITH_DOMAIN.com/ca.cer
And the full chain certs is there: /root/.acme.sh/*.REPLACE_WITH_DOMAIN.com/fullchain.cer

#4
awk '{printf "%s\\n", \$0}' /root/.acme.sh/_.REPLACE_WITH_DOMAIN.com/_.REPLACE_WITH_DOMAIN.com.cer

- Paste in JSON config
  awk '{printf "%s\\n", \$0}' /root/.acme.sh/_.REPLACE_WITH_DOMAIN.com/_.REPLACE_WITH_DOMAIN.com.key
- Paste in JSON config
  awk '{printf "%s\\n", \$0}' /root/.acme.sh/\*.REPLACE_WITH_DOMAIN.com/ca.cer
- Paste in JSON config
  \*\* MAKE SURE TO USE CA.cer for certPool field.

#5
sudo ./dist/proxy -config templates/mercadolivre.json
