# acme-client
a small tool to get and renew TLS certs from Let's Encrypt

## generate account private key
```
openssl genrsa -out account.key 4096
```

## generate domain private key
```
openssl genrsa -out domain.key 2048
```

## generate csr from domain private key
```
# single domain
openssl req -new -sha256 -key domain.key -out domain.csr -subj "/CN=domain.com"

# multiple domain
cp /etc/ssl/openssl.cnf domain.conf
printf "[SAN]\nsubjectAltName=DNS:domain.com,DNS:www.domain.com" >> domain.conf
openssl req -new -sha256 -key domain.key -out domain.csr -subj "/" \
        -reqexts SAN -config domain.conf
```

## add a sslcert user
```
useradd -M sslcert
```

## create http challenge dir
```
mkdir -p /var/www/challenges
chown sslcert:sslcert /var/www/challenges
```

## get cert
```
# usage: acme-client.php -a <account_key_file> -r <csr_file> 
#                        -d <domain_list(domain1;domain2...;domainN)>
#                        -c <http_challenge_dir>

./acme-client.php -a account.key -r domain.csr \
                  -d 'domain.com;www.domain.com' \
                  -c /var/www/challenges > domain.crt;
```

## nginx conf
```
```
