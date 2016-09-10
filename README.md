# acme-client
a small tool to get and renew TLS certs from Let's Encrypt

## dependency
```
openssl php-cli php-curl
```

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

## add a sslcert user, put the key in place
```
useradd -M sslcert
mkdir /opt/sslcert
mkdir /opt/sslcert/bin
mkdir /opt/sslcert/keys
mkdir /opt/sslcert/certs
mkdir /opt/sslcert/acme-challenge

cp acme-client.php /opt/sslcert/bin
mv account.key /opt/sslcert/keys
mv domain.csr /opt/sslcert/keys
mv domain.key /etc/ssl/private
wget https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem \
     -O /opt/sslcert/certs/lets-encrypt-x3-cross-signed.pem

chown -R sslcert:sslcert /opt/sslcert/keys
chown -R sslcert:sslcert /opt/sslcert/certs
chown -R sslcert:sslcert /opt/sslcert/acme-challenge
chmod 700 /opt/sslcert/keys
chmod 600 /opt/sslcert/keys/account.key
chmod 600 /opt/sslcert/keys/domain.csr
chmod 600 /etc/ssl/private/domain.key
```

## change nginx config to add http challenge dir
```
server {
    listen 80 default_server;

    ...

    server_name domain.com www.domain.com;
    try_files $uri $uri/ =404;

    location /.well-known/acme-challenge/ {
        default_type text/plain;
        alias /opt/sslcert/acme-challenge/;
    }

    ...
}
```

## create a wrap script
```
vi /opt/sslcert/bin/getcert.sh
chmod +x /opt/sslcert/bin/getcert.sh

#!/bin/bash

# usage: acme-client.php -a <account_key_file> -r <csr_file> 
#                        -d <domain_list(domain1;domain2...;domainN)>
#                        -c <http_challenge_dir>
#                        -o <output_cert_file>

php /opt/sslcert/bin/acme-client.php \
    -a /opt/sslcert/keys/account.key \
    -r /opt/sslcert/keys/domain.csr \
    -d "domain.com;www.domain.com" \
    -c /opt/sslcert/acme-challenge \
    -o /opt/sslcert/certs/domain.crt
if [ $? -ne 0 ]
then
    exit 1
fi

cat /opt/sslcert/certs/domain.crt \
    /opt/sslcert/certs/lets-encrypt-x3-cross-signed.pem \
    > /opt/sslcert/certs/domain.chained.crt

rm -f /opt/sslcert/acme-challenge/*

```

## get cert
```
su -s /bin/bash -c '/opt/sslcert/bin/getcert.sh' sslcert
```

## nginx ssl conf
```
server {
    listen 80 default_server;
    server_name domain.com www.domain.com;

    root /opt/www/html;
    index index.html;
    try_files $uri $uri/ =404;

    location /.well-known/acme-challenge/ {
        default_type text/plain;
        alias /opt/sslcert/acme-challenge/;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name domain.com www.domain.com;

    root /opt/www/html;
    index index.html;
    try_files $uri $uri/ =404;

    ssl on;
    ssl_certificate /opt/sslcert/certs/domain.chained.crt;
    ssl_certificate_key /etc/ssl/private/domain.key;
    ssl_session_timeout 10m;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
}
```

## set crontab task to renew cert (run every week)
```
crontab -u sslcert -e

0 0 * * 1 /bin/bash /opt/sslcert/bin/getcert.sh
```
