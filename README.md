# mkcert
Demos of create self-signed CA cert, create client cert with self-signed CAcert and verify client cert using openssl APIs.

## How to do this with openssl command line?
* Create CA private key and rootreq:  
  $ openssl req -nodes -newkey rsa:1024 -sha1 -keyout rootkey.pem -out rootreq.pem

* Create CA self-signed cert:  
  $ openssl x509 -req -in rootreq.pem -sha1 -signkey rootkey.pem -out rootcert.pem

* Install CA cert as trusted cert:  
  $ sudo mkdir /usr/share/ca-certificates/extra
  $ sudo cp rootcert.pem /usr/share/ca-certificates/extra/rootcert.crt
  $ sudo dpkg-reconfigure ca-certificates
  $ sudo update-ca-certificates

* Client create private key and certreq:  
  $ openssl req -nodes -newkey rsa:1024 -sha1 -keyout userkey.pem -out userreq.pem 

* Create client cert by CA:  
  $ openssl x509 -req -in userreq.pem -sha1 -CA /etc/ssl/certs/rootcert.pem -CAkey rootkey.pem -CAcreateserial -out usercert.pem 

* Verify client cert:  
  $ openssl verify -CAfile rootcert.pem usercert.pem

## How to do this with openssl APIs?
* Create CA private key and rootreq:  
  See mkcacert.c

* Client create private key and certreq, create client cert by CA:  
  See mkclientcert.c

* Verify client cert:  
  See verify.c

## TODO
Revoke client cert
