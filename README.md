# mkcert
Demos of create self-signed CA cert, create client cert with self-signed CAcert and verify client cert using openssl APIs.

## How to do this with openssl command line?
### Create CA private key and rootreq
  $ openssl req -nodes -newkey rsa:1024 -sha1 -keyout rootkey.pem -out rootreq.pem

### Create CA self-signed cert
  $ openssl x509 -req -in rootreq.pem -sha1 -signkey rootkey.pem -out rootcert.pem

### Install CA cert as trusted cert (optional)
  $ sudo mkdir /usr/share/ca-certificates/extra  
  $ sudo cp rootcert.pem /usr/share/ca-certificates/extra/rootcert.crt  
  $ sudo dpkg-reconfigure ca-certificates  
  $ sudo update-ca-certificates  

### Client create private key and certreq
  $ openssl req -nodes -newkey rsa:1024 -sha1 -keyout userkey.pem -out userreq.pem 

### Create client cert by CA:  
  $ openssl x509 -req -in userreq.pem -sha1 -CA /etc/ssl/certs/rootcert.pem -CAkey rootkey.pem -CAcreateserial -out usercert.pem 

### Verify client cert
  $ openssl verify -CAfile rootcert.pem usercert.pem

### Revoke client cert
#### Create CRL
Before we can generate a CRL, we must create a `crlnumber` file, but we look the openssl.cnf at first.
* modify openssl.cnf (ubuntu: /etc/ssl/openss.cnf, centos: /etc/pki/tls/openssl.cnf), find the session CA_default and modify it as follow:  
> [ CA_default ]
> 
> dir             = /etc/ssl/demoCA               # Where everything is kept  
> certs           = $dir/certs            # Where the issued certs are kept  
> crl_dir         = $dir/crl              # Where the issued crl are kept  
> database        = $dir/index.txt        # database index file.  
> \# unique_subject = no                    # Set to 'no' to allow creation of  
>                                         # several ctificates with same subject.  
> new_certs_dir   = $dir/newcerts         # default place for new certs.  
> 
> certificate     = $dir/rootcert.pem       # The CA certificate  
> serial          = $dir/serial           # The current serial number  
> crlnumber       = $dir/crlnumber        # the current crl number  
>                                         # must be commented out to leave a V1 CRL  
> crl             = $dir/crl.pem          # The current CRL  
> private_key     = $dir/private/rootkey.pem # The private key  

* copy the rootkey.pem and rootcert.pem to the related dir  

* create `index.txt` file:  
$ > /etc/ssl/demoCA/index.txt

* create `crlnumber` file:  
$ echo 1024 > /etc/ssl/demoCA/crlnumber

#### Create url.pem  
$ openssl ca -gencrl -out /etc/ssl/demoCA/crl/crl.pem  

#### View crl.pem
$ openssl crl -in /etc/ssl/demoCA/crl/crl.pem -text  
> Certificate Revocation List (CRL):  
        Version 2 (0x1) 
    Signature Algorithm: sha256WithRSAEncryption  
        Issuer: /C=UK/CN=OpenSSL Group/C=UK/CN=Openssl  
        Last Update: Mar 30 03:56:23 2015 GMT  
        Next Update: Apr 29 03:56:23 2015 GMT  
        CRL extensions:  
            X509v3 CRL Number:   
                4133  
No Revoked Certificates.  
    Signature Algorithm: sha256WithRSAEncryption  
    ...  
    

#### Revoke client cert
$ openssl ca -revoke usercert.pem

#### Update the CRL
$ openssl ca -gencrl -out /etc/ssl/demoCA/crl/crl.pem

#### View the crl.pem again 
$ openssl crl -in /etc/ssl/demoCA/crl/crl.pem -text  
> Certificate Revocation List (CRL):  
        Version 2 (0x1)  
    Signature Algorithm: sha256WithRSAEncryption  
        Issuer: /C=UK/CN=OpenSSL Group/C=UK/CN=Openssl  
        Last Update: Mar 30 03:59:11 2015 GMT  
        Next Update: Apr 29 03:59:11 2015 GMT  
        CRL extensions:  
            X509v3 CRL Number:   
                4134  
Revoked Certificates:  
    Serial Number: 0400  
        Revocation Date: Mar 30 03:57:52 2015 GMT  
    Signature Algorithm: sha256WithRSAEncryption  
    ...  

## How to do this with openssl APIs?
### Create CA private key and rootreq:  
See mkcacert.c

### Client create private key and certreq, create client cert by CA:  
See mkclientcert.c

### Verify client cert with or without CRL:  
See verify.c

## TODO
Revoke client cert
