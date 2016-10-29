#!/bin/bash

# Created by liuyuning on 2016/10/20.
# Copyright © 2016年 liuyuning. All rights reserved.

#OpenSSL Docs https://www.openssl.org/docs/manmaster/apps/
#Default '-inform' and '-outform' is 'PEM'

echo '\033[0;31m'
echo '== DO NOT RELEASE "PRIVATE KEY" IN PACKAGE(切记不要把私钥一起打包发布) =='
echo '\033[0m'

rm -rf KEY; mkdir KEY; pushd KEY

#1. Private key
openssl genrsa -out rsa_private_key.pem 1024 #PEM fromat
openssl rsa -in rsa_private_key.pem -outform DER -out rsa_private_key.der #DER fromat

#2. Public key
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem #PEM fromat
openssl rsa -in rsa_private_key.pem -pubout -outform DER -out rsa_public_key.der #DER fromat
#openssl rsa -in rsa_public_key.pem -pubin -outform DER -out rsa_public_key_.der #Same as upper

#3. Modulus & Exponent
#http://www.dsm.fordham.edu/~mathai/openssl.html
#openssl rsa -in rsa_public_key.pem -pubin -modulus -noout # > rsa_modulus.txt #Get modulus
#openssl rsa -in rsa_private_key.pem -modulus -noout # > rsa_modulus_.txt #Same as upper
openssl rsa -in rsa_private_key.pem -text -noout > rsa_modulus_exponent.txt
openssl asn1parse -in rsa_private_key.pem -i > rsa_modulus_exponent_asn1.txt

#4. CA x509
#https://gist.github.com/lvjian700/635368d6f1e421447680
echo '\033[0;31m'
echo '== Input info of certificate request(输入证书请求的信息) =='
echo '\033[0m'
openssl req -new -key rsa_private_key.pem -out rsa_cert_req.pem #Another extension as 'rsa_cert_req.csr'. PEM fromat
#openssl req -in rsa_cert_req.pem -text -noout #Show the content
openssl x509 -req -days 3650 -in rsa_cert_req.pem -signkey rsa_private_key.pem -out rsa_cert_cert.pem #Another extension as 'rsa_cert_cert.cer'. PEM fromat
#openssl x509 -in rsa_cert_cert.pem -text -noout #Show the content
openssl x509 -in rsa_cert_cert.pem -outform DER -out rsa_cert_cert.der #Convert PEM to DER

#Print Apple CA
#openssl x509 -in AppleWWDRCA.cer -inform DER -text -noout #DER fromat
#openssl x509 -in AppleWWDRCA.cer -inform DER -out AppleWWDRCA.pem -outform PEM

#5. PKCS#8 & #12
openssl pkcs8 -topk8 -in rsa_private_key.pem -nocrypt -out rsa_private_key_pk8.pem #For Java PEM fromat
echo '\033[0;31m'
echo '\n== Input password for p12(输入密码给p12加密) =='
echo '\033[0m'
openssl pkcs12 -export -in rsa_cert_cert.pem -inkey rsa_private_key.pem -out rsa_private_key_p12.p12 #For Mac and iOS

#For (4.) input option of certificate request
#-----
#Country Name (2 letter code) [AU]:CN
#State or Province Name (full name) [Some-State]:Beijing
#Locality Name (eg, city) []:Haidian
#Organization Name (eg, company) [Internet Widgits Pty Ltd]:Sogou
#Organizational Unit Name (eg, section) []:Desktop
#Common Name (e.g. server FQDN or YOUR name) []:Liuyuning Test Certification Authority
#Email Address []:liuyuning@xxx.com
#
#Please enter the following 'extra' attributes
#to be sent with your certificate request
#A challenge password []:
#An optional company name []:


