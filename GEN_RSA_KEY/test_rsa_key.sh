#!/bin/bash

# Created by liuyuning on 2016/10/20.
# Copyright © 2016年 liuyuning. All rights reserved.

#OpenSSL Docs https://www.openssl.org/docs/manmaster/apps/

rm -rf TEST; mkdir TEST; pushd TEST

#Encrypt test
#https://raymii.org/s/tutorials/Encrypt_and_decrypt_files_to_public_keys_via_the_OpenSSL_Command_Line.html
echo 'Hello!' > test.txt #The text in file is "Hello!\n"
echo '[TXT]\c'
cat test.txt
openssl rsautl -encrypt -inkey ../KEY/rsa_public_key.pem -pubin -in test.txt -out test.txt.enc
echo '[ENC]'
xxd -ps test.txt.enc
openssl rsautl -decrypt -inkey ../KEY/rsa_private_key.pem -in test.txt.enc -out test.txt.dec
echo '[DEC]\c'
cat test.txt.dec

#Sign test
#openssl rsautl -sign -inkey ../KEY/rsa_private_key.pem -in test.txt -out test.txt.sgn
#echo '[SNG]'
#xxd -ps test.txt.sgn
