# QuickRSA
RSA Encrypt and Decrypt for iOS


#### 1. Run script gen_rsa_key.sh generate RSA keys.

WARNING: DO NOT RELEASE "PRIVATE KEY" IN PACKAGE(注意：切记不要把私钥一起打包发布)

```shell
$sh gen_rsa_key.sh  #Generate a peer keys of RSA.
$sh test_rsa_key.sh #A test.
```


#### 2. Create a RSA SecKeyRef

```objc
//1. 509 Cert
+ (SecKeyRef)RSASecKeyPubCopyWithX509CertData:(NSData *)certData;
//2. Import P12 for private key
+ (SecKeyRef)RSASecKeyPriCopyWithP12Data:(NSData *)p12Data password:(NSString *)password;
//3. Use Keychain
+ (SecKeyRef)RSASecKeyCopyWithPKCS1Data:(NSData *)pkcs1Data appTag:(NSString *)appTag isPublic:(BOOL)isPublic;
//4. Use System API (For iOS 10 and later only)
+ (SecKeyRef)RSASecKeyCopyWithDERData:(NSData *)derData isPublic:(BOOL)isPublic;
```

#### 3. RSA Enc/Dec with SecKeyRef

```objc
@interface NSData(QRSecCrypto)
- (NSData *)RSAEncryptDataWithPublicKey:(SecKeyRef)publicKey;
- (NSData *)RSADecryptDataWithPrivateKey:(SecKeyRef)privateKey;
@end
```

#### 4. OpenSSL RSA Enc/Dec

```objc
//Use PEM, Pub(Pri) Enc -> Pri(Pub) Dec
- (NSData *)OpenSSL_RSA_EncryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic;//PEM key
- (NSData *)OpenSSL_RSA_DecryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic;//PEM key

//Use DER, Pub(Pri) Enc -> Pri(Pub) Dec
- (NSData *)OpenSSL_RSA_EncryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic;//DER key
- (NSData *)OpenSSL_RSA_DecryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic;//DER key

//Use modulus exponent
- (NSData *)OpenSSL_RSA_DataWithPublicModulus:(NSData *)modulus exponent:(NSData *)exponent isDecrypt:(BOOL)isDecrypt;
```

#### 5. Format convert class "QRFormatConvert"


#### 6. Usage of RSA

a. RSA + AES(Client[RSA PUB Enc AES] -> Server[RSA PRI Dec AES], Client[AES Enc/Dec DATA] <-> Server[AES Enc/Dec DATA]).

b. RSA Enc and Dec.


#### 7. Link error

Project Settings add "Other Linker Flags" -all_load or -ObjC


#### 8. Reference

OpenSSL lib built from https://github.com/x2on/OpenSSL-for-iPhone

http://www.jianshu.com/p/21bb11ff8e27
https://www.openssl.org/docs/man1.0.1/crypto/i2d_RSA_PUBKEY.html
https://github.com/StCredZero/SCZ-BasicEncodingRules-iOS
http://www.techper.net/2012/06/01/converting-rsa-public-key-modulus-and-exponent-into-pem-file/

