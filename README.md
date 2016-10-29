# QuickRSA
RSA Encrypt and Decrypt for iOS


1. RSA + AES(Client[RSA PUB Enc AES] -> Server[RSA PRI Dec AES], Client[AES Enc/Dec DATA] <-> Server[AES Enc/Dec DATA]).
2. RSA Enc and Dec.

WARNING: DO NOT RELEASE "PRIVATE KEY" IN PACKAGE(注意：切记不要把私钥一起打包发布)

```shell
$sh gen_rsa_key.sh #Generate a peer keys of RSA.
$sh test_rsa_key.sh #Run a test.
```

Project Settings add "Other Linker Flags" -all_load or -ObjC

Public Enc

```objc


//Call CFRelease() to free SecKeyRef.

+ (SecKeyRef)RSASecKeyPubCopyWithX509CertData:(NSData *)certData;//509 Cert
+ (SecKeyRef)RSASecKeyPriCopyWithP12Data:(NSData *)p12Data password:(NSString *)password;//P12

//Turn On Keychain Sharing(Project - TARGETS - Capabilitys - Keychain Sharing - Switch On)
//This API using SecItemXXX works with Keychain, retrun nil if the Keychain can't access.
+ (SecKeyRef)RSASecKeyCopyWithPKCS1Data:(NSData *)pkcs1Data appTag:(NSString *)appTag isPublic:(BOOL)isPublic;//Use Keychain

//For iOS 10 and later
+ (SecKeyRef)RSASecKeyCopyWithDERData:(NSData *)derData isPublic:(BOOL)isPublic __OSX_AVAILABLE(10.12) __IOS_AVAILABLE(10.0) __TVOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0);
@end


@interface NSData(QRSecCrypto)
- (NSData *)RSAEncryptDataWithPublicKey:(SecKeyRef)publicKey;
- (NSData *)RSADecryptDataWithPrivateKey:(SecKeyRef)privateKey;

```


OpenSSL lib built from https://github.com/x2on/OpenSSL-for-iPhone

Reference
http://www.jianshu.com/p/21bb11ff8e27
https://www.openssl.org/docs/man1.0.1/crypto/i2d_RSA_PUBKEY.html
https://github.com/StCredZero/SCZ-BasicEncodingRules-iOS
http://www.techper.net/2012/06/01/converting-rsa-public-key-modulus-and-exponent-into-pem-file/

