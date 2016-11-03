# QuickRSA
RSA Encrypt and Decrypt lib and demo for iOS (Using Security.framework and OpenSSL)


#### 1. Run script gen_rsa_key.sh generate RSA keys.

WARNING: DO NOT RELEASE "PRIVATE KEY" IN PACKAGE(注意：切记不要把私钥一起打包发布)

```shell
$sh gen_rsa_key.sh  #Generate a peer keys of RSA
$sh test_rsa_key.sh #Test
```


#### 2. Create a RSA SecKeyRef

```objc
@interface QRSecCrypto : NSObject
//1. 509 Cert
+ (SecKeyRef)RSASecKeyPubCopyWithX509CertData:(NSData *)certData;
//2. Import P12 for private key
+ (SecKeyRef)RSASecKeyPriCopyWithP12Data:(NSData *)p12Data password:(NSString *)password;
//3. Use Keychain
+ (SecKeyRef)RSASecKeyCopyWithPKCS1Data:(NSData *)pkcs1Data appTag:(NSString *)appTag isPublic:(BOOL)isPublic;
//4. Use System API (For iOS 10 and later only)
+ (SecKeyRef)RSASecKeyCopyWithDERData:(NSData *)derData isPublic:(BOOL)isPublic;
@end
```


Keychain API "SecItemAdd" and "SecItemCopyMatching" for getting SecKeyRef may return NULL(钥匙串函数"SecItemAdd"和"SecItemCopyMatching"获取SecKeyRef可能返回NULL).
The func +[QRSecCrypto RSASecKeyCopyWithPKCS1Data:appTag:isPublic:] not always return SecKeyRef.

The system log of SecItemXXX return error:
```txt
Jul  7 18:51:48 iPhone securityd[212] <Error>:  securityd_xpc_dictionary_handler TestApp[780] copy_matching Error Domain=NSOSStatusErrorDomain Code=-34018 "client has neither application-identifier nor keychain-access-groups entitlements" UserInfo={NSDescription=client has neither application-identifier nor keychain-access-groups entitlements}
Jul  7 18:51:48 iPhone TestApp[780] <Error>:  SecOSStatusWith error:[-34018] Error Domain=NSOSStatusErrorDomain Code=-34018 "client has neither application-identifier nor keychain-access-groups entitlements" UserInfo={NSDescription=client has neither application-identifier nor keychain-access-groups entitlements}
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
@interface NSData(OpenSSL)
//Use PEM, Pub(Pri) Enc -> Pri(Pub) Dec
- (NSData *)OpenSSL_RSA_EncryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic;//PEM key
- (NSData *)OpenSSL_RSA_DecryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic;//PEM key

//Use DER, Pub(Pri) Enc -> Pri(Pub) Dec
- (NSData *)OpenSSL_RSA_EncryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic;//DER key
- (NSData *)OpenSSL_RSA_DecryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic;//DER key

//Use modulus exponent
- (NSData *)OpenSSL_RSA_DataWithPublicModulus:(NSData *)modulus exponent:(NSData *)exponent isDecrypt:(BOOL)isDecrypt;
#endif
```

#### 5. Format convert class "QRFormatConvert"

PEM <-> DER

modulus, exponent <-> DER

PKCS1 <-> DER

Data <->Hex string


#### 6. Link error

Project Settings add "Other Linker Flags" -ObjC or -all_load


#### 7. Reference

 1. https://github.com/x2on/OpenSSL-for-iPhone (OpenSSL lib）
 2. http://www.jianshu.com/p/21bb11ff8e27
 3. https://www.openssl.org/docs/man1.0.1/crypto/i2d_RSA_PUBKEY.html
 4. https://github.com/StCredZero/SCZ-BasicEncodingRules-iOS
 5. http://www.techper.net/2012/06/01/converting-rsa-public-key-modulus-and-exponent-into-pem-file/
 6. http://www.dsm.fordham.edu/~mathai/openssl.html
 7. https://gist.github.com/lvjian700/635368d6f1e421447680
