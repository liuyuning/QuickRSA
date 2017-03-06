//
//  QRSecCrypto.h
//  QuickRSA
//
//  Created by liuyuning on 2016/10/26.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface QRSecCrypto : NSObject
//Call CFRelease() to free SecKeyRef.

//1. Public SecKeyRef from 509 Cert
+ (SecKeyRef)RSASecKeyCreatePublicWithX509CertData:(NSData *)certData;
//2. Private SecKeyRef from P12
+ (SecKeyRef)RSASecKeyCreatePrivateWithP12Data:(NSData *)p12Data password:(NSString *)password;


//3. Use Keychain
//Turn On Keychain Sharing(Project - TARGETS - Capabilitys - Keychain Sharing - Switch On).
//This API using SecItemXXX works with Keychain, may retrun nil if the Keychain can't access.

//Public SecKeyRef must use PKCS1 format data, get it form DER format use +[QRFormatConvert RSA_PUB_PKCS1FromDER:]
+ (SecKeyRef)RSASecKeyCreatePublicWithPKCS1Data:(NSData *)pkcs1Data appTag:(NSString *)appTag;
//Private SecKeyRef use DER format data directly. [DER format] == [PKCS1 format]
+ (SecKeyRef)RSASecKeyCreatePrivateWithDERData:(NSData *)derData appTag:(NSString *)appTag;


//4. For iOS 10 and later, public key or private key.
+ (SecKeyRef)RSASecKeyCreateWithDERData_iOS10:(NSData *)derData isPublic:(BOOL)isPublic __OSX_AVAILABLE(10.12) __IOS_AVAILABLE(10.0) __TVOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0);
@end


@interface NSData(QRSecCrypto)
//Default padding is kSecPaddingPKCS1

- (NSData *)RSAEncryptDataWithPublicKey:(SecKeyRef)publicKey;//Encrypt with public key
- (NSData *)RSADecryptDataWithPrivateKey:(SecKeyRef)privateKey;//Decrypt with private key

- (NSData *)RSASignDataWithPrivateKey:(SecKeyRef)privateKey;//Sign(Encrypt) with private key
- (BOOL)RSAVerifyWithRawData:(NSData *)rawData publicKey:(SecKeyRef)publicKey;//Verify with public key (Decrypt and Compare)
@end
