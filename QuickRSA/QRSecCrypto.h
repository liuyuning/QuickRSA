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
@end

