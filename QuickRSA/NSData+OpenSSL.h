//
//  NSData+OpenSSL.h
//  QuickRSA
//
//  Created by liuyuning on 2016/10/19.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import <Foundation/Foundation.h>

#define USE_OPENSSL 1

@interface NSData(OpenSSL)

#if USE_OPENSSL
//Use PEM, Pub(Pri) Enc -> Pri(Pub) Dec
- (NSData *)OpenSSL_RSA_EncryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic;//PEM key
- (NSData *)OpenSSL_RSA_DecryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic;//PEM key

//Use DER, Pub(Pri) Enc -> Pri(Pub) Dec
- (NSData *)OpenSSL_RSA_EncryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic;//DER key
- (NSData *)OpenSSL_RSA_DecryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic;//DER key

//Use modulus exponent
- (NSData *)OpenSSL_RSA_DataWithPublicModulus:(NSData *)modulus exponent:(NSData *)exponent isDecrypt:(BOOL)isDecrypt;
//- (NSData *)OpenSSL_RSA_DataWithPrivateModulus:...
#endif

@end


