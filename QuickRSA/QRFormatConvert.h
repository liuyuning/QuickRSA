//
//  QRFormatConvert.h
//  QuickRSA
//
//  Created by liuyuning on 2016/10/26.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import <Foundation/Foundation.h>

//#import <openssl/pem.h>
#ifndef HEADER_PEM_H
# define PEM_STRING_X509_OLD     "X509 CERTIFICATE"
# define PEM_STRING_X509         "CERTIFICATE"
# define PEM_STRING_X509_PAIR    "CERTIFICATE PAIR"
# define PEM_STRING_X509_TRUSTED "TRUSTED CERTIFICATE"
# define PEM_STRING_X509_REQ_OLD "NEW CERTIFICATE REQUEST"
# define PEM_STRING_X509_REQ     "CERTIFICATE REQUEST"
# define PEM_STRING_X509_CRL     "X509 CRL"
# define PEM_STRING_EVP_PKEY     "ANY PRIVATE KEY"
# define PEM_STRING_PUBLIC       "PUBLIC KEY"
# define PEM_STRING_RSA          "RSA PRIVATE KEY"
# define PEM_STRING_RSA_PUBLIC   "RSA PUBLIC KEY"
# define PEM_STRING_DSA          "DSA PRIVATE KEY"
# define PEM_STRING_DSA_PUBLIC   "DSA PUBLIC KEY"
# define PEM_STRING_PKCS7        "PKCS7"
# define PEM_STRING_PKCS7_SIGNED "PKCS #7 SIGNED DATA"
# define PEM_STRING_PKCS8        "ENCRYPTED PRIVATE KEY"
# define PEM_STRING_PKCS8INF     "PRIVATE KEY"
# define PEM_STRING_DHPARAMS     "DH PARAMETERS"
# define PEM_STRING_DHXPARAMS    "X9.42 DH PARAMETERS"
# define PEM_STRING_SSL_SESSION  "SSL SESSION PARAMETERS"
# define PEM_STRING_DSAPARAMS    "DSA PARAMETERS"
# define PEM_STRING_ECDSA_PUBLIC "ECDSA PUBLIC KEY"
# define PEM_STRING_ECPARAMETERS "EC PARAMETERS"
# define PEM_STRING_ECPRIVATEKEY "EC PRIVATE KEY"
# define PEM_STRING_PARAMETERS   "PARAMETERS"
# define PEM_STRING_CMS          "CMS"
#endif

#define USE_OPENSSL 1

@interface QRFormatConvert : NSObject

+ (NSData *)DERFromPEM:(NSData *)pemData;//PEM to DER
+ (NSData *)PEMFromDER:(NSData *)derData header:(const char *)header;//DER to PEM, header such as PEM_STRING_RSA

#if USE_OPENSSL
//Public Key
+ (NSData *)RSA_PUB_ModulusFromDER:(NSData *)derData;   //Public key modulus
+ (NSData *)RSA_PUB_ExponentFromDER:(NSData *)derData;  //Public key exponent

+ (NSData *)RSA_PUB_PKCS1FromDER:(NSData *)derData;     //Public key PKCS1 format from DER
+ (NSData *)RSA_PUB_DERFromPKCS1:(NSData *)pkcs1Data;   //Public key DER format from PKCS1

+ (NSData *)RSA_PUB_PKCS1FromModulus:(NSData *)modulus exponent:(NSData *)exponent useDER:(BOOL)useDER; //Public key PKCS1 or DER from modulus and exponent

//Private Key
//[DER format] == [PKCS1 format]
+ (NSData *)RSA_PRI_DERFromModulus:(NSData *)modulus  //Private key DER format from components
                       pubExponent:(NSData *)pubExponent
                       priExponent:(NSData *)priExponent
                            prime1:(NSData *)prime1
                            prime2:(NSData *)prime2
                         exponent1:(NSData *)exponent1
                         exponent2:(NSData *)exponent2
                       coefficient:(NSData *)coefficient;
#endif
@end

//Hex
@interface NSData(QuickRSA)
- (NSString *)hexString;
@end

@interface NSString(QuickRSA)
- (NSData *)dataFromHexString;
@end

