//
//  QRFormatConvert.m
//  QuickRSA
//
//  Created by liuyuning on 2016/10/26.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import "QRFormatConvert.h"

#if USE_OPENSSL
#import <openssl/pem.h>
//#import <openssl/rsa.h>
//#import <openssl/bn.h>
#endif

@implementation QRFormatConvert
+ (NSData *)DERFromPEM:(NSData *)pemData{
    NSRange range1 = [pemData rangeOfData:[NSData dataWithBytes:"-----\n" length:6] options:0 range:NSMakeRange(0, pemData.length)];
    NSRange range2 = [pemData rangeOfData:[NSData dataWithBytes:"\n-----" length:6] options:0 range:NSMakeRange(0, pemData.length)];
    
    if ((range1.location !=  NSNotFound) && (range2.location !=  NSNotFound)) {
        CFIndex start = range1.location + range1.length;
        pemData = [pemData subdataWithRange:NSMakeRange(start, range2.location - start)];
        return [[NSData alloc] initWithBase64EncodedData:pemData options:NSDataBase64DecodingIgnoreUnknownCharacters];
    }
    return nil;
}

+ (NSData *)PEMFromDER:(NSData *)derData header:(const char *)header{
    NSString *base64 = [derData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithLineFeed];
    NSString *pemString = [NSString stringWithFormat:@"-----BEGIN %s-----\n%@\n-----END %s-----\n",header,base64,header];
    return [pemString dataUsingEncoding:NSUTF8StringEncoding];
}


#if USE_OPENSSL
//Pub
+ (NSData *)RSA_PUB_ModulusFromDER:(NSData *)derData{
    
    if (!derData) {
        return nil;
    }
    
    NSData *data = nil;
    const unsigned char *pp = (const unsigned char *)derData.bytes;
    RSA *rsa = d2i_RSA_PUBKEY(NULL, &pp, derData.length);
    if (rsa) {
        int length = BN_num_bits(rsa -> n);
        unsigned char *buffer = malloc(length);
        if (buffer) {
            int outLen = BN_bn2bin(rsa -> n, buffer);
            if (outLen > 0) {
                data = [NSData dataWithBytes:buffer length:outLen];
            }
            free(buffer);
        }
        RSA_free(rsa);
    }
    return data;
}

+ (NSData *)RSA_PUB_ExponentFromDER:(NSData *)derData{
    if (!derData) {
        return nil;
    }
    
    NSData *data = nil;
    const unsigned char *pp = (const unsigned char *)derData.bytes;
    RSA *rsa = d2i_RSA_PUBKEY(NULL, &pp, derData.length);
    if (rsa) {
        int length = BN_num_bits(rsa -> e);
        unsigned char *buffer = malloc(length);
        if (buffer) {
            int outLen = BN_bn2bin(rsa -> e, buffer);
            if (outLen > 0) {
                data = [NSData dataWithBytes:buffer length:outLen];
            }
            free(buffer);
        }
        RSA_free(rsa);
    }
    return data;
}

+ (NSData *)RSA_PUB_PKCS1FromDER:(NSData *)derData{
    if (!derData) {
        return nil;
    }
    
    NSData *data = nil;
    const unsigned char *pp = (const unsigned char *)derData.bytes;
    RSA *rsa = d2i_RSA_PUBKEY(NULL, &pp, derData.length);
    if (rsa) {
        unsigned char *pOut = NULL;
        int length = i2d_RSAPublicKey(rsa, &pOut);
        if (pOut) {
            if (length > 0) {
                data = [NSData dataWithBytes:pOut length:length];
            }
            free(pOut);
        }
        RSA_free(rsa);
    }
    return data;
}

+ (NSData *)RSA_PUB_DERFromPKCS1:(NSData *)pkcs1Data{
    if (!pkcs1Data) {
        return nil;
    }
    
    NSData *data = nil;
    const unsigned char *pp = (const unsigned char *)pkcs1Data.bytes;
    RSA *rsa = d2i_RSAPublicKey(NULL, &pp, pkcs1Data.length);
    if (rsa) {
        unsigned char *pOut = NULL;
        int length = i2d_RSA_PUBKEY(rsa, &pOut);
        if (pOut) {
            if (length > 0) {
                data = [NSData dataWithBytes:pOut length:length];
            }
            free(pOut);
        }
        RSA_free(rsa);
    }
    return data;
}

+ (NSData *)RSA_PUB_PKCS1FromModulus:(NSData *)modulus exponent:(NSData *)exponent useDER:(BOOL)useDER{
    if (!modulus || !exponent) {
        return nil;
    }
    
    NSData *keyData = nil;
    RSA *rsa = RSA_new();
    if (rsa) {
        BIGNUM *n = BN_bin2bn(modulus.bytes, (int)modulus.length, NULL);
        BIGNUM *e = BN_bin2bn(exponent.bytes, (int)exponent.length, NULL);
        
        rsa->e = e;
        rsa->n = n;
        
        if (e && n) {
            //i2d_PublicKey(EVP_PKEY *a, unsigned char **pp)
            
            //d2i_RSAPublicKey() and i2d_RSAPublicKey() decode and encode a PKCS#1 RSAPublicKey structure.
            //i2d_RSAPublicKey(const RSA *a, unsigned char **out)
            //i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa)
            //i2d_RSAPublicKey_bio(BIO *bp, RSA *rsa)
            
            //d2i_RSA_PUBKEY() and i2d_RSA_PUBKEY() decode and encode an RSA public key using a SubjectPublicKeyInfo (certificate public key) structure.
            //i2d_RSA_PUBKEY(RSA *a, unsigned char **pp)
            //i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa)
            //i2d_RSA_PUBKEY_bio(BIO *bp, RSA *rsa)
            
            unsigned char *pOut = NULL;
            int length = useDER ? i2d_RSA_PUBKEY(rsa, &pOut) : i2d_RSAPublicKey(rsa, &pOut);
            if (pOut) {
                if (length > 0) {
                    keyData = [NSData dataWithBytes:pOut length:length];
                }
                free(pOut);
            }
        }
        RSA_free(rsa);
        //BN_free(n);//Free by RSA_free()
        //BN_free(e);//Free by RSA_free()
    }
    return keyData;
}

//Pri
+ (NSData *)RSA_PRI_PKCS1FromModulus:(NSData *)modulus
                         pubExponent:(NSData *)pubExponent
                         priExponent:(NSData *)priExponent
                              prime1:(NSData *)prime1
                              prime2:(NSData *)prime2
                           exponent1:(NSData *)exponent1
                           exponent2:(NSData *)exponent2
                         coefficient:(NSData *)coefficient
{
    
    if (!modulus || !pubExponent || !(priExponent || (prime1 && prime2 && exponent1 && exponent2 && coefficient))) {
        return nil;
    }
    
    NSData *keyData = nil;
    RSA *rsa = RSA_new();
    if (rsa) {
        
        BIGNUM *n = BN_bin2bn(modulus.bytes, (int)modulus.length, NULL);//modulus
        BIGNUM *e = BN_bin2bn(pubExponent.bytes, (int)pubExponent.length, NULL);//publicExponent
        BIGNUM *d = BN_bin2bn(priExponent.bytes, (int)priExponent.length, NULL);//privateExponent
        BIGNUM *p = BN_bin2bn(prime1.bytes, (int)prime1.length, NULL);//prime1
        BIGNUM *q = BN_bin2bn(prime2.bytes, (int)prime2.length, NULL);//prime2
        BIGNUM *dmp1 = BN_bin2bn(exponent1.bytes, (int)exponent1.length, NULL);//exponent1
        BIGNUM *dmq1 = BN_bin2bn(exponent2.bytes, (int)exponent2.length, NULL);//exponent2
        BIGNUM *iqmp = BN_bin2bn(coefficient.bytes, (int)coefficient.length, NULL);//coefficient
        
        rsa->e = e;//modulus
        rsa->n = n;//publicExponent
        rsa->d = d;//privateExponent
        rsa->p = p;//prime1
        rsa->q = q;//prime2
        rsa->dmp1 = dmp1;//exponent1
        rsa->dmq1 = dmq1;//exponent2
        rsa->iqmp = iqmp;//coefficient
        
        if (e && n && (d || (p && q && dmp1 && dmq1 && iqmp))) {
            
            //d2i_RSAPrivateKey(), i2d_RSAPrivateKey() decode and encode a PKCS#1 RSAPrivateKey structure.
            
            //i2d_RSAPrivateKey(const RSA *a, unsigned char **out)
            //i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa)
            //i2d_RSAPrivateKey_bio(BIO *bp, RSA *rsa)
            
            unsigned char *pOut = NULL;
            int length = i2d_RSAPrivateKey(rsa, &pOut);
            if (pOut) {
                if (length > 0) {
                    keyData = [NSData dataWithBytes:pOut length:length];
                }
                free(pOut);
            }
        }
        RSA_free(rsa);
        //BN_free(n);//Free by RSA_free()
        //BN_free(e);//Free by RSA_free()
    }
    return keyData;
}
#endif

@end




@implementation NSData(QuickRSA)
- (NSString *)hexString{
    NSMutableString *string = [NSMutableString string];
    for (int i = 0; i < self.length; i++) {
        [string appendFormat:@"%02X",*((uint8_t *)self.bytes + i)];
    }
    return string;
}
@end

@implementation NSString(QuickRSA)
- (NSData *)dataFromHexString{
    
    const char *string = [self cStringUsingEncoding:NSUTF8StringEncoding];
    size_t length = strlen(string);
    
    if (length % 2 != 0) {
        return nil;
    }
    
    NSMutableData *data = [NSMutableData data];
    
    for (int i = 0; i < length; i += 2) {
        char byte1 = *(string + i);
        char byte2 = *(string + i + 1);
        
        int8_t value1 = 0;
        int8_t value2 = 0;
        
        if (byte1 >= 'a') {
            value1 = byte1 - 'a' + 10;
        }
        else if (byte1 >= 'A'){
            value1 = byte1 - 'A' + 10;
        }
        else if (byte1 >= '0'){
            value1 = byte1 - '0';
        }
        
        if (byte2 >= 'a') {
            value2 = byte2 - 'a' + 10;
        }
        else if (byte2 >= 'A'){
            value2 = byte2 - 'A' + 10;
        }
        else if (byte2 >= '0'){
            value2 = byte2 - '0';
        }
        
        if (value1 < 0 || value1 > 15 || value2 < 0 || value2 > 15) {
            data = nil;
            break;
        }
        
        int8_t value = value1 * 16 + value2;
        [data appendBytes:&value length:1];
    }
    return data;
}
@end


