//
//  NSData+OpenSSL.m
//  QuickRSA
//
//  Created by liuyuning on 2016/10/19.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import "NSData+OpenSSL.h"

#if USE_OPENSSL
#import <openssl/pem.h>
//#import <openssl/rsa.h>
//#import <openssl/bn.h>

@implementation NSData(OpenSSL)

- (NSData *)OpenSSL_RSA_DataEncryptWithKey:(RSA *)rsaKey isPublic:(BOOL)isPublic{
    
    NSData *plainData = self;
    NSMutableData *cipherData = [NSMutableData data];
    
    if (rsaKey) {
        int size = RSA_size(rsaKey);
        uint8_t *buffer = malloc(size);
        if (buffer) {
            
            NSUInteger offset = 0;
            NSUInteger length = 0;
            
            do {
                length = plainData.length - offset;
                if (length > size - 11) {
                    length = size - 11;
                }
                
                int out_len = 0;
                if (isPublic) {
                    out_len = RSA_public_encrypt((int)length, (uint8_t *)plainData.bytes + offset, buffer, rsaKey, RSA_PKCS1_PADDING);
                }
                else{
                    out_len = RSA_private_encrypt((int)length, (uint8_t *)plainData.bytes + offset, buffer, rsaKey, RSA_PKCS1_PADDING);
                }
                
                if (out_len > 0) {
                    [cipherData appendBytes:buffer length:out_len];
                }
                else{
                    NSLog(@"RSA_public_encrypt error:%d",out_len);
                    cipherData = nil;
                    break;
                }
                offset += length;
            } while (offset < self.length);
            free(buffer);
        }
    }
    return cipherData.length ? cipherData : nil;
}

- (NSData *)OpenSSL_RSA_DataDecryptWithKey:(RSA *)rsaKey isPublic:(BOOL)isPublic{
    NSMutableData *plainData = [NSMutableData data];
    NSData *cipherData = self;
    if (rsaKey) {
        int block_size = RSA_size(rsaKey);
        uint8_t *buffer = malloc(block_size);
        
        if (buffer) {
            for (int i = 0; i < cipherData.length / block_size; i++) {
                
                int out_len = 0;
                if (isPublic) {
                    out_len = RSA_public_decrypt(block_size, (uint8_t *)self.bytes + block_size * i, buffer, rsaKey, RSA_PKCS1_PADDING);
                }
                else{
                    out_len = RSA_private_decrypt(block_size, (uint8_t *)self.bytes + block_size * i, buffer, rsaKey, RSA_PKCS1_PADDING);
                }
                
                if (out_len > 0) {
                    [plainData appendBytes:buffer length:out_len];
                }
                else{
                    NSLog(@"RSA_private_decrypt error:%d",out_len);
                    plainData = nil;
                    break;
                }
            }
            free(buffer);
        }
    }
    return plainData.length ? plainData : nil;
}

- (NSData *)OpenSSL_RSA_EncryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic{
    //PEM_read_RSA_PUBKEY(FILE *fp, RSA **x, pem_password_cb *cb, void *u)
    //PEM_read_RSAPublicKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u)
    //PEM_read_RSAPrivateKey(FILE *fp, RSA **x, pem_password_cb *cb, void *u)
    
    //PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x, pem_password_cb *cb, void *u)
    //PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u)
    //PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x, pem_password_cb *cb, void *u)
    
    NSData *outData = nil;
    RSA *rsa = NULL;
    
    BIO *bio = BIO_new_mem_buf((uint8_t *)pemData.bytes, (int)pemData.length);
    if (bio) {
        rsa = isPublic ? PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL) : PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    
    if (rsa) {
        outData = [self OpenSSL_RSA_DataEncryptWithKey:rsa isPublic:isPublic];
        RSA_free(rsa);
    }
    return outData;
}
- (NSData *)OpenSSL_RSA_DecryptDataWithPEM:(NSData *)pemData isPublic:(BOOL)isPublic{
    NSData *outData = nil;
    RSA *rsa = NULL;
    
    BIO *bio = BIO_new_mem_buf((uint8_t *)pemData.bytes, (int)pemData.length);
    if (bio) {
        rsa = isPublic ? PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL) : PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    
    if (rsa) {
        outData = [self OpenSSL_RSA_DataDecryptWithKey:rsa isPublic:isPublic];
        RSA_free(rsa);
    }
    return outData;
}

- (NSData *)OpenSSL_RSA_EncryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic{
    
    if (!derData) {
        return nil;
    }
    NSData *outData = nil;
    const unsigned char *pp = derData.bytes;
    
    //BIO *bio = BIO_new_mem_buf((uint8_t *)derData.bytes, (int)derData.length);
    //RSA *rsa  = isPublic ? d2i_RSA_PUBKEY_bio(bio, NULL) : d2i_RSAPrivateKey_bio(bio, NULL);
    //BIO_free(bio);
    
    RSA *rsa = isPublic ? d2i_RSA_PUBKEY(NULL, &pp, derData.length) : d2i_RSAPrivateKey(NULL, &pp, derData.length);
    if (rsa) {
        outData = [self OpenSSL_RSA_DataEncryptWithKey:rsa isPublic:isPublic];
        RSA_free(rsa);
    }
    return outData;
}
- (NSData *)OpenSSL_RSA_DecryptDataWithDER:(NSData *)derData isPublic:(BOOL)isPublic{
    
    if (!derData) {
        return nil;
    }
    NSData *outData = nil;
    const unsigned char *pp = derData.bytes;
    RSA *rsa = isPublic ? d2i_RSA_PUBKEY(NULL, &pp, derData.length) : d2i_RSAPrivateKey(NULL, &pp, derData.length);
    if (rsa) {
        outData = [self OpenSSL_RSA_DataDecryptWithKey:rsa isPublic:isPublic];
        RSA_free(rsa);
    }
    return outData;
}


- (NSData *)OpenSSL_RSA_DataWithPublicModulus:(NSData *)modulus exponent:(NSData *)exponent isDecrypt:(BOOL)isDecrypt{
    
    if (!modulus || !exponent) {
        return nil;
    }
    
    NSData *outData = nil;
    RSA *rsa = RSA_new();
    if (rsa) {
        BIGNUM *n = BN_bin2bn(modulus.bytes, (int)modulus.length, NULL);
        BIGNUM *e = BN_bin2bn(exponent.bytes, (int)exponent.length, NULL);
        
        rsa->e = e;
        rsa->n = n;
        
        if (e && n) {
            if (isDecrypt) {
                outData = [self OpenSSL_RSA_DataDecryptWithKey:rsa isPublic:YES];
            }
            else{
                outData = [self OpenSSL_RSA_DataEncryptWithKey:rsa isPublic:YES];
            }
        }
        RSA_free(rsa);
        //BN_free(n);BN_free(e);
    }
    return outData;
}
@end

#endif
