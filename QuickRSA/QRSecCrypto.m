//
//  QRSecCrypto.m
//  QuickRSA
//
//  Created by liuyuning on 2016/10/26.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import "QRSecCrypto.h"

@implementation QRSecCrypto

//Public SecKeyRef from 509 Cert
+ (SecKeyRef)RSASecKeyCreatePublicWithX509CertData:(NSData *)certData{
    if (!certData) {
        return NULL;
    }
    
    SecKeyRef publicKey = NULL;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    if (policy) {
        SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
        if (certificate) {
            SecTrustRef trust = NULL;
            OSStatus status = SecTrustCreateWithCertificates(certificate, policy, &trust);
            if (errSecSuccess != status) {
                NSLog(@"SecTrustCreateWithCertificates status:%d",(int)status);
            }
            
            if (trust) {
                publicKey = SecTrustCopyPublicKey(trust);
                CFRelease(trust);
            }
            CFRelease(certificate);
        }
        CFRelease(policy);
    }
    
    //return publicKey ? (SecKeyRef)CFAutorelease(publicKey) : NULL;
    return publicKey;
}

//Private SecKeyRef from P12
+ (SecKeyRef)RSASecKeyCreatePrivateWithP12Data:(NSData *)p12Data password:(NSString *)password{
    
    if (!p12Data || !password) {
        return NULL;
    }
    
    SecKeyRef privateKey = NULL;
    
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    if (options) {
        CFDictionaryAddValue(options, kSecImportExportPassphrase, (__bridge CFStringRef)password);
        
        CFArrayRef items = NULL;
        OSStatus status = SecPKCS12Import((__bridge CFDataRef)p12Data, options, &items);
        if (errSecSuccess != status) {
            NSLog(@"SecPKCS12Import status:%d",(int)status);
        }
        
        CFRelease(options);
        
        if (items) {
            if (CFArrayGetCount(items)) {
                CFDictionaryRef dict = CFArrayGetValueAtIndex(items, 0);
                if (dict) {
                    SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(dict, kSecImportItemIdentity);
                    if (identity) {
                        status = SecIdentityCopyPrivateKey(identity, &privateKey);
                        if (errSecSuccess != status) {
                            NSLog(@"SecIdentityCopyPrivateKey status:%d",(int)status);
                        }
                    }
                }
            }
            CFRelease(items);
        }
    }
    return privateKey;
}

//Use Keychain
+ (SecKeyRef)RSASecKeyCreateWithData:(NSData *)pkcs1Data appTag:(NSString *)appTag isPublic:(BOOL)isPublic{
    if(!pkcs1Data || !appTag){
        return NULL;
    }
    
    SecKeyRef secKey = NULL;
    NSData *tagData = [appTag dataUsingEncoding:NSUTF8StringEncoding];
    
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    if (attributes) {
        CFDictionaryAddValue(attributes, kSecClass, kSecClassKey);
        CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionaryAddValue(attributes, kSecAttrKeyClass, isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate);
        CFDictionaryAddValue(attributes, kSecAttrApplicationTag, (__bridge CFDataRef)tagData);
        CFDictionaryAddValue(attributes, kSecReturnRef, kCFBooleanTrue);
        
        //SecItemDelete(attributes);
        OSStatus status = SecItemCopyMatching(attributes, (CFTypeRef *)&secKey);
        if (errSecItemNotFound == status) {
            CFDictionaryAddValue(attributes, kSecValueData, (__bridge CFDataRef)pkcs1Data);
            status = SecItemAdd(attributes, (CFTypeRef *)&secKey);
        }
        
        if (errSecSuccess == status) {
            //NSLog(@"%@",secKey);
        }
        else if(-34018 == status){
            NSLog(@"Please enable 'Keychain Sharing' in Project Capabilitys!!! status:%d",(int)status);
        }
        else{
            NSLog(@"status:%d",(int)status);
        }
        
        CFRelease(attributes);
    }
    return secKey;
}

//Public SecKeyRef must use PKCS1 format data, get it form DER format use +[QRFormatConvert RSA_PUB_PKCS1FromDER:].
+ (SecKeyRef)RSASecKeyCreatePublicWithPKCS1Data:(NSData *)pkcs1Data appTag:(NSString *)appTag{
    return [self RSASecKeyCreateWithData:pkcs1Data appTag:appTag isPublic:YES];
}

//Private SecKeyRef use DER format data directly. [DER format] == [PKCS1 format]
+ (SecKeyRef)RSASecKeyCreatePrivateWithDERData:(NSData *)derData appTag:(NSString *)appTag{
    return [self RSASecKeyCreateWithData:derData appTag:appTag isPublic:NO];
}


//For iOS 10 and later, public key or private key.
+ (SecKeyRef)RSASecKeyCreateWithDERData_iOS10:(NSData *)derData isPublic:(BOOL)isPublic{
    if (!derData) {
        return NULL;
    }
    
    SecKeyRef secKey = NULL;
#if __IPHONE_OS_VERSION_MAX_ALLOWED  >= 100000 //__IPHONE_10_0
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    if (attributes) {
        CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionaryAddValue(attributes, kSecAttrKeyClass, isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate);
        //CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, (__bridge CFNumberRef)@(1024));
        
        CFErrorRef error = NULL;
        secKey = SecKeyCreateWithData((__bridge CFDataRef)derData, attributes, &error);
        if (error) {
            NSLog(@"SecKeyCreateWithData %@",error);
        }
        CFRelease(attributes);
    }
#endif
    return secKey;
}
@end



@implementation NSData(QRSecCrypto)
- (NSData *)RSAEncryptDataWithKey:(SecKeyRef)key isPublic:(BOOL)isPublic{
    if (self.length && key) {
        
        size_t blockSize = SecKeyGetBlockSize(key);
        size_t cipherLen = blockSize;//Should set cipherLen before SecKeyEncrypt
        uint8_t *buffer = malloc(cipherLen);
        
        if (buffer) {
            
            NSUInteger offset = 0;
            NSUInteger length = 0;
            
            NSData *plainData = self;
            NSMutableData *cipherData = [NSMutableData data];
            
            do {
                length = plainData.length - offset;
                if (length > blockSize - 11) {
                    length = blockSize - 11;
                }
                
                //memset(buffer, 0, cipherLen);
                OSStatus status = errSecSuccess;
                if (isPublic) {
                    status = SecKeyEncrypt(key, kSecPaddingPKCS1, (uint8_t *)(plainData.bytes + offset), length, buffer, &cipherLen);
                }
                else{
                    status = SecKeyRawSign(key, kSecPaddingPKCS1, (uint8_t *)(plainData.bytes + offset), length, buffer, &cipherLen);//kSecPaddingPKCS1SHA1
                }
                
                if (errSecSuccess == status) {
                    [cipherData appendBytes:buffer length:cipherLen];
                }
                else{
                    NSLog(@"SecKeyEncrypt/SecKeyRawSign status:%d",(int)status);
                    cipherData = nil;
                    break;
                }
                
                offset += length;
                
            } while (offset < plainData.length);
            free(buffer);
            
            return cipherData;
        }
    }
    return nil;
}

//Encrypt with public key
- (NSData *)RSAEncryptDataWithPublicKey:(SecKeyRef)publicKey{
    return [self RSAEncryptDataWithKey:publicKey isPublic:YES];
}

//Decrypt with private key
- (NSData *)RSADecryptDataWithPrivateKey:(SecKeyRef)privateKey{
    if (self.length && privateKey) {
        
        size_t blockSize = SecKeyGetBlockSize(privateKey);
        size_t plainLen = blockSize;
        uint8_t *buffer = malloc(plainLen);
        
        if (buffer) {
            
            NSData *cipherData = self;
            NSMutableData *plainData = [NSMutableData data];
            
            for (int i = 0; i < cipherData.length / blockSize; i++) {
                
                //memset(buffer, 0, plainLen);
                
                //1. Decrypt with public key and kSecPaddingPKCS1 will receive error code -9809. (errSSLCrypto = -9809, /* underlying cryptographic error */ SecureTransport.h)
                //2. Decrypt with public key and kSecPaddingNone will success, but the decrypted data format incorrect!
                OSStatus status = SecKeyDecrypt(privateKey, kSecPaddingPKCS1, (uint8_t *)(cipherData.bytes + blockSize * i), blockSize, buffer, &plainLen);
                if (errSecSuccess == status) {
                    [plainData appendBytes:buffer length:plainLen];
                }
                else{
                    NSLog(@"SecKeyDecrypt status:%d",(int)status);
                    plainData = nil;
                    break;
                }
            }
            free(buffer);
            
            return plainData;
        }
    }
    return nil;
}


//Sign(Encrypt) with private key
- (NSData *)RSASignDataWithPrivateKey:(SecKeyRef)privateKey{
    return [self RSAEncryptDataWithKey:privateKey isPublic:NO];
}

//Verify with public key (Decrypt and Compare)
- (BOOL)RSAVerifyWithRawData:(NSData *)rawData publicKey:(SecKeyRef)publicKey{
    if (self.length && rawData.length && publicKey) {
        
        size_t blockSize = SecKeyGetBlockSize(publicKey);
        size_t plainLen = blockSize - 11;
        
        NSData *cipherData = self;
        
        for (int i = 0; i < cipherData.length / blockSize; i++) {
            
            size_t inLen = rawData.length - plainLen * i;
            if (inLen > plainLen) {
                inLen = plainLen;
            }
            
            OSStatus status = SecKeyRawVerify(publicKey, kSecPaddingPKCS1, rawData.bytes + plainLen * i, inLen, cipherData.bytes + blockSize * i, blockSize);
            if (errSecSuccess != status) {
                NSLog(@"SecKeyRawVerify status:%d",(int)status);
                return NO;
            }
        }
        return YES;
    }
    return NO;
}

@end
