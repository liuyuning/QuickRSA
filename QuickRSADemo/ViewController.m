//
//  ViewController.m
//  QuickRSADemo
//
//  Created by liuyuning on 2016/10/26.
//  Copyright © 2016年 liuyuning. All rights reserved.
//

#import "ViewController.h"
#import "QuickRSA.h"

@interface ViewController (){
    NSData *_plainData;
    NSData *_encryptData;
}
@end


@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    _plainData = [@"aabbccddee" dataFromHexString];
    NSLog(@"[DAT]%@",_plainData);
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)actionSeciOS10Enc:(id)sender{
    if ([UIDevice currentDevice].systemVersion.floatValue < 10.) {
        NSLog(@"For iOS 10 and later!");
        return;
    }
    
    NSString *derPathPub = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.der" ofType:nil];
    NSData *derDataPub = [NSData dataWithContentsOfFile:derPathPub];
    
    SecKeyRef pubkey = [QRSecCrypto RSASecKeyCopyWithDERData:derDataPub isPublic:YES];
    if (pubkey) {
        _encryptData = [_plainData RSAEncryptDataWithPublicKey:pubkey];
        NSLog(@"[ENC]%@",_encryptData);
        CFRelease(pubkey);
    }
}
- (IBAction)actionSeciOS10Dec:(id)sender{
    
    if ([UIDevice currentDevice].systemVersion.floatValue < 10.) {
        NSLog(@"For iOS 10 and later!");
        return;
    }
    
    NSString *derPathPri = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.der" ofType:nil];
    NSData *derDataPri = [NSData dataWithContentsOfFile:derPathPri];
    
    SecKeyRef prikey = [QRSecCrypto RSASecKeyCopyWithDERData:derDataPri isPublic:NO];
    if (prikey) {
        NSData *decryptData = [_encryptData RSADecryptDataWithPrivateKey:prikey];
        NSLog(@"[DEC]%@",decryptData);
        CFRelease(prikey);
    }
}

- (IBAction)actionSecX509Enc:(id)sender{
    NSString *certDERPath = [[NSBundle mainBundle] pathForResource:@"rsa_cert_cert.der" ofType:nil];
    NSData *certDERData = [NSData dataWithContentsOfFile:certDERPath];
    
    SecKeyRef pubkey = [QRSecCrypto RSASecKeyPubCopyWithX509CertData:certDERData];
    if (pubkey) {
        _encryptData = [_plainData RSAEncryptDataWithPublicKey:pubkey];
        NSLog(@"[ENC]%@",_encryptData);
        CFRelease(pubkey);
    }
}
- (IBAction)actionSecP12Dec:(id)sender{
    
    NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"rsa_private_key_p12.p12" ofType:nil];
    NSData *p12Data = [NSData dataWithContentsOfFile:p12Path];
    
    SecKeyRef prikey = [QRSecCrypto RSASecKeyPriCopyWithP12Data:p12Data password:@"12345"];
    if (prikey) {
        NSData *decryptData = [_encryptData RSADecryptDataWithPrivateKey:prikey];
        NSLog(@"[DEC]%@",decryptData);
        CFRelease(prikey);
    }
}

//Data form DER use +[QRFormatConvert RSA_PUB_PKCS1DataWithDER:]
unsigned char PUB_KEY_PKCS1[] = {
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xce, 0xd8, 0x72, 0x7b, 0x58,
    0xd6, 0x2a, 0xe3, 0x2b, 0x46, 0xfc, 0x95, 0xa6, 0xca, 0xce, 0x01, 0x60,
    0xda, 0x92, 0xb9, 0xc8, 0xb4, 0xe5, 0xb3, 0x9f, 0xa7, 0xf9, 0xa0, 0x70,
    0xa7, 0x49, 0x21, 0x46, 0xd1, 0xfd, 0xb3, 0x93, 0xd2, 0xb2, 0xaa, 0xb1,
    0x68, 0x86, 0xd9, 0xcc, 0x63, 0x78, 0x0a, 0x59, 0xcb, 0xb5, 0xe0, 0xfb,
    0x14, 0x79, 0x0c, 0x8c, 0x5e, 0xef, 0xdb, 0xbc, 0x59, 0x28, 0x34, 0xfa,
    0xc9, 0x3f, 0x0f, 0x3e, 0x7c, 0x38, 0xf3, 0x38, 0xd6, 0x73, 0xf0, 0x03,
    0x37, 0xb8, 0xa9, 0x3e, 0xbd, 0x25, 0xde, 0x17, 0xdf, 0x1c, 0xc1, 0x56,
    0xe5, 0x42, 0xbe, 0x02, 0x81, 0x54, 0x28, 0x90, 0x41, 0xe6, 0x17, 0xdc,
    0x5e, 0x6b, 0xfc, 0x0c, 0x56, 0xbe, 0x98, 0x67, 0x02, 0xd2, 0x74, 0xd0,
    0x01, 0xc6, 0x5c, 0xe3, 0x77, 0x04, 0x1a, 0xba, 0x15, 0x62, 0x98, 0x54,
    0x05, 0x16, 0xd7, 0x02, 0x03, 0x01, 0x00, 0x01
};
unsigned int PUB_KEY_PKCS1_len = 140;

- (IBAction)actionSecKeyChainPKCS1Enc:(id)sender{
    
    //NSString *derPathPub = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.der" ofType:nil];
    //NSData *derDataPub = [NSData dataWithContentsOfFile:derPathPub];
    //NSData *pkcs1Data = [QRFormatConvert RSA_PUB_PKCS1DataWithDER:derDataPub];
    
    //NSString *hexModulus = @"CED8727B58D62AE32B46FC95A6CACE0160DA92B9C8B4E5B39FA7F9A070A7492146D1FDB393D2B2AAB16886D9CC63780A59CBB5E0FB14790C8C5EEFDBBC592834FAC93F0F3E7C38F338D673F00337B8A93EBD25DE17DF1CC156E542BE028154289041E617DC5E6BFC0C56BE986702D274D001C65CE377041ABA156298540516D7";
    ////hexModulus = [@"00" stringByAppendingString:hexModulus];
    //NSString *hexExponent = @"010001";
    //NSData *pkcs1Data = [QRFormatConvert RSA_PUB_PKCS1FromModulus:[hexModulus dataFromHexString] exponent:[hexExponent dataFromHexString] useDER:NO];
    
    NSData *pkcs1Data = [NSData dataWithBytes:PUB_KEY_PKCS1 length:PUB_KEY_PKCS1_len];
    
    SecKeyRef pubkey = [QRSecCrypto RSASecKeyCopyWithPKCS1Data:pkcs1Data appTag:@"TestRSA" isPublic:YES];
    if (pubkey) {
        _encryptData = [_plainData RSAEncryptDataWithPublicKey:pubkey];
        NSLog(@"[ENC]%@",_encryptData);
        CFRelease(pubkey);
    }
}
- (IBAction)actionSecKeyChainPKCS1Dec:(id)sender{
    //Pri DER data is PKCS1 format
    NSString *derPathPri = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.der" ofType:nil];
    NSData *derDataPri = [NSData dataWithContentsOfFile:derPathPri];
    
    SecKeyRef prikey = [QRSecCrypto RSASecKeyCopyWithPKCS1Data:derDataPri appTag:@"TestRSA" isPublic:NO];
    if (prikey) {
        NSData *decryptData = [_encryptData RSADecryptDataWithPrivateKey:prikey];
        NSLog(@"[DEC]%@",decryptData);
        CFRelease(prikey);
    }
}


//PEM <-> DER
- (IBAction)actionFromatPEMAndDER:(id)sender{
    
    NSString *derPath = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.der" ofType:nil];
    NSString *pemPath = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.pem" ofType:nil];
    
    NSData *derData = [NSData dataWithContentsOfFile:derPath];
    NSData *pemData = [NSData dataWithContentsOfFile:pemPath];
    
    NSLog(@"%@",derData);
    NSLog(@"%@",[[NSString alloc] initWithData:pemData encoding:NSUTF8StringEncoding]);
    
    NSData *derData1 = [QRFormatConvert DERFromPEM:pemData];
    NSData *pemData1 = [QRFormatConvert PEMFromDER:derData header:PEM_STRING_PUBLIC];
    
    NSLog(@"%@",derData1);
    NSLog(@"%@",[[NSString alloc] initWithData:pemData1 encoding:NSUTF8StringEncoding]);
    
    if ([derData isEqualToData:derData1]) {
        NSLog(@"DER is Equal!");
    }
    if ([pemData isEqualToData:pemData1]) {
        NSLog(@"PEM is Equal!");
    }
}



//OpenSSL
- (IBAction)actionOpenSSLDEREnc:(id)sender{
    NSString *path = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.der" ofType:nil];
    NSData *keyData = [NSData dataWithContentsOfFile:path];
    
    _encryptData = [_plainData OpenSSL_RSA_EncryptDataWithDER:keyData isPublic:YES];
    NSLog(@"[ENC]%@",_encryptData);
}
- (IBAction)actionOpenSSLDERDec:(id)sender{
    
    NSString *path = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.der" ofType:nil];
    NSData *keyData = [NSData dataWithContentsOfFile:path];
    
    NSData *decryptData = [_encryptData OpenSSL_RSA_DecryptDataWithDER:keyData isPublic:NO];
    NSLog(@"[DEC]%@",decryptData);
}

- (IBAction)actionOpenSSLPEMEnc:(id)sender{
    NSString *path = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.pem" ofType:nil];
    NSData *keyData = [NSData dataWithContentsOfFile:path];
    
    _encryptData = [_plainData OpenSSL_RSA_EncryptDataWithPEM:keyData isPublic:YES];
    NSLog(@"[ENC]%@",_encryptData);
}
- (IBAction)actionOpenSSLPEMDec:(id)sender{
    NSString *path = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.pem" ofType:nil];
    NSData *keyData = [NSData dataWithContentsOfFile:path];
    
    NSData *decryptData = [_encryptData OpenSSL_RSA_DecryptDataWithPEM:keyData isPublic:NO];
    NSLog(@"[DEC]%@",decryptData);
}

- (IBAction)actionOpenSSLModExpEnc:(id)sender{
    
    NSString *hexModulus = @"CED8727B58D62AE32B46FC95A6CACE0160DA92B9C8B4E5B39FA7F9A070A7492146D1FDB393D2B2AAB16886D9CC63780A59CBB5E0FB14790C8C5EEFDBBC592834FAC93F0F3E7C38F338D673F00337B8A93EBD25DE17DF1CC156E542BE028154289041E617DC5E6BFC0C56BE986702D274D001C65CE377041ABA156298540516D7";
    NSString *hexExponent = @"010001";
    
    _encryptData = [_plainData OpenSSL_RSA_DataWithPublicModulus:[hexModulus dataFromHexString] exponent:[hexExponent dataFromHexString] isDecrypt:NO];
    NSLog(@"[ENC]%@",_encryptData);
}

- (IBAction)actionOpenSSLPriEncPubDec:(id)sender{
    
    NSString *derPathPri = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.der" ofType:nil];
    NSString *derPathPub = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.der" ofType:nil];
    
    NSData *derDataPri = [NSData dataWithContentsOfFile:derPathPri];
    NSData *derDataPub = [NSData dataWithContentsOfFile:derPathPub];
    
    NSString *text = @"Hello!";
    NSLog(@"[TXT]%@",text);
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encData = [data OpenSSL_RSA_EncryptDataWithDER:derDataPri isPublic:NO];
    NSLog(@"[ENC]%@",encData);
    NSData *decData = [encData OpenSSL_RSA_DecryptDataWithDER:derDataPub isPublic:YES];
    NSLog(@"[DEC]%@",[[NSString alloc] initWithData:decData encoding:NSUTF8StringEncoding]);
}

- (IBAction)actionOpenSSLFormatConvert:(id)sender{
    //Pub
    NSString *derPathPub = [[NSBundle mainBundle] pathForResource:@"rsa_public_key.der" ofType:nil];
    NSData *derDataPub = [NSData dataWithContentsOfFile:derPathPub];
    
    NSLog(@"Pub Modulus:%@",[QRFormatConvert RSA_PUB_ModulusFromDER:derDataPub]);
    NSLog(@"Pub Exponent:%@",[QRFormatConvert RSA_PUB_ExponentFromDER:derDataPub]);
    
    NSLog(@"Pub PKCS1:%@",[QRFormatConvert RSA_PUB_PKCS1FromDER:derDataPub]);
    NSData *pkcs1Data = [NSData dataWithBytes:PUB_KEY_PKCS1 length:PUB_KEY_PKCS1_len];
    NSLog(@"Pub DER From PKCS1:%@",[QRFormatConvert RSA_PUB_DERFromPKCS1:pkcs1Data]);
    
    NSString *hexModulus = @"CED8727B58D62AE32B46FC95A6CACE0160DA92B9C8B4E5B39FA7F9A070A7492146D1FDB393D2B2AAB16886D9CC63780A59CBB5E0FB14790C8C5EEFDBBC592834FAC93F0F3E7C38F338D673F00337B8A93EBD25DE17DF1CC156E542BE028154289041E617DC5E6BFC0C56BE986702D274D001C65CE377041ABA156298540516D7";
    NSString *hexPubExponent = @"010001";
    
    NSLog(@"Pub PKCS1 From Mod&Exp:%@",[QRFormatConvert RSA_PUB_PKCS1FromModulus:[hexModulus dataFromHexString] exponent:[hexPubExponent dataFromHexString] useDER:NO]);
    NSLog(@"Pub DER From Mod&Exp:%@",[QRFormatConvert RSA_PUB_PKCS1FromModulus:[hexModulus dataFromHexString] exponent:[hexPubExponent dataFromHexString] useDER:YES]);
    
    
    //Pri
    NSString *derPathPri = [[NSBundle mainBundle] pathForResource:@"rsa_private_key.der" ofType:nil];
    NSData *derDataPri = [NSData dataWithContentsOfFile:derPathPri];
    
    NSString *hexPriExponent = @"47FEC8A22C42A73CD8C46588453CD3C5610BD3043D5AD194DADE61A1B974509CF78481D4AE8028D606D8060FEAF738420A0D40AA255A73E3AD3C222A8E7D4DE3BAB09DFF36B51D8E0A94BEAACE86F4DFBD0EB385BBC0AB315E798D9037F2250B8FFCE7E482F6C6E2BF967A173D4BF687A0977707675AE146AA477633A3ADA951";
    NSString *hexPrime1 = @"E7E8D96B810AF13545AA188686094069F049E8B25D614B63530820F8A64ACDA8B884A66F019B2FE4B4477A3FA59199B64FE59826909E03A38749E896375BEADF";
    NSString *hexPrime2 = @"E455123EF6C0BEB34C4E562477AC81C19D0C7771F7CEBBDA5DA83A57036A4E8BE81E7BAC75685818D7AE5FCA0E22B89BC3D398BD3733FCEF82A1A2154DD5CB09";
    NSString *hexExponent1 = @"89B46F1DF1C3109564676B26BE02525855915D76441298D442A28A097B9CE15FB5293736A50A8436D681B6EA8222E1D62ABD174A9706ECFC364241B4A8EC909B";
    NSString *hexExponent2 = @"37EEB6F7818E99A8664AD24340A59B6B884323876182DCF592F7C0C2CBED60AC59020E9DA26D1B178ACE065D02B572AF857AF1F177F25E4575A48E85D57947B1";
    NSString *hexCoefficient = @"B0D03F9EBAD8D99496286F16DEDFB31FEACF58B54571BBB4558112390320749B2D7E572A4A3F83937681995E812C510F386D1F24B727095FFD4ED3DB64EE2405";
    
    NSData *pkcs1DataPri = [QRFormatConvert RSA_PRI_PKCS1FromModulus:[hexModulus dataFromHexString]
                                                         pubExponent:[hexPubExponent dataFromHexString]
                                                         priExponent:[hexPriExponent dataFromHexString]
                                                              prime1:[hexPrime1 dataFromHexString]
                                                              prime2:[hexPrime2 dataFromHexString]
                                                           exponent1:[hexExponent1 dataFromHexString]
                                                           exponent2:[hexExponent2 dataFromHexString]
                                                         coefficient:[hexCoefficient dataFromHexString]];
    if ([derDataPri isEqualToData:pkcs1DataPri]) {
        NSLog(@"PEM is Equal!");
    }
    NSData *decryptData = [_encryptData OpenSSL_RSA_DecryptDataWithDER:pkcs1DataPri isPublic:NO];
    NSLog(@"[DEC]%@",decryptData);
}


@end


