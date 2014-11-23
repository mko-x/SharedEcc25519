//
//  Ecc25519.m
//  BuildTests
//
//  Created by Frederic Jacobs on 22/07/14.
//  Copyright (c) 2014 Open Whisper Systems. All rights reserved.
//

#import "Ecc25519.h"

#define kKeyLength 32
#define kExpandedKeyLength 64
#define kSignatureLength 64

extern void curve25519_donna(unsigned char *output,
                             const unsigned char *a,
                             const unsigned char *b);

extern int crypto_ed_sign_keypair(unsigned char* pk,
                                  unsigned char* sk);

extern int crypto_ed_expand_private_key(unsigned char *ek,
                                        unsigned char *se);

extern int crypto_ed_sign(unsigned char *sm,unsigned long long *smlen,
                          const unsigned char *m,unsigned long long mlen,
                          const unsigned char *sk );

extern int crypto_ed_verify(const unsigned char *signature,
                            const unsigned char *message,
                            uint8_t message_len,
                            const unsigned char *public_key);

extern void ecc_clamp(unsigned char* k);

extern void ecc_keygen(unsigned char* P,
                       unsigned char* s,
                       unsigned char* k);

extern void ecc_curve(unsigned char* Z,
                      const unsigned char* k,
                      const unsigned char* P);

@implementation Ecc25519

+(void) ecc_curve25519_donna:(unsigned char *)output withSecret: (const unsigned char *) secret fromBasepoint: (const unsigned char *) basepoint{
    if(output == nil){
        output = malloc(kKeyLength);
    }
    ecc_curve(output, secret, basepoint);
}

+(NSData*) clamp: (NSData *) key{
    
    Byte signatureBuffer[kKeyLength];
    [key getBytes:signatureBuffer];
    
    ecc_clamp(signatureBuffer);
    
    return [NSData dataWithBytes:signatureBuffer length:kKeyLength];
}

+(NSData*) keygen: (NSData*) privateKey{
    uint8_t *keyPrivateProvided = (uint8_t*)[privateKey bytes];
    
    Byte publicDiffieHellman[kKeyLength];
    
    ecc_keygen(publicDiffieHellman, NULL, keyPrivateProvided);
    
    NSData * result = [NSData dataWithBytes:publicDiffieHellman length:sizeof(publicDiffieHellman)];
    
    return  result;
}

+(NSData*) curvePrivate:(NSData*) privateKey withPublicKey: (NSData*) publicKey{
    
    uint8_t *priv = (uint8_t*)[privateKey bytes];
    uint8_t *pub = (uint8_t*)[publicKey bytes];
    
    unsigned char * share = malloc(kKeyLength);
    
    ecc_curve(share, priv, pub);
    
    return [NSData dataWithBytes:share length:sizeof(share)];
}

+(NSData*) computePublicKeySignature: (NSData*) privateKey{
    if(privateKey.length != kKeyLength && privateKey.length != kExpandedKeyLength){
        @throw [NSException exceptionWithName:NSInvalidArgumentException reason:@"Invalid private key length != 32 byte" userInfo:nil];
    }
    if(privateKey.length == kKeyLength){
        privateKey = [Ecc25519 expandPrivateKey:privateKey];
    }
    
    //start at 32nd to last
    NSRange rng = {kKeyLength, kExpandedKeyLength - kKeyLength};
    
    NSData * res = [privateKey subdataWithRange:rng];
    
    return res;
}

+(NSData*) expandPrivateKey: (NSData*) key{
    if(key.length != kKeyLength && key.length != kExpandedKeyLength){
        @throw [NSException exceptionWithName:NSInvalidArgumentException reason:@"Invalid private key length != 32 byte" userInfo:nil];
    }
    if(key.length == kExpandedKeyLength){
        return key;
    }
    
    uint8_t *keyPrivateProvided = (uint8_t*)[key bytes];
    
    unsigned char * pub = malloc(kExpandedKeyLength);
    
    crypto_ed_expand_private_key(pub, keyPrivateProvided);
    
    return [NSData dataWithBytes:(const void *)pub length: kExpandedKeyLength];
}

+(NSData*)sign:(NSData*)message withPrivateKey:(NSData*) privateKey{
    if((privateKey.length != kKeyLength) && (privateKey.length != kExpandedKeyLength)){
        @throw [NSException exceptionWithName:NSInvalidArgumentException reason:@"Invalid private key length != 32 byte" userInfo:nil];
    }
    
    if(privateKey.length == kKeyLength){
        privateKey = [Ecc25519 expandPrivateKey:privateKey];
    }
    
    unsigned long long messageLen = message.length;
    uint8_t *messageData = (uint8_t*)[message bytes];
    
    unsigned long long signatureLength = kExpandedKeyLength + messageLen;
    Byte signatureBuffer[signatureLength];
    
    uint8_t *keyPrivateProvided = (uint8_t*)[privateKey bytes];
    
    crypto_ed_sign(signatureBuffer, &signatureLength, messageData, messageLen, keyPrivateProvided);
    
    NSData * signature = [NSData dataWithBytes:signatureBuffer length:kSignatureLength];
    
    return signature;
}

+(BOOL) verify:(NSData*) signature ofMessage:(NSData*) message withPublicKey:(NSData*) publicKey{
    [Ecc25519 ensureArg:signature withDetail:@"Signature"];
    [Ecc25519 ensureArg:message withDetail:@"Message"];
    [Ecc25519 ensureArg:publicKey withDetail:@"Public Key"];
    if(publicKey.length != kKeyLength){
        @throw [NSException exceptionWithName:NSInvalidArgumentException reason:@"Invalid public key length != 32 byte" userInfo:nil];
    }
    if(signature.length != 64){
        return false;
    }
    
    const uint8_t _messageLen = (uint8_t) message.length;
    const uint8_t * _message = (uint8_t*)[message bytes];
    
    const uint8_t * _signature = (uint8_t*)[signature bytes];
    const uint8_t * _publicKey = (uint8_t*)[publicKey bytes];
    
    return crypto_ed_verify(_signature, _message, _messageLen, _publicKey) == 0;
}

+(void) ensureArg: (NSData*) arg withDetail: (NSString*) detail{
    if(!arg || arg.length <= 0){
        @throw [NSException exceptionWithName:NSInvalidArgumentException reason:[NSString stringWithFormat:@"Invalid argument passed to crypto function. Detail: %@", detail] userInfo:nil];
    }
}
@end
