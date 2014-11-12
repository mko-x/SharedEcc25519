//
//  Ecc25519.h
//  SQRLEntrance
//
//  Created by Markus Kosmal on 03/11/14.
//  Copyright (c) 2014 adorsys GmbH & Co KG. All rights reserved.
//


#import <Foundation/Foundation.h>

@interface Ecc25519 : NSObject

/**
 *  ed25519 public key signature of private key
 *
 *  @param privateKey as input
 *
 *  @return ecc signature of public key
 */
+(NSData*) computePublicKeySignature: (NSData*) privateKey;

/**
 *  Sign with Ed25519-SHA512
 *
 *  @param message    content to sign
 *  @param privateKey signature key to sign with
 *
 *  @return signature of message according to privateKey
 */
+(NSData*)sign:(NSData*)message withPrivateKey:(NSData*) privateKey;

/**
 *  Verify with Edwards.
 *
 *  @param signature delivered signature
 *  @param message   the signature is from
 *  @param publicKey public signing key
 *
 *  @return <#return value description#>
 */
+(BOOL) verify:(NSData*) signature ofMessage:(NSData*) message withPublicKey:(NSData*) publicKey;

/**
 *  Fills key to reach enough complexity
 *
 *  @param key of 32 or 64 byte
 *
 *  @return expanded key to 64 byte if key == 32 Byte
 */
+(NSData*) expandPrivateKey: (NSData*) key;

/**
 *  Private key clamping
 *
 *  @param key to clamp
 */
+(NSData*) clamp: (NSData *) key;

/**
 *  Use curve for diffie hellman key agreement
 *
 *  @param privateKey source
 *
 *  @return public key
 */
+(NSData*) keygen: (NSData*) privateKey;

/**
 *  Create diffie hellman shared secret
 *
 *  @param privateKey   in own
 *  @param publicKey    in theirs
 *
 *  @return shared secret
 */
+(NSData*) curvePrivate:(NSData*) privateKey withPublicKey: (NSData*) publicKey;

/**
 *  Ecc direct call to native c donna.
 *
 *  @param output
 *  @param secret
 *  @param basepoint
 */
+(void) ecc_curve25519_donna:(unsigned char *)output withSecret: (const unsigned char *) secret fromBasepoint: (const unsigned char *) basepoint;
@end
