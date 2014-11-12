#include <string.h>
#include "sc.h"
#include "ge.h"
#include "curve_sigs.h"
#include "crypto_sign.h"
#include "crypto_verify_32.h"
#include "crypto_hash_sha512.h"

void curve25519_keygen(unsigned char* curve25519_pubkey_out,
                       const unsigned char* curve25519_privkey_in)
{
  ge_p3 ed; /* Ed25519 pubkey point */
    //original -removed unused variable
    //fe ed_y, ed_y_plus_one, one_minus_ed_y, inv_one_minus_ed_y;
    fe ed_y_plus_one, one_minus_ed_y, inv_one_minus_ed_y;
  fe mont_x;

  /* Perform a fixed-base multiplication of the Edwards base point,
     (which is efficient due to precalculated tables), then convert
     to the Curve25519 montgomery-format public key.  In particular,
     convert Curve25519's "montgomery" x-coordinate into an Ed25519
     "edwards" y-coordinate:

     mont_x = (ed_y + 1) / (1 - ed_y)
     
     with projective coordinates:

     mont_x = (ed_y + ed_z) / (ed_z - ed_y)

     NOTE: ed_y=1 is converted to mont_x=0 since fe_invert is mod-exp
  */

  ge_scalarmult_base(&ed, curve25519_privkey_in);
  fe_add(ed_y_plus_one, ed.Y, ed.Z);
  fe_sub(one_minus_ed_y, ed.Z, ed.Y);  
  fe_invert(inv_one_minus_ed_y, one_minus_ed_y);
  fe_mul(mont_x, ed_y_plus_one, inv_one_minus_ed_y);
  fe_tobytes(curve25519_pubkey_out, mont_x);
}

int curve25519_sign(unsigned char* signature_out,
                    const unsigned char* curve25519_privkey,
                    const unsigned char* msg, const unsigned long msg_len,
                    const unsigned char* random)
{
  ge_p3 ed_pubkey_point; /* Ed25519 pubkey point */
  unsigned char ed_pubkey[32]; /* Ed25519 encoded pubkey */
  unsigned char sigbuf[MAX_MSG_LEN + 128]; /* working buffer */
  unsigned char sign_bit = 0;

  if (msg_len > MAX_MSG_LEN) {
    memset(signature_out, 0, 64);
    return -1;
  }

  /* Convert the Curve25519 privkey to an Ed25519 public key */
  ge_scalarmult_base(&ed_pubkey_point, curve25519_privkey);
  ge_p3_tobytes(ed_pubkey, &ed_pubkey_point);
  sign_bit = ed_pubkey[31] & 0x80;

  /* Perform an Ed25519 signature with explicit private key */
  crypto_sign_modified(sigbuf, msg, msg_len, curve25519_privkey,
                       ed_pubkey, random);
  memmove(signature_out, sigbuf, 64);

  /* Encode the sign bit into signature (in unused high bit of S) */
   signature_out[63] &= 0x7F; /* bit should be zero already, but just in case */
   signature_out[63] |= sign_bit;
   return 0;
}

int curve25519_verify(const unsigned char* signature,
                      const unsigned char* curve25519_pubkey,
                      const unsigned char* msg, const unsigned long msg_len)
{
  fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one;
  fe one;
  fe ed_y;
  unsigned char ed_pubkey[32];
  unsigned long long some_retval;
  unsigned char verifybuf[MAX_MSG_LEN + 64]; /* working buffer */
  unsigned char verifybuf2[MAX_MSG_LEN + 64]; /* working buffer #2 */

  if (msg_len > MAX_MSG_LEN) {
    return -1;
  }

  /* Convert the Curve25519 public key into an Ed25519 public key.  In
     particular, convert Curve25519's "montgomery" x-coordinate into an
     Ed25519 "edwards" y-coordinate:

     ed_y = (mont_x - 1) / (mont_x + 1)

     NOTE: mont_x=-1 is converted to ed_y=0 since fe_invert is mod-exp

     Then move the sign bit into the pubkey from the signature.
  */
  fe_frombytes(mont_x, curve25519_pubkey);
  fe_1(one);
  fe_sub(mont_x_minus_one, mont_x, one);
  fe_add(mont_x_plus_one, mont_x, one);
  fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
  fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
  fe_tobytes(ed_pubkey, ed_y);

  /* Copy the sign bit, and remove it from signature */
  ed_pubkey[31] &= 0x7F;  /* bit should be zero already, but just in case */
  ed_pubkey[31] |= (signature[63] & 0x80);
  memmove(verifybuf, signature, 64);
  verifybuf[63] &= 0x7F;

  memmove(verifybuf+64, msg, msg_len);

  /* Then perform a normal Ed25519 verification, return 0 on success */
  /* The below call has a strange API: */
  /* verifybuf = R || S || message */
  /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets 
     replaced with pubkey for hashing, then the whole thing gets zeroized */
  return crypto_sign_open(verifybuf2, &some_retval, verifybuf, 64 + msg_len, ed_pubkey);
}

int crypto_ed_sign_keypair(unsigned char* pk, unsigned char* sk)
{
    unsigned char h[64];
    ge_p3 A;
    int i;
    
    crypto_hash_sha512(h, sk, 32);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    
    ge_scalarmult_base(&A,h);
    ge_p3_tobytes(pk,&A);
    
    for (i = 0;i < 32;++i) sk[32 + i] = pk[i];
    return 0;
}

int crypto_ed_expand_private_key(unsigned char *ek,unsigned char *se)
{
    unsigned char pk[32];
    int i;
    for (i = 0; i < 32; i++) {
        ek[i] = se[i];
    }
    
    crypto_ed_sign_keypair(pk, ek);
    return 0;
}

int crypto_ed_sign(unsigned char *sm,unsigned long long *smlen, const unsigned char *m,unsigned long long mlen, const unsigned char *sk ){
    return crypto_sign(sm, &mlen, m, mlen, sk);
}

int crypto_ed_verify(const unsigned char *signature, const unsigned char *message, uint8_t message_len, const unsigned char *public_key) {
    
    unsigned char h[64];
    unsigned char checker[32];
    //SHA512_CTX hash;
    ge_p3 A;
    ge_p2 R;
    
    if (signature[63] & 224) {
        return -1;
    }
    
    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return -2;
    }
    
//    SHA512_Init(&hash);
//    SHA512_Update(&hash, signature, 32);
//    SHA512_Update(&hash, public_key, 32);
//    SHA512_Update(&hash, message, message_len);
//    SHA512_Final(h, &hash);
    
    crypto_hash_sha512(h, signature, 32);
    crypto_hash_sha512(h, public_key, 32);
    crypto_hash_sha512(h, message, message_len);
    
    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);
    
    if (!(crypto_verify_32(checker, signature) == 0)) {
        return -3;
    }
    
    return 0;
}

int crypto_curve_clamp(unsigned char* k){
    k[31] &= 0x7F;
    k[31] |= 0x40;
    k[ 0] &= 0xF8;
    return 0;
}