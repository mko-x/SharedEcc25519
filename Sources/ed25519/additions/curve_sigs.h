
#ifndef __CURVE_SIGS_H__
#define __CURVE_SIGS_H__

#define MAX_MSG_LEN 256

void curve25519_keygen(unsigned char* curve25519_pubkey_out, /* 32 bytes */
                       const unsigned char* curve25519_privkey_in); /* 32 bytes */

/* returns 0 on success */
int curve25519_sign(unsigned char* signature_out, /* 64 bytes */
                     const unsigned char* curve25519_privkey, /* 32 bytes */
                     const unsigned char* msg, const unsigned long msg_len,
                     const unsigned char* random); /* 64 bytes */

/* returns 0 on success */
int curve25519_verify(const unsigned char* signature, /* 64 bytes */
                      const unsigned char* curve25519_pubkey, /* 32 bytes */
                      const unsigned char* msg, const unsigned long msg_len);

/* helper function - modified version of crypto_sign() to use 
   explicit private key.  In particular:

   sk     : private key
   pk     : public key
   msg    : message
   prefix : 0xFE || [0xFF]*31
   random : 64 bytes random
   q      : main subgroup order

   The prefix is chosen to distinguish the two SHA512 uses below, since
   prefix is an invalid encoding for R (it would encode a "field element"
   of 2^255 - 2).  0xFF*32 is set aside for use in ECDH protocols, which
   is why the first byte here ix 0xFE.

   sig_nonce = SHA512(prefix || sk ||  msg || random) % q
   R = g^sig_nonce
   M = SHA512(R || pk || m)
   S = sig_nonce + (m * sk)
   signature = (R || S)
 */
int crypto_sign_modified(
  unsigned char *sm,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk, /* Curve/Ed25519 private key */
  const unsigned char *pk, /* Ed25519 public key */
  const unsigned char *random /* 64 bytes random to hash into nonce */
  );

/* sign a keypair
 
 */
int crypto_ed_sign_keypair(
  unsigned char *pk,
  unsigned char *sk
  );

/*
    expands a given seed 'se' to length of 64
 */
int crypto_ed_expand_private_key(
  unsigned char *ek,
  unsigned char *se
  );

/*
  sign message m of length mlen with secret sk and returns signature sm of length smlen.
 */
int crypto_ed_sign(
  unsigned char *sm,unsigned long long *smlen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk
  );

/**
 *  Verify signature of message
 *
 *  @param signature
 *  @param message
 *  @param message_len
 *  @param public_key
 *
 *  @return 0 if successful
 *          -1 wrong signature
 *          -2 group element failed
 *          -3 Const-time comparison from SUPERCOP failed, http://bench.cr.yp.to/supercop.html
 */
int crypto_ed_verify(const unsigned char *signature,
                     const unsigned char *message,
                     uint8_t message_len,
                     const unsigned char *public_key);

/*
    private key clamping
 */
int crypto_curve_clamp(
  unsigned char* k
  );
#endif
