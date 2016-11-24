
#ifndef __SECURITY_H__
#define __SECURITY_H__

#ifdef USE_POLARSSL
#include <polarssl/sha2.h>
#include <polarssl/arc4.h>
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH    32
#endif
#define HMAC_CTX    sha2_context
#define HMAC_setup(ctx, key, len)   sha2_hmac_starts(&ctx, (unsigned char *)key, len, 0)
#define HMAC_crunch(ctx, buf, len)  sha2_hmac_update(&ctx, buf, len)
#define HMAC_finish(ctx, dig, dlen) dlen = SHA256_DIGEST_LENGTH; sha2_hmac_finish(&ctx, dig)

typedef arc4_context *  RC4_handle;
#define RC4_alloc(h)    *h = malloc(sizeof(arc4_context))
#define RC4_setkey(h,l,k)   arc4_setup(h,k,l)
#define RC4_encrypt(h,l,d)  arc4_crypt(h,l,(unsigned char *)d,(unsigned char *)d)
#define RC4_encrypt2(h,l,s,d)   arc4_crypt(h,l,(unsigned char *)s,(unsigned char *)d)
#define RC4_free(h) free(h)

#elif defined(USE_GNUTLS)
#include <gcrypt.h>
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH    32
#endif
#define HMAC_CTX    gcry_md_hd_t
#define HMAC_setup(ctx, key, len)   gcry_md_open(&ctx, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC); gcry_md_setkey(ctx, key, len)
#define HMAC_crunch(ctx, buf, len)  gcry_md_write(ctx, buf, len)
#define HMAC_finish(ctx, dig, dlen) dlen = SHA256_DIGEST_LENGTH; memcpy(dig, gcry_md_read(ctx, 0), dlen); gcry_md_close(ctx)

typedef gcry_cipher_hd_t    RC4_handle;
#define RC4_alloc(h)    gcry_cipher_open(h, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0)
#define RC4_setkey(h,l,k)   gcry_cipher_setkey(h,k,l)
#define RC4_encrypt(h,l,d)  gcry_cipher_encrypt(h,(void *)d,l,NULL,0)
#define RC4_encrypt2(h,l,s,d)   gcry_cipher_encrypt(h,(void *)d,l,(void *)s,l)
#define RC4_free(h) gcry_cipher_close(h)

#else   /* USE_OPENSSL */
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#if OPENSSL_VERSION_NUMBER < 0x0090800 || !defined(SHA256_DIGEST_LENGTH)
#error Your OpenSSL is too old, need 0.9.8 or newer with SHA256
#endif
#define HMAC_setup(ctx, key, len)   HMAC_CTX_init(&ctx); HMAC_Init_ex(&ctx, key, len, EVP_sha256(), 0)
#define HMAC_crunch(ctx, buf, len)  HMAC_Update(&ctx, buf, len)
#define HMAC_finish(ctx, dig, dlen) HMAC_Final(&ctx, dig, &dlen); HMAC_CTX_cleanup(&ctx)

typedef RC4_KEY *   RC4_handle;
#define RC4_alloc(h)    *h = malloc(sizeof(RC4_KEY))
#define RC4_setkey(h,l,k)   RC4_set_key(h,l,k)
#define RC4_encrypt(h,l,d)  RC4(h,l,(uint8_t *)d,(uint8_t *)d)
#define RC4_encrypt2(h,l,s,d)   RC4(h,l,(uint8_t *)s,(uint8_t *)d)
#define RC4_free(h) free(h)
#endif

#define FP10

#include "keys.h"


extern unsigned int getDigestPos(int offalgo, uint8_t *handshake, unsigned int len);
extern unsigned int getDhPos(int offalgo, uint8_t *handshake, unsigned int len);
extern void verify_HMAC(const uint8_t *message, size_t messageLen, const uint8_t *key, int keyType, size_t keylen, uint8_t *digest);
extern int verify_digest(int offalgo, uint8_t *handshakeMessage);
extern void calculate_digest(unsigned int digestPos, uint8_t *handshakeMessage,
                 int keyType , size_t keyLen, uint8_t *digest);

extern void InitRC4Encryption(uint8_t * secretKey,
                              uint8_t * pubKeyIn,
                              uint8_t * pubKeyOut, RC4_handle *rc4keyIn, RC4_handle *rc4keyOut) ;


#define GENUINE_FMSKEY  1
#define GENUINE_FPSKEY  2

static const uint8_t GenuineFMSKey[] = {
  0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20, 0x41, 0x64, 0x6f, 0x62,
    0x65, 0x20, 0x46, 0x6c,
  0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x20, 0x53, 0x65,
    0x72, 0x76, 0x65, 0x72,
  0x20, 0x30, 0x30, 0x31,   /* Genuine Adobe Flash Media Server 001 */

  0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8, 0x2e, 0x00, 0xd0, 0xd1,
  0x02, 0x9e, 0x7e, 0x57, 0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
    0x93, 0xb8, 0xe6, 0x36,
  0xcf, 0xeb, 0x31, 0xae
};              /* 68 */

static const uint8_t GenuineFPKey[] = {
  0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20, 0x41, 0x64, 0x6F, 0x62,
    0x65, 0x20, 0x46, 0x6C,
  0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x20, 0x30,
    0x30, 0x31,         /* Genuine Adobe Flash Player 001 */
  0xF0, 0xEE,
  0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E,
    0x7E, 0x57, 0x6E, 0xEC,
  0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB,
    0x31, 0xAE
};              /* 62 */

void InitRC4Encryption(uint8_t * secretKey,
                              uint8_t * pubKeyIn,
                              uint8_t * pubKeyOut, RC4_handle *rc4keyIn, RC4_handle *rc4keyOut)
{
  uint8_t digest[SHA256_DIGEST_LENGTH];
  unsigned int digestLen = 0;
  HMAC_CTX ctx;

  RC4_alloc(rc4keyIn);
  RC4_alloc(rc4keyOut);

  HMAC_setup(ctx, secretKey, 128);
  HMAC_crunch(ctx, pubKeyIn, 128);
  HMAC_finish(ctx, digest, digestLen);

  ast_debug(8, "RC4 Out Key\n");

  RC4_setkey(*rc4keyOut, 16, digest);

  HMAC_setup(ctx, secretKey, 128);
  HMAC_crunch(ctx, pubKeyOut, 128);
  HMAC_finish(ctx, digest, digestLen);

  ast_debug(8, "RC4 In Key\n");

  RC4_setkey(*rc4keyIn, 16, digest);
}

typedef unsigned int (getoff)(uint8_t *buf, unsigned int len);

static unsigned int GetDHOffset2(uint8_t *handshake, unsigned int len)
{
  unsigned int offset = 0;
  uint8_t *ptr = handshake + 768;
  unsigned int res;

  ////  assert(RTMP_BLOCK_SIZE <= len);

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  res = (offset % 632) + 8;

  if (res + 128 > 767)
    {
      ast_verbose( "%s: Couldn't calculate correct DH offset (got %d), exiting!",
              __FUNCTION__, res);
      return -1;
    }
  return res;
}

static unsigned int GetDigestOffset2(uint8_t *handshake, unsigned int len)
{
  unsigned int offset = 0;
  uint8_t *ptr = handshake + 772;
  unsigned int res;

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  res = (offset % 728) + 776;

  if (res + 32 > 1535)
    {
      ast_verbose("%s: Couldn't calculate correct digest offset (got %d), exiting",
              __FUNCTION__, res);
      return -1;
    }
  return res;
}

static unsigned int GetDHOffset1(uint8_t *handshake, unsigned int len)
{
  unsigned int offset = 0;
  uint8_t *ptr = handshake + 1532;
  unsigned int res;

  ///// assert(RTMP_BLOCK_SIZE <= len);

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  res = (offset % 632) + 772;

  if (res + 128 > 1531)
    {
      ast_verbose( "%s: Couldn't calculate DH offset (got %d), exiting!",
              __FUNCTION__, res);
      return -1;
    }

  return res;
}

static unsigned int GetDigestOffset1(uint8_t *handshake, unsigned int len)
{
  unsigned int offset = 0;
  uint8_t *ptr = handshake + 8;
  unsigned int res;

 /// assert(12 <= len);

  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);
  ptr++;
  offset += (*ptr);

  res = (offset % 728) + 12;

  if (res + 32 > 771)
    {
      ast_verbose("%s: Couldn't calculate digest offset (got %d), exiting!",
              __FUNCTION__, res);
      return -1;
    }

  return res;
}


static void HMACsha256(const uint8_t *message, size_t messageLen, const uint8_t *key,
       size_t keylen, uint8_t *digest)
{
  unsigned int digestLen;
  HMAC_CTX ctx;

  HMAC_setup(ctx, key, keylen);
  HMAC_crunch(ctx, message, messageLen);
  HMAC_finish(ctx, digest, digestLen);

  ///assert(digestLen == 32);
}

static void CalculateDigest(unsigned int digestPos, uint8_t *handshakeMessage,
                            const uint8_t *key , size_t keyLen, uint8_t *digest)
{
  const int messageLen = RTMP_BLOCK_SIZE - SHA256_DIGEST_LENGTH;
  uint8_t message[RTMP_BLOCK_SIZE - SHA256_DIGEST_LENGTH];

  memcpy(message, handshakeMessage, digestPos);
  memcpy(message + digestPos,
     &handshakeMessage[digestPos + SHA256_DIGEST_LENGTH],
     messageLen - digestPos);

  HMACsha256(message, messageLen, key, keyLen, digest);
}

static int VerifyDigest(unsigned int digestPos, uint8_t *handshakeMessage, const uint8_t *key,
                        size_t keyLen)
{
  uint8_t calcDigest[SHA256_DIGEST_LENGTH];

  CalculateDigest(digestPos, handshakeMessage, key, keyLen, calcDigest);

  return memcmp(&handshakeMessage[digestPos], calcDigest,
        SHA256_DIGEST_LENGTH) == 0;
}

/* handshake
 *
 * Type     = [1 bytes] plain: 0x03, encrypted: 0x06, 0x08, 0x09
 * -------------------------------------------------------------------- [1536 bytes]
 * Uptime   = [4 bytes] big endian unsigned number, uptime
 * Version  = [4 bytes] each byte represents a version number, e.g. 9.0.124.0
 * ...
 *
 */

static const uint32_t rtmpe8_keys[16][4] = {
    {0xbff034b2, 0x11d9081f, 0xccdfb795, 0x748de732},
    {0x086a5eb6, 0x1743090e, 0x6ef05ab8, 0xfe5a39e2},
    {0x7b10956f, 0x76ce0521, 0x2388a73a, 0x440149a1},
    {0xa943f317, 0xebf11bb2, 0xa691a5ee, 0x17f36339},
    {0x7a30e00a, 0xb529e22c, 0xa087aea5, 0xc0cb79ac},
    {0xbdce0c23, 0x2febdeff, 0x1cfaae16, 0x1123239d},
    {0x55dd3f7b, 0x77e7e62e, 0x9bb8c499, 0xc9481ee4},
    {0x407bb6b4, 0x71e89136, 0xa7aebf55, 0xca33b839},
    {0xfcf6bdc3, 0xb63c3697, 0x7ce4f825, 0x04d959b2},
    {0x28e091fd, 0x41954c4c, 0x7fb7db00, 0xe3a066f8},
    {0x57845b76, 0x4f251b03, 0x46d45bcd, 0xa2c30d29},
    {0x0acceef8, 0xda55b546, 0x03473452, 0x5863713b},
    {0xb82075dc, 0xa75f1fee, 0xd84268e8, 0xa72a44cc},
    {0x07cf6e9e, 0xa16d7b25, 0x9fa7ae6c, 0xd92f5629},
    {0xfeb1eae4, 0x8c8c3ce1, 0x4e0064a7, 0x6a387c2a},
    {0x893a9427, 0xcc3013a2, 0xf106385b, 0xa829f927}
};

/* RTMPE type 8 uses XTEA on the regular signature
 * http://en.wikipedia.org/wiki/XTEA
 */
static void rtmpe8_sig(uint8_t *in, uint8_t *out, int keyid)
{
  unsigned int i, num_rounds = 32;
  uint32_t v0, v1, sum=0, delta=0x9E3779B9;
  uint32_t const *k;

  v0 = in[0] | (in[1] << 8) | (in[2] << 16) | (in[3] << 24);
  v1 = in[4] | (in[5] << 8) | (in[6] << 16) | (in[7] << 24);
  k = rtmpe8_keys[keyid];

  for (i=0; i < num_rounds; i++) {
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    sum += delta;
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
  }

  out[0] = v0; v0 >>= 8;
  out[1] = v0; v0 >>= 8;
  out[2] = v0; v0 >>= 8;
  out[3] = v0;

  out[4] = v1; v1 >>= 8;
  out[5] = v1; v1 >>= 8;
  out[6] = v1; v1 >>= 8;
  out[7] = v1;
}


static getoff *digoff[] = {GetDigestOffset1, GetDigestOffset2};
static getoff *dhoff[] = {GetDHOffset1, GetDHOffset2};

unsigned int getDigestPos(int offalgo, uint8_t *handshake, unsigned int len)
{
    getoff *getdig = NULL;
    getdig = digoff[offalgo];
    return getdig(handshake, len);
}

unsigned int getDhPos(int offalgo, uint8_t *handshake, unsigned int len)
{
    getoff *getdh = NULL;
    getdh  = dhoff[offalgo];
    return getdh(handshake, len);
}

void verify_HMAC(const uint8_t *message, size_t messageLen, const uint8_t *key, int keyType, size_t keylen, uint8_t *digest)
{
    if (key == NULL) {
        if (keyType == GENUINE_FMSKEY) {
            ast_debug(9, "verify_HMAC with GenuineFMSKey\n");
            HMACsha256(message, messageLen, GenuineFMSKey, sizeof(GenuineFMSKey) ,digest);
        }
        else {
            ast_debug(9, "verify_HMAC with GenuineFPSKey\n");
            HMACsha256(message, messageLen, GenuineFPKey, sizeof(GenuineFPKey) ,digest);
        }
    }
    else {
        ast_debug(9, "verify_HMAC with buffer\n");
        HMACsha256(message, messageLen, key, keylen ,digest);
    }                                   
}


int verify_digest(int offalgo, uint8_t *handshakeMessage)
{
    /* we have to use this signature now to find the correct algorithms for getting the digest and DH positions */
    int digestPosClient = getDigestPos(offalgo, handshakeMessage, RTMP_BLOCK_SIZE);

    if (!VerifyDigest(digestPosClient, handshakeMessage, GenuineFPKey, 30))
    {
        ast_debug(4, "handshake: Trying different position for client digest!\n");
        offalgo ^= 1;

        digestPosClient = getDigestPos(offalgo, handshakeMessage, RTMP_BLOCK_SIZE);

        if (!VerifyDigest(digestPosClient, handshakeMessage, GenuineFPKey, 30))
        {
            ast_log(LOG_ERROR, "Couldn't verify the client digest\n");
            return -1;
        }
    }
    return digestPosClient;
}

void calculate_digest(unsigned int digestPos, uint8_t *handshakeMessage,
                 int keyType , size_t keyLen, uint8_t *digest)
{
    const uint8_t *key;

    if (keyType == GENUINE_FMSKEY) {
        key = GenuineFMSKey;
    }
    else {
        key = GenuineFPKey;
    }
    CalculateDigest(digestPos, handshakeMessage, key, keyLen,digest);

    return;
}


#endif


