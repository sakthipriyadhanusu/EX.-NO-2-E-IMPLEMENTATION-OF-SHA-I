# EX.-NO-2-E-IMPLEMENTATION-OF-SHA-I

## AIM:
  To implement the SHA-I hashing technique using C program.
  
## ALGORITHM:

  STEP-1: Read the 256-bit key values.
  
  STEP-2: Divide into five equal-sized blocks named A, B, C, D and E.
  
  STEP-3: The blocks B, C and D are passed to the function F.
  
  STEP-4: The resultant value is permuted with block E.
  
  STEP-5: The block A is shifted right by ‘s’ times and permuted with the result of
  
  
  STEP-6: Then it is permuted with a weight value and then with some other key pair and taken as the first block.
  
  STEP-7: Block A is taken as the second block and the block B is shifted by ‘s’ times and taken as the third block.
  
  STEP-8: The blocks C and D are taken as the block D and E for the final output.

## PROGRAM:
```
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Define the SHA-1 circular left shift macro
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

// SHA-1 context structure
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[5];
} SHA1_CTX;

// SHA-1 initialization constants
uint32_t k[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

// Functions for processing and updating the hash
void sha1_transform(SHA1_CTX *ctx, uint8_t data[]) {
    uint32_t a, b, c, d, e, i, j, t, m[80];
    
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    
    for ( ; i < 80; ++i)
        m[i] = LEFTROTATE(m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16], 1);
    
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    
    for (i = 0; i < 80; ++i) {
        if (i < 20)
            t = LEFTROTATE(a, 5) + ((b & c) | (~b & d)) + e + k[0] + m[i];
        else if (i < 40)
            t = LEFTROTATE(a, 5) + (b ^ c ^ d) + e + k[1] + m[i];
        else if (i < 60)
            t = LEFTROTATE(a, 5) + ((b & c) | (b & d) | (c & d)) + e + k[2] + m[i];
        else
            t = LEFTROTATE(a, 5) + (b ^ c ^ d) + e + k[3] + m[i];
        
        e = d;
        d = c;
        c = LEFTROTATE(b, 30);
        b = a;
        a = t;
    }
    
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(SHA1_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
}

void sha1_update(SHA1_CTX *ctx, const uint8_t data[], size_t len) {
    for (unsigned int i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha1_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha1_final(SHA1_CTX *ctx, uint8_t hash[]) {
    unsigned int i = ctx->datalen;
    
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha1_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha1_transform(ctx, ctx->data);
    
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    }
}

int main() {
    // initializing string
    char *str = "cryptography";
    printf("Text: %s\n", str);
    
    // Create SHA1 context and hash buffer
    SHA1_CTX ctx;
    uint8_t hash[20];
    
    // Initialize, update, and finalize SHA-1 hash
    sha1_init(&ctx);
    sha1_update(&ctx, (unsigned char*)str, strlen(str));
    sha1_final(&ctx, hash);
    
    // Printing the equivalent hexadecimal value
    printf("\nThe hexadecimal equivalent of SHA1 is: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
```
## OUTPUT:
![Screenshot 2024-09-30 114812](https://github.com/user-attachments/assets/87565f67-9988-4cc7-821c-e54ec5c20362)

## RESULT:
  Thus the SHA-1 hashing technique had been implemented successfully.
  
