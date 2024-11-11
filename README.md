# EX-NO-7-IMPLEMENTATION OF SHA-1 ALGORITHM

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

// SHA-1 constants
#define H0_INIT 0x67452301
#define H1_INIT 0xEFCDAB89
#define H2_INIT 0x98BADCFE
#define H3_INIT 0x10325476
#define H4_INIT 0xC3D2E1F0

#define BLOCK_SIZE 64  // SHA-1 processes data in 512-bit blocks (64 bytes)

// Circular left shift macro
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

// SHA-1 padding function
void sha1_pad_message(const uint8_t *input, uint32_t length, uint8_t *padded_message, uint32_t *padded_length) {
    uint32_t i, bit_len;
    *padded_length = length + 1;

    // Padding the message
    while (*padded_length % BLOCK_SIZE != 56) *padded_length += 1;

    memcpy(padded_message, input, length);
    padded_message[length] = 0x80;  // Append 1 bit and 0s

    // Append original length in bits at the end
    bit_len = length * 8;
    for (i = 0; i < 4; ++i) {
        padded_message[*padded_length + 3 - i] = bit_len >> (i * 8);
    }

    *padded_length += 4;
}

// SHA-1 main processing function
void sha1_process_block(const uint8_t block[BLOCK_SIZE], uint32_t *H0, uint32_t *H1, uint32_t *H2, uint32_t *H3, uint32_t *H4) {
    uint32_t W[80], A, B, C, D, E, temp;
    int t;

    // Prepare the message schedule
    for (t = 0; t < 16; ++t) {
        W[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | (block[t * 4 + 3]);
    }
    for (t = 16; t < 80; ++t) {
        W[t] = LEFTROTATE(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    // Initialize working variables
    A = *H0;
    B = *H1;
    C = *H2;
    D = *H3;
    E = *H4;

    // Main loop
    for (t = 0; t < 80; ++t) {
        uint32_t f, k;

        if (t < 20) {
            f = (B & C) | ((~B) & D);
            k = 0x5A827999;
        } else if (t < 40) {
            f = B ^ C ^ D;
            k = 0x6ED9EBA1;
        } else if (t < 60) {
            f = (B & C) | (B & D) | (C & D);
            k = 0x8F1BBCDC;
        } else {
            f = B ^ C ^ D;
            k = 0xCA62C1D6;
        }

        temp = LEFTROTATE(A, 5) + f + E + k + W[t];
        E = D;
        D = C;
        C = LEFTROTATE(B, 30);
        B = A;
        A = temp;
    }

    *H0 += A;
    *H1 += B;
    *H2 += C;
    *H3 += D;
    *H4 += E;
}

// Main SHA-1 hashing function
void sha1(const uint8_t *input, uint32_t length, uint8_t output[20]) {
    uint8_t padded_message[BLOCK_SIZE * 2] = {0};
    uint32_t padded_length = 0;
    uint32_t H0 = H0_INIT, H1 = H1_INIT, H2 = H2_INIT, H3 = H3_INIT, H4 = H4_INIT;

    sha1_pad_message(input, length, padded_message, &padded_length);

    // Process each 512-bit block
    for (uint32_t i = 0; i < padded_length; i += BLOCK_SIZE) {
        sha1_process_block(padded_message + i, &H0, &H1, &H2, &H3, &H4);
    }

    // Produce the final hash value (big-endian)
    output[0] = (H0 >> 24) & 0xFF;
    output[1] = (H0 >> 16) & 0xFF;
    output[2] = (H0 >> 8) & 0xFF;
    output[3] = H0 & 0xFF;
    output[4] = (H1 >> 24) & 0xFF;
    output[5] = (H1 >> 16) & 0xFF;
    output[6] = (H1 >> 8) & 0xFF;
    output[7] = H1 & 0xFF;
    output[8] = (H2 >> 24) & 0xFF;
    output[9] = (H2 >> 16) & 0xFF;
    output[10] = (H2 >> 8) & 0xFF;
    output[11] = H2 & 0xFF;
    output[12] = (H3 >> 24) & 0xFF;
    output[13] = (H3 >> 16) & 0xFF;
    output[14] = (H3 >> 8) & 0xFF;
    output[15] = H3 & 0xFF;
    output[16] = (H4 >> 24) & 0xFF;
    output[17] = (H4 >> 16) & 0xFF;
    output[18] = (H4 >> 8) & 0xFF;
    output[19] = H4 & 0xFF;
}

// Helper function to print the SHA-1 hash in hexadecimal
void print_hash(const uint8_t hash[20]) {
    for (int i = 0; i < 20; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    const uint8_t *input = (uint8_t *)"abc";
    uint8_t hash[20];

    sha1(input, strlen((const char *)input), hash);

    printf("SHA-1(\"%s\") = ", input);
    print_hash(hash);

    return 0;
} 
```
## OUTPUT:
![Screenshot 2024-11-08 212839](https://github.com/user-attachments/assets/94a35b94-bea1-4170-952e-a6fd71b8b4c9)


## RESULT:
Thus the SHA-1 hashing technique had been implemented successfully.
  
