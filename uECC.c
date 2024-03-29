/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include "uECC_vli.h"

#ifndef uECC_RNG_MAX_TRIES
    #define uECC_RNG_MAX_TRIES 64
#endif

#define CONCATX(a, ...) a ## __VA_ARGS__
#define CONCAT(a, ...) CONCATX(a, __VA_ARGS__)

#define STRX(a) #a
#define STR(a) STRX(a)

#define EVAL(...)  EVAL1(EVAL1(EVAL1(EVAL1(__VA_ARGS__))))
#define EVAL1(...) EVAL2(EVAL2(EVAL2(EVAL2(__VA_ARGS__))))
#define EVAL2(...) EVAL3(EVAL3(EVAL3(EVAL3(__VA_ARGS__))))
#define EVAL3(...) EVAL4(EVAL4(EVAL4(EVAL4(__VA_ARGS__))))
#define EVAL4(...) __VA_ARGS__

#define DEC_1  0
#define DEC_2  1
#define DEC_3  2
#define DEC_4  3
#define DEC_5  4
#define DEC_6  5
#define DEC_7  6
#define DEC_8  7
#define DEC_9  8
#define DEC_10 9
#define DEC_11 10
#define DEC_12 11
#define DEC_13 12
#define DEC_14 13
#define DEC_15 14
#define DEC_16 15
#define DEC_17 16
#define DEC_18 17
#define DEC_19 18
#define DEC_20 19
#define DEC_21 20
#define DEC_22 21
#define DEC_23 22
#define DEC_24 23
#define DEC_25 24
#define DEC_26 25
#define DEC_27 26
#define DEC_28 27
#define DEC_29 28
#define DEC_30 29
#define DEC_31 30
#define DEC_32 31

#define DEC(N) CONCAT(DEC_, N)

#define SECOND_ARG(_, val, ...) val
#define SOME_CHECK_0 ~, 0
#define GET_SECOND_ARG(...) SECOND_ARG(__VA_ARGS__, SOME,)
#define SOME_OR_0(N) GET_SECOND_ARG(CONCAT(SOME_CHECK_, N))

#define EMPTY(...)
#define DEFER(...) __VA_ARGS__ EMPTY()

#define REPEAT_NAME_0() REPEAT_0
#define REPEAT_NAME_SOME() REPEAT_SOME
#define REPEAT_0(...)
#define REPEAT_SOME(N, stuff) DEFER(CONCAT(REPEAT_NAME_, SOME_OR_0(DEC(N))))()(DEC(N), stuff) stuff
#define REPEAT(N, stuff) EVAL(REPEAT_SOME(N, stuff))

#define REPEATM_NAME_0() REPEATM_0
#define REPEATM_NAME_SOME() REPEATM_SOME
#define REPEATM_0(...)
#define REPEATM_SOME(N, macro) macro(N) \
    DEFER(CONCAT(REPEATM_NAME_, SOME_OR_0(DEC(N))))()(DEC(N), macro)
#define REPEATM(N, macro) EVAL(REPEATM_SOME(N, macro))

#if (uECC_WORD_SIZE == 1)
    #undef uECC_MAX_WORDS
    #define uECC_MAX_WORDS 32
#elif (uECC_WORD_SIZE == 4)
    #undef uECC_MAX_WORDS
    #define uECC_MAX_WORDS 8
#elif (uECC_WORD_SIZE == 8)
    #undef uECC_MAX_WORDS
    #define uECC_MAX_WORDS 4
#endif /* uECC_WORD_SIZE */

#define BITS_TO_WORDS(num_bits) ((num_bits + ((uECC_WORD_SIZE * 8) - 1)) / (uECC_WORD_SIZE * 8))
#define BITS_TO_BYTES(num_bits) ((num_bits + 7) / 8)

struct uECC_Curve_t {
    wordcount_t num_words;
    wordcount_t num_bytes;
    bitcount_t num_n_bits;
    uECC_word_t p[uECC_MAX_WORDS];
    uECC_word_t n[uECC_MAX_WORDS];
    uECC_word_t half_n[uECC_MAX_WORDS];
    uECC_word_t G[uECC_MAX_WORDS * 2];
    uECC_word_t b[uECC_MAX_WORDS];
    void (*double_jacobian)(uECC_word_t * X1,
                            uECC_word_t * Y1,
                            uECC_word_t * Z1);
    void (*mod_sqrt)(uECC_word_t *a);
    void (*x_side)(uECC_word_t *result, const uECC_word_t *x);
#if (uECC_OPTIMIZATION_LEVEL > 0)
    void (*mmod_fast)(uECC_word_t *result, uECC_word_t *product);
#endif
};

static void bcopy(uint8_t *dst,
                  const uint8_t *src,
                  unsigned num_bytes) {
    while (0 != num_bytes) {
        num_bytes--;
        dst[num_bytes] = src[num_bytes];
    }
}

static cmpresult_t uECC_vli_cmp_unsafe(const uECC_word_t *left,
                                       const uECC_word_t *right,
                                       wordcount_t num_words);

#if (uECC_PLATFORM == uECC_arm || uECC_PLATFORM == uECC_arm_thumb || \
        uECC_PLATFORM == uECC_arm_thumb2)
    #include "asm_arm.inc"
#endif

#if (uECC_PLATFORM == uECC_avr)
    #include "asm_avr.inc"
#endif

int uECC_curve_private_key_size() {
    return BITS_TO_BYTES(curve_secp256k1.num_n_bits);
}

int uECC_curve_public_key_size() {
    return 2 * curve_secp256k1.num_bytes;
}

#if !asm_clear
void uECC_vli_clear(uECC_word_t *vli, wordcount_t num_words) {
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        vli[i] = 0;
    }
}
#endif /* !asm_clear */

/* Constant-time comparison to zero - secure way to compare long integers */
/* Returns 1 if vli == 0, 0 otherwise. */
uECC_word_t uECC_vli_isZero(const uECC_word_t *vli, wordcount_t num_words) {
    uECC_word_t bits = 0;
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        bits |= vli[i];
    }
    return (bits == 0);
}

/* Returns nonzero if bit 'bit' of vli is set. */
uECC_word_t uECC_vli_testBit(const uECC_word_t *vli, bitcount_t bit) {
    return (vli[bit >> uECC_WORD_BITS_SHIFT] & ((uECC_word_t)1 << (bit & uECC_WORD_BITS_MASK)));
}

/* Counts the number of words in vli. */
static wordcount_t vli_numDigits(const uECC_word_t *vli, const wordcount_t max_words) {
    wordcount_t i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = max_words - 1; i >= 0 && vli[i] == 0; --i) {
    }

    return (i + 1);
}

/* Counts the number of bits required to represent vli. */
bitcount_t uECC_vli_numBits(const uECC_word_t *vli, const wordcount_t max_words) {
    uECC_word_t i;
    uECC_word_t digit;

    wordcount_t num_digits = vli_numDigits(vli, max_words);
    if (num_digits == 0) {
        return 0;
    }

    digit = vli[num_digits - 1];
    for (i = 0; digit; ++i) {
        digit >>= 1;
    }

    return (((bitcount_t)(num_digits - 1) << uECC_WORD_BITS_SHIFT) + i);
}

/* Sets dest = src. */
#if !asm_set
void uECC_vli_set(uECC_word_t *dest, const uECC_word_t *src, wordcount_t num_words) {
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        dest[i] = src[i];
    }
}
#endif /* !asm_set */

/* Returns sign of left - right. */
static cmpresult_t uECC_vli_cmp_unsafe(const uECC_word_t *left,
                                       const uECC_word_t *right,
                                       wordcount_t num_words) {
    wordcount_t i;
    for (i = num_words - 1; i >= 0; --i) {
        if (left[i] > right[i]) {
            return 1;
        } else if (left[i] < right[i]) {
            return -1;
        }
    }
    return 0;
}

/* Constant-time comparison function - secure way to compare long integers */
/* Returns one if left == right, zero otherwise. */
uECC_word_t uECC_vli_equal(const uECC_word_t *left,
                                        const uECC_word_t *right,
                                        wordcount_t num_words) {
    uECC_word_t diff = 0;
    wordcount_t i;
    for (i = num_words - 1; i >= 0; --i) {
        diff |= (left[i] ^ right[i]);
    }
    return (diff == 0);
}

uECC_word_t uECC_vli_sub(uECC_word_t *result,
                                      const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words);

/* Returns sign of left - right, in constant time. */
cmpresult_t uECC_vli_cmp(const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words) {
    uECC_word_t tmp[uECC_MAX_WORDS];
    uECC_word_t neg = !!uECC_vli_sub(tmp, left, right, num_words);
    uECC_word_t equal = uECC_vli_isZero(tmp, num_words);
    return (!equal - 2 * neg);
}

/* Computes vli = vli >> 1. */
#if !asm_rshift1
void uECC_vli_rshift1(uECC_word_t *vli, wordcount_t num_words) {
    uECC_word_t *end = vli;
    uECC_word_t carry = 0;

    vli += num_words;
    while (vli-- > end) {
        uECC_word_t temp = *vli;
        *vli = (temp >> 1) | carry;
        carry = temp << (uECC_WORD_BITS - 1);
    }
}
#endif /* !asm_rshift1 */

/* Computes result = left + right, returning carry. Can modify in place. */
#if !asm_add
uECC_word_t uECC_vli_add(uECC_word_t *result,
                                      const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words) {
    uECC_word_t carry = 0;
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        uECC_word_t sum = left[i] + right[i] + carry;
        if (sum != left[i]) {
            carry = (sum < left[i]);
        }
        result[i] = sum;
    }
    return carry;
}
#endif /* !asm_add */

/* Computes result = left - right, returning borrow. Can modify in place. */
#if !asm_sub
uECC_word_t uECC_vli_sub(uECC_word_t *result,
                                      const uECC_word_t *left,
                                      const uECC_word_t *right,
                                      wordcount_t num_words) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < num_words; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}
#endif /* !asm_sub */

#if !asm_mult || (uECC_SQUARE_FUNC && !asm_square) || \
    ((uECC_OPTIMIZATION_LEVEL > 0) && \
        ((uECC_WORD_SIZE == 1) || (uECC_WORD_SIZE == 8)))
static void muladd(uECC_word_t a,
                   uECC_word_t b,
                   uECC_word_t *r0,
                   uECC_word_t *r1,
                   uECC_word_t *r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1) { /* overflow */
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}
#endif /* muladd needed */

#if !asm_mult
void uECC_vli_mult(uECC_word_t *result,
                                const uECC_word_t *left,
                                const uECC_word_t *right,
                                wordcount_t num_words) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t i, k;

    /* Compute each digit of result in sequence, maintaining the carries. */
    for (k = 0; k < num_words; ++k) {
        for (i = 0; i <= k; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (k = num_words; k < num_words * 2 - 1; ++k) {
        for (i = (k + 1) - num_words; i < num_words; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[num_words * 2 - 1] = r0;
}
#endif /* !asm_mult */

#if uECC_SQUARE_FUNC

#if !asm_square
static void mul2add(uECC_word_t a,
                    uECC_word_t b,
                    uECC_word_t *r0,
                    uECC_word_t *r1,
                    uECC_word_t *r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1)
    { /* overflow */
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r2 += (p1 >> 63);
    p1 = (p1 << 1) | (p0 >> 63);
    p0 <<= 1;

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    *r2 += (p >> (uECC_WORD_BITS * 2 - 1));
    p *= 2;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}

void uECC_vli_square(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  wordcount_t num_words) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;

    wordcount_t i, k;

    for (k = 0; k < num_words * 2 - 1; ++k) {
        uECC_word_t min = (k < num_words ? 0 : (k + 1) - num_words);
        for (i = min; i <= k && i <= k - i; ++i) {
            if (i < k-i) {
                mul2add(left[i], left[k - i], &r0, &r1, &r2);
            } else {
                muladd(left[i], left[k - i], &r0, &r1, &r2);
            }
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }

    result[num_words * 2 - 1] = r0;
}
#endif /* !asm_square */

#else /* uECC_SQUARE_FUNC */

void uECC_vli_square(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  wordcount_t num_words) {
    uECC_vli_mult(result, left, left, num_words);
}

#endif /* uECC_SQUARE_FUNC */

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_vli_modAdd(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  const uECC_word_t *right,
                                  const uECC_word_t *mod,
                                  wordcount_t num_words) {
    uECC_word_t carry = uECC_vli_add(result, left, right, num_words);
    if (carry || uECC_vli_cmp_unsafe(mod, result, num_words) != 1) {
        /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
        uECC_vli_sub(result, result, mod, num_words);
    }
}

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_vli_modSub(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  const uECC_word_t *right,
                                  const uECC_word_t *mod,
                                  wordcount_t num_words) {
    uECC_word_t l_borrow = uECC_vli_sub(result, left, right, num_words);
    if (l_borrow) {
        /* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
           we can get the correct result from result + mod (with overflow). */
        uECC_vli_add(result, result, mod, num_words);
    }
}

/* Computes result = product % mod, where product is 2N words long. */
/* Currently only designed to work for curve_p or curve_n. */
void uECC_vli_mmod(uECC_word_t *result,
                                uECC_word_t *product,
                                const uECC_word_t *mod,
                                wordcount_t num_words) {
    uECC_word_t mod_multiple[2 * uECC_MAX_WORDS];
    uECC_word_t tmp[2 * uECC_MAX_WORDS];
    uECC_word_t *v[2] = {tmp, product};
    uECC_word_t index;

    /* Shift mod so its highest set bit is at the maximum position. */
    bitcount_t shift = (num_words * 2 * uECC_WORD_BITS) - uECC_vli_numBits(mod, num_words);
    wordcount_t word_shift = shift / uECC_WORD_BITS;
    wordcount_t bit_shift = shift % uECC_WORD_BITS;
    uECC_word_t carry = 0;
    uECC_vli_clear(mod_multiple, word_shift);
    if (bit_shift > 0) {
        for(index = 0; index < (uECC_word_t)num_words; ++index) {
            mod_multiple[word_shift + index] = (mod[index] << bit_shift) | carry;
            carry = mod[index] >> (uECC_WORD_BITS - bit_shift);
        }
    } else {
        uECC_vli_set(mod_multiple + word_shift, mod, num_words);
    }

    for (index = 1; shift >= 0; --shift) {
        uECC_word_t borrow = 0;
        wordcount_t i;
        for (i = 0; i < num_words * 2; ++i) {
            uECC_word_t diff = v[index][i] - mod_multiple[i] - borrow;
            if (diff != v[index][i]) {
                borrow = (diff > v[index][i]);
            }
            v[1 - index][i] = diff;
        }
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        uECC_vli_rshift1(mod_multiple, num_words);
        mod_multiple[num_words - 1] |= mod_multiple[num_words] << (uECC_WORD_BITS - 1);
        uECC_vli_rshift1(mod_multiple + num_words, num_words);
    }
    uECC_vli_set(result, v[index], num_words);
}

/* Computes result = (left * right) % mod. */
void uECC_vli_modMult(uECC_word_t *result,
                                   const uECC_word_t *left,
                                   const uECC_word_t *right,
                                   const uECC_word_t *mod,
                                   wordcount_t num_words) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_mult(product, left, right, num_words);
    uECC_vli_mmod(result, product, mod, num_words);
}

void uECC_vli_modMult_fast(uECC_word_t *result,
                                        const uECC_word_t *left,
                                        const uECC_word_t *right) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_mult(product, left, right, curve_secp256k1.num_words);
#if (uECC_OPTIMIZATION_LEVEL > 0)
    curve_secp256k1.mmod_fast(result, product);
#else
    uECC_vli_mmod(result, product, curve_secp256k1.p, curve_secp256k1.num_words);
#endif
}

#if uECC_SQUARE_FUNC

/* Computes result = left^2 % mod. */
void uECC_vli_modSquare(uECC_word_t *result,
                                     const uECC_word_t *left,
                                     const uECC_word_t *mod,
                                     wordcount_t num_words) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_square(product, left, num_words);
    uECC_vli_mmod(result, product, mod, num_words);
}

void uECC_vli_modSquare_fast(uECC_word_t *result, const uECC_word_t *left) {
    uECC_word_t product[2 * uECC_MAX_WORDS];
    uECC_vli_square(product, left, curve_secp256k1.num_words);
#if (uECC_OPTIMIZATION_LEVEL > 0)
    curve_secp256k1.mmod_fast(result, product);
#else
    uECC_vli_mmod(result, product, curve_secp256k1.p, curve_secp256k1.num_words);
#endif
}

#else /* uECC_SQUARE_FUNC */

void uECC_vli_modSquare(uECC_word_t *result,
                                     const uECC_word_t *left,
                                     const uECC_word_t *mod,
                                     wordcount_t num_words) {
    uECC_vli_modMult(result, left, left, mod, num_words);
}

void uECC_vli_modSquare_fast(uECC_word_t *result, const uECC_word_t *left) {
    uECC_vli_modMult_fast(result, left, left);
}

#endif /* uECC_SQUARE_FUNC */

#define EVEN(vli) (!(vli[0] & 1))
static void vli_modInv_update(uECC_word_t *uv,
                              const uECC_word_t *mod,
                              wordcount_t num_words) {
    uECC_word_t carry = 0;
    if (!EVEN(uv)) {
        carry = uECC_vli_add(uv, uv, mod, num_words);
    }
    uECC_vli_rshift1(uv, num_words);
    if (carry) {
        uv[num_words - 1] |= HIGH_BIT_SET;
    }
}

/* Computes result = (1 / input) % mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide" */
void uECC_vli_modInv(uECC_word_t *result,
                                  const uECC_word_t *input,
                                  const uECC_word_t *mod,
                                  wordcount_t num_words) {
    uECC_word_t a[uECC_MAX_WORDS], b[uECC_MAX_WORDS], u[uECC_MAX_WORDS], v[uECC_MAX_WORDS];
    cmpresult_t cmpResult;

    if (uECC_vli_isZero(input, num_words)) {
        uECC_vli_clear(result, num_words);
        return;
    }

    uECC_vli_set(a, input, num_words);
    uECC_vli_set(b, mod, num_words);
    uECC_vli_clear(u, num_words);
    u[0] = 1;
    uECC_vli_clear(v, num_words);
    while ((cmpResult = uECC_vli_cmp_unsafe(a, b, num_words)) != 0) {
        if (EVEN(a)) {
            uECC_vli_rshift1(a, num_words);
            vli_modInv_update(u, mod, num_words);
        } else if (EVEN(b)) {
            uECC_vli_rshift1(b, num_words);
            vli_modInv_update(v, mod, num_words);
        } else if (cmpResult > 0) {
            uECC_vli_sub(a, a, b, num_words);
            uECC_vli_rshift1(a, num_words);
            if (uECC_vli_cmp_unsafe(u, v, num_words) < 0) {
                uECC_vli_add(u, u, mod, num_words);
            }
            uECC_vli_sub(u, u, v, num_words);
            vli_modInv_update(u, mod, num_words);
        } else {
            uECC_vli_sub(b, b, a, num_words);
            uECC_vli_rshift1(b, num_words);
            if (uECC_vli_cmp_unsafe(v, u, num_words) < 0) {
                uECC_vli_add(v, v, mod, num_words);
            }
            uECC_vli_sub(v, v, u, num_words);
            vli_modInv_update(v, mod, num_words);
        }
    }
    uECC_vli_set(result, u, num_words);
}

/* ------ Point operations ------ */

#include "curve-specific.inc"

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
#define EccPoint_isZero(point) uECC_vli_isZero((point), curve_secp256k1.num_words * 2)

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uECC_word_t * X1,
                    uECC_word_t * Y1,
                    const uECC_word_t * const Z) {
    uECC_word_t t1[uECC_MAX_WORDS];

    uECC_vli_modSquare_fast(t1, Z);    /* z^2 */
    uECC_vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
    uECC_vli_modMult_fast(t1, t1, Z);  /* z^3 */
    uECC_vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uECC_word_t * X1,
                                uECC_word_t * Y1,
                                uECC_word_t * X2,
                                uECC_word_t * Y2,
                                const uECC_word_t * const initial_Z) {
    uECC_word_t z[uECC_MAX_WORDS];
    wordcount_t num_words = curve_secp256k1.num_words;
    if (initial_Z) {
        uECC_vli_set(z, initial_Z, num_words);
    } else {
        uECC_vli_clear(z, num_words);
        z[0] = 1;
    }

    uECC_vli_set(X2, X1, num_words);
    uECC_vli_set(Y2, Y1, num_words);

    apply_z(X1, Y1, z);
    curve_secp256k1.double_jacobian(X1, Y1, z);
    apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(uECC_word_t * X1,
                     uECC_word_t * Y1,
                     uECC_word_t * X2,
                     uECC_word_t * Y2) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_MAX_WORDS];
    wordcount_t num_words = curve_secp256k1.num_words;

    uECC_vli_modSub(t5, X2, X1, curve_secp256k1.p, num_words); /* t5 = x2 - x1 */
    uECC_vli_modSquare_fast(t5, t5);                  /* t5 = (x2 - x1)^2 = A */
    uECC_vli_modMult_fast(X1, X1, t5);                /* t1 = x1*A = B */
    uECC_vli_modMult_fast(X2, X2, t5);                /* t3 = x2*A = C */
    uECC_vli_modSub(Y2, Y2, Y1, curve_secp256k1.p, num_words); /* t4 = y2 - y1 */
    uECC_vli_modSquare_fast(t5, Y2);                  /* t5 = (y2 - y1)^2 = D */

    uECC_vli_modSub(t5, t5, X1, curve_secp256k1.p, num_words); /* t5 = D - B */
    uECC_vli_modSub(t5, t5, X2, curve_secp256k1.p, num_words); /* t5 = D - B - C = x3 */
    uECC_vli_modSub(X2, X2, X1, curve_secp256k1.p, num_words); /* t3 = C - B */
    uECC_vli_modMult_fast(Y1, Y1, X2);                /* t2 = y1*(C - B) */
    uECC_vli_modSub(X2, X1, t5, curve_secp256k1.p, num_words); /* t3 = B - x3 */
    uECC_vli_modMult_fast(Y2, Y2, X2);                /* t4 = (y2 - y1)*(B - x3) */
    uECC_vli_modSub(Y2, Y2, Y1, curve_secp256k1.p, num_words); /* t4 = y3 */

    uECC_vli_set(X2, t5, num_words);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uECC_word_t * X1,
                      uECC_word_t * Y1,
                      uECC_word_t * X2,
                      uECC_word_t * Y2) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_MAX_WORDS];
    uECC_word_t t6[uECC_MAX_WORDS];
    uECC_word_t t7[uECC_MAX_WORDS];
    wordcount_t num_words = curve_secp256k1.num_words;

    uECC_vli_modSub(t5, X2, X1, curve_secp256k1.p, num_words); /* t5 = x2 - x1 */
    uECC_vli_modSquare_fast(t5, t5);                  /* t5 = (x2 - x1)^2 = A */
    uECC_vli_modMult_fast(X1, X1, t5);                /* t1 = x1*A = B */
    uECC_vli_modMult_fast(X2, X2, t5);                /* t3 = x2*A = C */
    uECC_vli_modAdd(t5, Y2, Y1, curve_secp256k1.p, num_words); /* t5 = y2 + y1 */
    uECC_vli_modSub(Y2, Y2, Y1, curve_secp256k1.p, num_words); /* t4 = y2 - y1 */

    uECC_vli_modSub(t6, X2, X1, curve_secp256k1.p, num_words); /* t6 = C - B */
    uECC_vli_modMult_fast(Y1, Y1, t6);                /* t2 = y1 * (C - B) = E */
    uECC_vli_modAdd(t6, X1, X2, curve_secp256k1.p, num_words); /* t6 = B + C */
    uECC_vli_modSquare_fast(X2, Y2);                  /* t3 = (y2 - y1)^2 = D */
    uECC_vli_modSub(X2, X2, t6, curve_secp256k1.p, num_words); /* t3 = D - (B + C) = x3 */

    uECC_vli_modSub(t7, X1, X2, curve_secp256k1.p, num_words); /* t7 = B - x3 */
    uECC_vli_modMult_fast(Y2, Y2, t7);                /* t4 = (y2 - y1)*(B - x3) */
    uECC_vli_modSub(Y2, Y2, Y1, curve_secp256k1.p, num_words); /* t4 = (y2 - y1)*(B - x3) - E = y3 */

    uECC_vli_modSquare_fast(t7, t5);                  /* t7 = (y2 + y1)^2 = F */
    uECC_vli_modSub(t7, t7, t6, curve_secp256k1.p, num_words); /* t7 = F - (B + C) = x3' */
    uECC_vli_modSub(t6, t7, X1, curve_secp256k1.p, num_words); /* t6 = x3' - B */
    uECC_vli_modMult_fast(t6, t6, t5);                /* t6 = (y2+y1)*(x3' - B) */
    uECC_vli_modSub(Y1, t6, Y1, curve_secp256k1.p, num_words); /* t2 = (y2+y1)*(x3' - B) - E = y3' */

    uECC_vli_set(X1, t7, num_words);
}

/* result may overlap point. */
static void EccPoint_mult(uECC_word_t * result,
                          const uECC_word_t * point,
                          const uECC_word_t * scalar,
                          const uECC_word_t * initial_Z,
                          bitcount_t num_bits) {
    /* R0 and R1 */
    uECC_word_t Rx[2][uECC_MAX_WORDS];
    uECC_word_t Ry[2][uECC_MAX_WORDS];
    uECC_word_t z[uECC_MAX_WORDS];
    bitcount_t i;
    uECC_word_t nb;
    wordcount_t num_words = curve_secp256k1.num_words;

    uECC_vli_set(Rx[1], point, num_words);
    uECC_vli_set(Ry[1], point + num_words, num_words);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initial_Z);

    for (i = num_bits - 2; i > 0; --i) {
        nb = !uECC_vli_testBit(scalar, i);
        XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
    }

    nb = !uECC_vli_testBit(scalar, 0);
    XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

    /* Find final 1/Z value. */
    uECC_vli_modSub(z, Rx[1], Rx[0], curve_secp256k1.p, num_words); /* X1 - X0 */
    uECC_vli_modMult_fast(z, z, Ry[1 - nb]);               /* Yb * (X1 - X0) */
    uECC_vli_modMult_fast(z, z, point);                    /* xP * Yb * (X1 - X0) */
    uECC_vli_modInv(z, z, curve_secp256k1.p, num_words);            /* 1 / (xP * Yb * (X1 - X0)) */
    /* yP / (xP * Yb * (X1 - X0)) */
    uECC_vli_modMult_fast(z, z, point + num_words);
    uECC_vli_modMult_fast(z, z, Rx[1 - nb]); /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
    apply_z(Rx[0], Ry[0], z);

    uECC_vli_set(result, Rx[0], num_words);
    uECC_vli_set(result + num_words, Ry[0], num_words);
}

static uECC_word_t regularize_k(const uECC_word_t * const k,
                                uECC_word_t *k0,
                                uECC_word_t *k1) {
    wordcount_t num_n_words = BITS_TO_WORDS(curve_secp256k1.num_n_bits);
    bitcount_t num_n_bits = curve_secp256k1.num_n_bits;
    uECC_word_t carry = uECC_vli_add(k0, k, curve_secp256k1.n, num_n_words) ||
        (num_n_bits < ((bitcount_t)num_n_words * uECC_WORD_SIZE * 8) &&
         uECC_vli_testBit(k0, num_n_bits));
    uECC_vli_add(k1, k0, curve_secp256k1.n, num_n_words);
    return carry;
}

static uECC_word_t EccPoint_compute_public_key(uECC_word_t *result,
                                               uECC_word_t *private_key) {
    uECC_word_t tmp1[uECC_MAX_WORDS];
    uECC_word_t tmp2[uECC_MAX_WORDS];
    uECC_word_t *p2[2] = {tmp1, tmp2};
    uECC_word_t carry;

    /* Regularize the bitcount for the private key so that attackers cannot use a side channel
       attack to learn the number of leading zeros. */
    carry = regularize_k(private_key, tmp1, tmp2);

    EccPoint_mult(result, curve_secp256k1.G, p2[!carry], 0, curve_secp256k1.num_n_bits + 1);

    if (EccPoint_isZero(result)) {
        return 0;
    }
    return 1;
}

#if uECC_WORD_SIZE == 1

void uECC_vli_nativeToBytes(uint8_t *bytes,
                                         int num_bytes,
                                         const uint8_t *native) {
    wordcount_t i;
    for (i = 0; i < num_bytes; ++i) {
        bytes[i] = native[(num_bytes - 1) - i];
    }
}

void uECC_vli_bytesToNative(uint8_t *native,
                                         const uint8_t *bytes,
                                         int num_bytes) {
    uECC_vli_nativeToBytes(native, num_bytes, bytes);
}

#else

void uECC_vli_nativeToBytes(uint8_t *bytes,
                                         int num_bytes,
                                         const uECC_word_t *native) {
    wordcount_t i;
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        bytes[i] = native[b / uECC_WORD_SIZE] >> (8 * (b % uECC_WORD_SIZE));
    }
}

void uECC_vli_bytesToNative(uECC_word_t *native,
                                         const uint8_t *bytes,
                                         int num_bytes) {
    wordcount_t i;
    uECC_vli_clear(native, (num_bytes + (uECC_WORD_SIZE - 1)) / uECC_WORD_SIZE);
    for (i = 0; i < num_bytes; ++i) {
        unsigned b = num_bytes - 1 - i;
        native[b / uECC_WORD_SIZE] |=
            (uECC_word_t)bytes[i] << (8 * (b % uECC_WORD_SIZE));
    }
}

#endif /* uECC_WORD_SIZE */

int uECC_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret) {
    uECC_word_t _public[uECC_MAX_WORDS * 2];
    uECC_word_t _private[uECC_MAX_WORDS];

    uECC_word_t tmp[uECC_MAX_WORDS];
    uECC_word_t *p2[2] = {_private, tmp};
    uECC_word_t *initial_Z = 0;
    uECC_word_t carry;
    wordcount_t num_words = curve_secp256k1.num_words;
    wordcount_t num_bytes = curve_secp256k1.num_bytes;

#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) _private, private_key, num_bytes);
    bcopy((uint8_t *) _public, public_key, num_bytes*2);
#else
    uECC_vli_bytesToNative(_private, private_key, BITS_TO_BYTES(curve_secp256k1.num_n_bits));
    uECC_vli_bytesToNative(_public, public_key, num_bytes);
    uECC_vli_bytesToNative(_public + num_words, public_key + num_bytes, num_bytes);
#endif

    /* Regularize the bitcount for the private key so that attackers cannot use a side channel
       attack to learn the number of leading zeros. */
    carry = regularize_k(_private, _private, tmp);

    EccPoint_mult(_public, _public, p2[!carry], initial_Z, curve_secp256k1.num_n_bits + 1);
#if uECC_VLI_NATIVE_LITTLE_ENDIAN
    bcopy((uint8_t *) secret, (uint8_t *) _public, num_bytes);
#else
    uECC_vli_nativeToBytes(secret, num_bytes, _public);
#endif
    return !EccPoint_isZero(_public);
}

void uECC_compress(const uint8_t *public_key, uint8_t *compressed) {
    wordcount_t i;
    for (i = 0; i < curve_secp256k1.num_bytes; ++i) {
        compressed[i+1] = public_key[i];
    }
    compressed[0] = 2 + (public_key[curve_secp256k1.num_bytes * 2 - 1] & 0x01);
}

void uECC_decompress(const uint8_t *compressed, uint8_t *public_key) {
    uECC_word_t point[uECC_MAX_WORDS * 2];
    uECC_word_t *y = point + curve_secp256k1.num_words;
    uECC_vli_bytesToNative(point, compressed + 1, curve_secp256k1.num_bytes);
    curve_secp256k1.x_side(y, point);
    curve_secp256k1.mod_sqrt(y);

    if ((y[0] & 0x01) != (compressed[0] & 0x01)) {
        uECC_vli_sub(y, curve_secp256k1.p, y, curve_secp256k1.num_words);
    }

    uECC_vli_nativeToBytes(public_key, curve_secp256k1.num_bytes, point);
    uECC_vli_nativeToBytes(public_key + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes, y);
}

int uECC_valid_point(const uECC_word_t *point) {
    uECC_word_t tmp1[uECC_MAX_WORDS];
    uECC_word_t tmp2[uECC_MAX_WORDS];
    wordcount_t num_words = curve_secp256k1.num_words;

    /* The point at infinity is invalid. */
    if (EccPoint_isZero(point)) {
        return 0;
    }

    /* x and y must be smaller than p. */
    if (uECC_vli_cmp_unsafe(curve_secp256k1.p, point, num_words) != 1 ||
            uECC_vli_cmp_unsafe(curve_secp256k1.p, point + num_words, num_words) != 1) {
        return 0;
    }

    uECC_vli_modSquare_fast(tmp1, point + num_words);
    curve_secp256k1.x_side(tmp2, point); /* tmp2 = x^3 + ax + b */

    /* Make sure that y^2 == x^3 + ax + b */
    return (int)(uECC_vli_equal(tmp1, tmp2, num_words));
}

int uECC_valid_public_key(const uint8_t *public_key) {
    uECC_word_t _public[uECC_MAX_WORDS * 2];

    uECC_vli_bytesToNative(_public, public_key, curve_secp256k1.num_bytes);
    uECC_vli_bytesToNative(_public + curve_secp256k1.num_words, public_key + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes);

    return uECC_valid_point(_public);
}

int uECC_valid_private_key(const uint8_t *private_key) {
    uECC_word_t _private[uECC_MAX_WORDS];
    uECC_vli_bytesToNative(_private, private_key, BITS_TO_BYTES(curve_secp256k1.num_n_bits));

    /* Make sure the private key is in the range [1, n-1]. */
    if (uECC_vli_isZero(_private, BITS_TO_WORDS(curve_secp256k1.num_n_bits))) {
        return 0;
    }

    if (uECC_vli_cmp(curve_secp256k1.n, _private, BITS_TO_WORDS(curve_secp256k1.num_n_bits)) != 1) {
        return 0;
    }

    return 1;
}

int uECC_public_point_tweak(uint8_t *result, const uint8_t *public_key, const uint8_t *scalar) {
    uECC_word_t _public[uECC_MAX_WORDS * 2] = {0};
    uECC_word_t _result[uECC_MAX_WORDS * 2] = {0};
    uECC_word_t _scalar[uECC_MAX_WORDS] = {0};
    uECC_word_t _s_mul_G[uECC_MAX_WORDS * 2] = {0};

    uECC_vli_bytesToNative(_public, public_key, curve_secp256k1.num_bytes);
    uECC_vli_bytesToNative(_public + curve_secp256k1.num_words, public_key + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes);
    uECC_vli_bytesToNative(_scalar, scalar, BITS_TO_BYTES(curve_secp256k1.num_n_bits));

    // Make sure that public key is valid
    if (!uECC_valid_point(_public)) {
        return 0;
    }

    /* Public key is computed by multiplication i.e. scalar*G whis is what we need */
    if (!EccPoint_compute_public_key(_s_mul_G, _scalar)) {
        return 0;
    }
    
    /* R = A + scalar*G */
    EccPoint_add(_result, _public, _s_mul_G);

    // Ensure that new public key is valid as well
    if (!uECC_valid_point(_result)) {
        return 0;
    }

    uECC_vli_nativeToBytes(result, curve_secp256k1.num_bytes, _result);
    uECC_vli_nativeToBytes(result + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes, _result + curve_secp256k1.num_words);

    return 1;
}

int uECC_private_scalar_tweak(uint8_t *result, const uint8_t *private_key, const uint8_t *scalar) {
    uECC_word_t _private[uECC_MAX_WORDS];
    uECC_word_t _result[uECC_MAX_WORDS];
    uECC_word_t _scalar[uECC_MAX_WORDS];

    uECC_vli_bytesToNative(_private, private_key, BITS_TO_BYTES(curve_secp256k1.num_n_bits));
    uECC_vli_bytesToNative(_scalar, scalar, BITS_TO_BYTES(curve_secp256k1.num_n_bits));

    /* Make sure the private key is in the range [1, n-1]. */
    if (uECC_vli_isZero(_private, BITS_TO_WORDS(curve_secp256k1.num_n_bits))) {
        return 0;
    }

    if (uECC_vli_cmp(curve_secp256k1.n, _private, BITS_TO_WORDS(curve_secp256k1.num_n_bits)) != 1) {
        return 0;
    }

    /* Make sure that scalar is in the range [1, n-1] */
    if (uECC_vli_isZero(_scalar, BITS_TO_WORDS(curve_secp256k1.num_n_bits))) {
        return 0;
    }

    if (uECC_vli_cmp(curve_secp256k1.n, _scalar, BITS_TO_WORDS(curve_secp256k1.num_n_bits)) != 1) {
        return 0;
    }

    /* Apply scalar addition
       r = (a + scalar) % n
    */
    uECC_vli_modAdd(_result, _private, _scalar, curve_secp256k1.n, BITS_TO_WORDS(curve_secp256k1.num_n_bits));

    /* Check again that the new private key is in the range [1, n-1]. */
    if (uECC_vli_isZero(_result, BITS_TO_WORDS(curve_secp256k1.num_n_bits))) {
        return 0;
    }

    if (uECC_vli_cmp(curve_secp256k1.n, _result, BITS_TO_WORDS(curve_secp256k1.num_n_bits)) != 1) {
        return 0;
    }

    uECC_vli_nativeToBytes(result, curve_secp256k1.num_bytes, _result);

    return 1;
}

int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key) {
    uECC_word_t _private[uECC_MAX_WORDS];
    uECC_word_t _public[uECC_MAX_WORDS * 2];

    uECC_vli_bytesToNative(_private, private_key, BITS_TO_BYTES(curve_secp256k1.num_n_bits));

    /* Make sure the private key is in the range [1, n-1]. */
    if (uECC_vli_isZero(_private, BITS_TO_WORDS(curve_secp256k1.num_n_bits))) {
        return 0;
    }

    if (uECC_vli_cmp(curve_secp256k1.n, _private, BITS_TO_WORDS(curve_secp256k1.num_n_bits)) != 1) {
        return 0;
    }

    /* Compute public key. */
    if (!EccPoint_compute_public_key(_public, _private)) {
        return 0;
    }

    uECC_vli_nativeToBytes(public_key, curve_secp256k1.num_bytes, _public);
    uECC_vli_nativeToBytes(public_key + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes, _public + curve_secp256k1.num_words);
    return 1;
}


/* -------- ECDSA code -------- */

static void bits2int(uECC_word_t *native,
                     const uint8_t *bits,
                     unsigned bits_size) {
    unsigned num_n_bytes = BITS_TO_BYTES(curve_secp256k1.num_n_bits);
    unsigned num_n_words = BITS_TO_WORDS(curve_secp256k1.num_n_bits);
    int shift;
    uECC_word_t carry;
    uECC_word_t *ptr;

    if (bits_size > num_n_bytes) {
        bits_size = num_n_bytes;
    }

    uECC_vli_clear(native, num_n_words);
    uECC_vli_bytesToNative(native, bits, bits_size);
    if (bits_size * 8 <= (unsigned)curve_secp256k1.num_n_bits) {
        return;
    }
    shift = bits_size * 8 - curve_secp256k1.num_n_bits;
    carry = 0;
    ptr = native + num_n_words;
    while (ptr-- > native) {
        uECC_word_t temp = *ptr;
        *ptr = (temp >> shift) | carry;
        carry = temp << (uECC_WORD_BITS - shift);
    }

    /* Reduce mod curve_n */
    if (uECC_vli_cmp_unsafe(curve_secp256k1.n, native, num_n_words) != 1) {
        uECC_vli_sub(native, native, curve_secp256k1.n, num_n_words);
    }
}

static int uECC_sign_with_k(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            uECC_word_t *k,
                            uint8_t *signature) {

    uECC_word_t tmp[uECC_MAX_WORDS];
    uECC_word_t s[uECC_MAX_WORDS];
    uECC_word_t *k2[2] = {tmp, s};
    uECC_word_t p[uECC_MAX_WORDS * 2];
    uECC_word_t carry;
    wordcount_t num_words = curve_secp256k1.num_words;
    wordcount_t num_n_words = BITS_TO_WORDS(curve_secp256k1.num_n_bits);
    bitcount_t num_n_bits = curve_secp256k1.num_n_bits;

    /* Make sure 0 < k < curve_n */
    if (uECC_vli_isZero(k, num_words) || uECC_vli_cmp(curve_secp256k1.n, k, num_n_words) != 1) {
        return 0;
    }

    carry = regularize_k(k, tmp, s);
    EccPoint_mult(p, curve_secp256k1.G, k2[!carry], 0, num_n_bits + 1);
    if (uECC_vli_isZero(p, num_words)) {
        return 0;
    }

    // Stub: No RNG function is actually used here
    uECC_vli_clear(tmp, num_n_words);
    tmp[0] = 1;

    /* Prevent side channel analysis of uECC_vli_modInv() to determine
       bits of k / the private key by premultiplying by a random number */
    uECC_vli_modMult(k, k, tmp, curve_secp256k1.n, num_n_words); /* k' = rand * k */
    uECC_vli_modInv(k, k, curve_secp256k1.n, num_n_words);       /* k = 1 / k' */
    uECC_vli_modMult(k, k, tmp, curve_secp256k1.n, num_n_words); /* k = 1 / k */

    uECC_vli_nativeToBytes(signature, curve_secp256k1.num_bytes, p); /* store r */
    uECC_vli_bytesToNative(tmp, private_key, BITS_TO_BYTES(curve_secp256k1.num_n_bits)); /* tmp = d */

    s[num_n_words - 1] = 0;
    uECC_vli_set(s, p, num_words);
    uECC_vli_modMult(s, tmp, s, curve_secp256k1.n, num_n_words); /* s = r*d */

    bits2int(tmp, message_hash, hash_size);
    uECC_vli_modAdd(s, tmp, s, curve_secp256k1.n, num_n_words); /* s = e + r*d */
    uECC_vli_modMult(s, s, k, curve_secp256k1.n, num_n_words);  /* s = (e + r*d) / k */
    if (uECC_vli_numBits(s, num_n_words) > (bitcount_t)curve_secp256k1.num_bytes * 8) {
        return 0;
    }

    if (uECC_vli_cmp(s, curve_secp256k1.half_n, curve_secp256k1.num_words) == 1) {
        /* Apply Low-S rule to signature */
        uECC_vli_sub(s, curve_secp256k1.n, s, curve_secp256k1.num_words); /* s = n - s */
    }

    uECC_vli_nativeToBytes(signature + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes, s);

    return 1;
}

/* Compute an HMAC using K as a key. Note that K is always
   the same size as the hash result size. */

/* V = HMAC_K(V) */
static void update_V(const uECC_HashContext *hash_context, uint8_t *K, uint8_t *V) {
    hash_context->hmac_init(hash_context, K, hash_context->digest_size);
    hash_context->hmac_update(hash_context, V, hash_context->digest_size);
    hash_context->hmac_finish(hash_context, V);
}

/* Deterministic signing, similar to RFC 6979. Differences are:
    * We just use H(m) directly rather than bits2octets(H(m))
      (it is not reduced modulo curve_n).
    * We generate a value for k (aka T) directly rather than converting endianness.

   Layout of hash_context->tmp: <K> | <V> | (1 byte overlapped 0x00 or 0x01) */
int uECC_sign_deterministic(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            const uECC_HashContext *hash_context,
                            uint8_t *signature) {
    uint8_t *K = hash_context->tmp;
    uint8_t *V = K + hash_context->digest_size;
    wordcount_t num_bytes = curve_secp256k1.num_bytes;
    wordcount_t num_n_words = BITS_TO_WORDS(curve_secp256k1.num_n_bits);
    bitcount_t num_n_bits = curve_secp256k1.num_n_bits;
    uECC_word_t tries;
    unsigned i;
    for (i = 0; i < hash_context->digest_size; ++i) {
        V[i] = 0x01;
        K[i] = 0;
    }

    /* K = HMAC_K(V || 0x00 || int2octets(x) || h(m)) */
    hash_context->hmac_init(hash_context, K, hash_context->digest_size);
    V[hash_context->digest_size] = 0x00;
    hash_context->hmac_update(hash_context, V, hash_context->digest_size + 1);
    hash_context->hmac_update(hash_context, private_key, num_bytes);
    hash_context->hmac_update(hash_context, message_hash, hash_size);
    hash_context->hmac_finish(hash_context, K);

    update_V(hash_context, K, V);

    /* K = HMAC_K(V || 0x01 || int2octets(x) || h(m)) */
    hash_context->hmac_init(hash_context, K, hash_context->digest_size);
    V[hash_context->digest_size] = 0x01;
    hash_context->hmac_update(hash_context, V, hash_context->digest_size + 1);
    hash_context->hmac_update(hash_context, private_key, num_bytes);
    hash_context->hmac_update(hash_context, message_hash, hash_size);
    hash_context->hmac_finish(hash_context, K);

    update_V(hash_context, K, V);

    for (tries = 0; tries < uECC_RNG_MAX_TRIES; ++tries) {
        uECC_word_t T[uECC_MAX_WORDS];
        uint8_t *T_ptr = (uint8_t *)T;
        wordcount_t T_bytes = 0;
        for (;;) {
            update_V(hash_context, K, V);
            for (i = 0; i < hash_context->digest_size; ++i) {
                T_ptr[T_bytes++] = V[i];
                if (T_bytes >= num_n_words * uECC_WORD_SIZE) {
                    goto filled;
                }
            }
        }
    filled:
        if ((bitcount_t)num_n_words * uECC_WORD_SIZE * 8 > num_n_bits) {
            uECC_word_t mask = (uECC_word_t)-1;
            T[num_n_words - 1] &=
                mask >> ((bitcount_t)(num_n_words * uECC_WORD_SIZE * 8 - num_n_bits));
        }

        if (uECC_sign_with_k(private_key, message_hash, hash_size, T, signature)) {
            return 1;
        }

        /* K = HMAC_K(V || 0x00) */
        hash_context->hmac_init(hash_context, K, hash_context->digest_size);
        V[hash_context->digest_size] = 0x00;
        hash_context->hmac_update(hash_context, V, hash_context->digest_size + 1);
        hash_context->hmac_finish(hash_context, K);

        update_V(hash_context, K, V);
    }
    return 0;
}

static bitcount_t smax(bitcount_t a, bitcount_t b) {
    return (a > b ? a : b);
}

void uECC_compact_to_der(const uint8_t *compact, uint8_t *der) {
    const unsigned char *rp = compact, *sp = compact + curve_secp256k1.num_bytes;
    unsigned lenR = curve_secp256k1.num_bytes, lenS = curve_secp256k1.num_bytes;

    der[0] = 0x30;
    der[1] = 4 + lenS + lenR;
    der[2] = 0x02;
    der[3] = lenR;
    bcopy(der+4, rp, lenR);
    der[4+lenR] = 0x02;
    der[5+lenR] = lenS;
    bcopy(der+lenR+6, sp, lenS);
}

/* Based on parse_der_lax routine from bitcoin distribution */
int uECC_der_to_compact(const uint8_t *input, unsigned inputlen, uint8_t *compact) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= 4) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= 4) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Copy R value */
    if (rlen > 32) {
        /* Overflow */
        return 0;
    } else {
        bcopy(compact + 32 - rlen, input + rpos, rlen);
    }

    /* Copy S value */
    if (slen > 32) {
        /* Overflow */
        return 0;
    } else {
        bcopy(compact + 64 - slen, input + spos, slen);
    }

    return 1;
}

int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature) {
    uECC_word_t u1[uECC_MAX_WORDS], u2[uECC_MAX_WORDS];
    uECC_word_t z[uECC_MAX_WORDS];
    uECC_word_t sum[uECC_MAX_WORDS * 2];
    uECC_word_t rx[uECC_MAX_WORDS];
    uECC_word_t ry[uECC_MAX_WORDS];
    uECC_word_t tx[uECC_MAX_WORDS];
    uECC_word_t ty[uECC_MAX_WORDS];
    uECC_word_t tz[uECC_MAX_WORDS];
    const uECC_word_t *points[4];
    const uECC_word_t *point;
    bitcount_t num_bits;
    bitcount_t i;
    uECC_word_t _public[uECC_MAX_WORDS * 2];
    uECC_word_t r[uECC_MAX_WORDS], s[uECC_MAX_WORDS];
    wordcount_t num_words = curve_secp256k1.num_words;
    wordcount_t num_n_words = BITS_TO_WORDS(curve_secp256k1.num_n_bits);

    rx[num_n_words - 1] = 0;
    r[num_n_words - 1] = 0;
    s[num_n_words - 1] = 0;

    uECC_vli_bytesToNative(_public, public_key, curve_secp256k1.num_bytes);
    uECC_vli_bytesToNative(_public + num_words, public_key + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes);
    uECC_vli_bytesToNative(r, signature, curve_secp256k1.num_bytes);
    uECC_vli_bytesToNative(s, signature + curve_secp256k1.num_bytes, curve_secp256k1.num_bytes);

    /* r, s must not be 0. */
    if (uECC_vli_isZero(r, num_words) || uECC_vli_isZero(s, num_words)) {
        return 0;
    }

    /* r, s must be < n. */
    if (uECC_vli_cmp_unsafe(curve_secp256k1.n, r, num_n_words) != 1 ||
            uECC_vli_cmp_unsafe(curve_secp256k1.n, s, num_n_words) != 1) {
        return 0;
    }

    /* Calculate u1 and u2. */
    uECC_vli_modInv(z, s, curve_secp256k1.n, num_n_words); /* z = 1/s */
    u1[num_n_words - 1] = 0;
    bits2int(u1, message_hash, hash_size);
    uECC_vli_modMult(u1, u1, z, curve_secp256k1.n, num_n_words); /* u1 = e/s */
    uECC_vli_modMult(u2, r, z, curve_secp256k1.n, num_n_words); /* u2 = r/s */

    /* Calculate sum = G + Q. */
    uECC_vli_set(sum, _public, num_words);
    uECC_vli_set(sum + num_words, _public + num_words, num_words);
    uECC_vli_set(tx, curve_secp256k1.G, num_words);
    uECC_vli_set(ty, curve_secp256k1.G + num_words, num_words);
    uECC_vli_modSub(z, sum, tx, curve_secp256k1.p, num_words); /* z = x2 - x1 */
    XYcZ_add(tx, ty, sum, sum + num_words);
    uECC_vli_modInv(z, z, curve_secp256k1.p, num_words); /* z = 1/z */
    apply_z(sum, sum + num_words, z);

    /* Use Shamir's trick to calculate u1*G + u2*Q */
    points[0] = 0;
    points[1] = curve_secp256k1.G;
    points[2] = _public;
    points[3] = sum;
    num_bits = smax(uECC_vli_numBits(u1, num_n_words),
                    uECC_vli_numBits(u2, num_n_words));

    point = points[(!!uECC_vli_testBit(u1, num_bits - 1)) |
                   ((!!uECC_vli_testBit(u2, num_bits - 1)) << 1)];
    uECC_vli_set(rx, point, num_words);
    uECC_vli_set(ry, point + num_words, num_words);
    uECC_vli_clear(z, num_words);
    z[0] = 1;

    for (i = num_bits - 2; i >= 0; --i) {
        uECC_word_t index;
        curve_secp256k1.double_jacobian(rx, ry, z);

        index = (!!uECC_vli_testBit(u1, i)) | ((!!uECC_vli_testBit(u2, i)) << 1);
        point = points[index];
        if (point) {
            uECC_vli_set(tx, point, num_words);
            uECC_vli_set(ty, point + num_words, num_words);
            apply_z(tx, ty, z);
            uECC_vli_modSub(tz, rx, tx, curve_secp256k1.p, num_words); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry);
            uECC_vli_modMult_fast(z, z, tz);
        }
    }

    uECC_vli_modInv(z, z, curve_secp256k1.p, num_words); /* Z = 1/Z */
    apply_z(rx, ry, z);

    /* v = x1 (mod n) */
    if (uECC_vli_cmp_unsafe(curve_secp256k1.n, rx, num_n_words) != 1) {
        uECC_vli_sub(rx, rx, curve_secp256k1.n, num_n_words);
    }

    /* Accept only if v == r. */
    return (int)(uECC_vli_equal(rx, r, num_words));
}

unsigned uECC_curve_num_words() {
    return curve_secp256k1.num_words;
}

unsigned uECC_curve_num_bytes() {
    return curve_secp256k1.num_bytes;
}

unsigned uECC_curve_num_bits() {
    return curve_secp256k1.num_bytes * 8;
}

unsigned uECC_curve_num_n_words() {
    return BITS_TO_WORDS(curve_secp256k1.num_n_bits);
}

unsigned uECC_curve_num_n_bytes() {
    return BITS_TO_BYTES(curve_secp256k1.num_n_bits);
}

unsigned uECC_curve_num_n_bits() {
    return curve_secp256k1.num_n_bits;
}

const uECC_word_t *uECC_curve_p() {
    return curve_secp256k1.p;
}

const uECC_word_t *uECC_curve_n() {
    return curve_secp256k1.n;
}

const uECC_word_t *uECC_curve_G() {
    return curve_secp256k1.G;
}

const uECC_word_t *uECC_curve_b() {
    return curve_secp256k1.b;
}

void uECC_vli_mod_sqrt(uECC_word_t *a) {
    curve_secp256k1.mod_sqrt(a);
}

void uECC_vli_mmod_fast(uECC_word_t *result, uECC_word_t *product) {
#if (uECC_OPTIMIZATION_LEVEL > 0)
    curve_secp256k1.mmod_fast(result, product);
#else
    uECC_vli_mmod(result, product, curve_secp256k1.p, curve_secp256k1.num_words);
#endif
}

void uECC_point_mult(uECC_word_t *result,
                     const uECC_word_t *point,
                     const uECC_word_t *scalar) {
    uECC_word_t tmp1[uECC_MAX_WORDS];
    uECC_word_t tmp2[uECC_MAX_WORDS];
    uECC_word_t *p2[2] = {tmp1, tmp2};
    uECC_word_t carry = regularize_k(scalar, tmp1, tmp2);

    EccPoint_mult(result, point, p2[!carry], 0, curve_secp256k1.num_n_bits + 1);
}

/* ECC Point Addition R = P + Q */
void EccPoint_add(uECC_word_t *R, const uECC_word_t *input_P, const uECC_word_t *input_Q){
    uECC_word_t P[uECC_MAX_WORDS * 2];
    uECC_word_t Q[uECC_MAX_WORDS * 2];
    uECC_word_t z[uECC_MAX_WORDS];

    wordcount_t num_words = curve_secp256k1.num_words;

    uECC_vli_set(P, input_P, num_words);
    uECC_vli_set(P + num_words, input_P + num_words, num_words);
    uECC_vli_set(Q, input_Q, num_words);
    uECC_vli_set(Q + num_words, input_Q + num_words, num_words);

    XYcZ_add(P, P + num_words, Q, Q + num_words);

    /* Find final 1/Z value. */
    uECC_vli_modMult_fast(z, input_P, P + num_words);
    uECC_vli_modInv(z, z, curve_secp256k1.p, num_words);
    uECC_vli_modMult_fast(z, z, P);
    uECC_vli_modMult_fast(z, z, input_P + num_words);
    /* End 1/Z calculation */

    apply_z(Q, Q + num_words, z);

    uECC_vli_set(R, Q, num_words);
    uECC_vli_set(R + num_words, Q + num_words, num_words);
}
