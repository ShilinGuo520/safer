/* 1. Standard types for AES cryptography source code               */

/* 2. Basic macros for speeding up generic operations               */

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

/* Invert byte order in a 32 bit variable                           */
#define bswap(x)    (rotl(x, 8) & 0x00ff00ff | rotr(x, 8) & 0xff00ff00)

/* For inverting byte order in input/output 32 bit words if needed  */
#define io_swap(x)  bswap(x)

/* For inverting the byte order of input/output blocks if needed    */
#define get_key(x,len)                          \
    ((unsigned int*)(x))[4] = ((unsigned int*)(x))[5] =     \
    ((unsigned int*)(x))[6] = ((unsigned int*)(x))[7] = 0;  \
    switch((((len) + 63) / 64)) {               \
    case 4:                                     \
    ((unsigned int*)(x))[6] = io_swap(in_key[6]);     \
    ((unsigned int*)(x))[7] = io_swap(in_key[7]);     \
    case 3:                                     \
    ((unsigned int*)(x))[4] = io_swap(in_key[4]);     \
    ((unsigned int*)(x))[5] = io_swap(in_key[5]);     \
    case 2:                                     \
    ((unsigned int*)(x))[0] = io_swap(in_key[0]);     \
    ((unsigned int*)(x))[1] = io_swap(in_key[1]);     \
    ((unsigned int*)(x))[2] = io_swap(in_key[2]);     \
    ((unsigned int*)(x))[3] = io_swap(in_key[3]);     \
    }
