
/* Timing data for SAFER+ (safer.c) */

#include "./std_defs.h"
#include "stdio.h" 
#include "string.h"

unsigned char  expf[256] =
{     1,  45, 226, 147, 190,  69,  21, 174, 120,   3, 135, 164, 184,  56, 207,  63, 
      8, 103,   9, 148, 235,  38, 168, 107, 189,  24,  52,  27, 187, 191, 114, 247, 
     64,  53,  72, 156,  81,  47,  59,  85, 227, 192, 159, 216, 211, 243, 141, 177, 
    255, 167,  62, 220, 134, 119, 215, 166,  17, 251, 244, 186, 146, 145, 100, 131, 
    241,  51, 239, 218,  44, 181, 178,  43, 136, 209, 153, 203, 140, 132,  29,  20, 
    129, 151, 113, 202,  95, 163, 139,  87,  60, 130, 196,  82,  92,  28, 232, 160, 
      4, 180, 133,  74, 246,  19,  84, 182, 223,  12,  26, 142, 222, 224,  57, 252, 
     32, 155,  36,  78, 169, 152, 158, 171, 242,  96, 208, 108, 234, 250, 199, 217, 
      0, 212,  31, 110,  67, 188, 236,  83, 137, 254, 122,  93,  73, 201,  50, 194, 
    249, 154, 248, 109,  22, 219,  89, 150,  68, 233, 205, 230,  70,  66, 143,  10, 
    193, 204, 185, 101, 176, 210, 198, 172,  30,  65,  98,  41,  46,  14, 116,  80, 
      2,  90, 195,  37, 123, 138,  42,  91, 240,   6,  13,  71, 111, 112, 157, 126, 
     16, 206,  18,  39, 213,  76,  79, 214, 121,  48, 104,  54, 117, 125, 228, 237, 
    128, 106, 144,  55, 162,  94, 118, 170, 197, 127,  61, 175, 165, 229,  25,  97, 
    253,  77, 124, 183,  11, 238, 173,  75,  34, 245, 231, 115,  35,  33, 200,   5, 
    225, 102, 221, 179,  88, 105,  99,  86,  15, 161,  49, 149,  23,   7,  58,  40 
};
 
unsigned char logf[512] = 
{
    128,   0, 176,   9,  96, 239, 185, 253,  16,  18, 159, 228, 105, 186, 173, 248, 
    192,  56, 194, 101,  79,   6, 148, 252,  25, 222, 106,  27,  93,  78, 168, 130, 
    112, 237, 232, 236, 114, 179,  21, 195, 255, 171, 182,  71,  68,   1, 172,  37, 
    201, 250, 142,  65,  26,  33, 203, 211,  13, 110, 254,  38,  88, 218,  50,  15, 
     32, 169, 157, 132, 152,   5, 156, 187,  34, 140,  99, 231, 197, 225, 115, 198, 
    175,  36,  91, 135, 102,  39, 247,  87, 244, 150, 177, 183,  92, 139, 213,  84, 
    121, 223, 170, 246,  62, 163, 241,  17, 202, 245, 209,  23, 123, 147, 131, 188, 
    189,  82,  30, 235, 174, 204, 214,  53,   8, 200, 138, 180, 226, 205, 191, 217, 
    208,  80,  89,  63,  77,  98,  52,  10,  72, 136, 181,  86,  76,  46, 107, 158, 
    210,  61,  60,   3,  19, 251, 151,  81, 117,  74, 145, 113,  35, 190, 118,  42, 
     95, 249, 212,  85,  11, 220,  55,  49,  22, 116, 215, 119, 167, 230,   7, 219, 
    164,  47,  70, 243,  97,  69, 103, 227,  12, 162,  59,  28, 133,  24,   4,  29, 
     41, 160, 143, 178,  90, 216, 166, 126, 238, 141,  83,  75, 161, 154, 193,  14, 
    122,  73, 165,  44, 129, 196, 199,  54,  43, 127,  67, 149,  51, 242, 108, 104, 
    109, 240,   2,  40, 206, 221, 155, 234,  94, 153, 124,  20, 134, 207, 229,  66, 
    184,  64, 120,  45,  58, 233, 100,  31, 146, 144, 125,  57, 111, 224, 137,  48,
 
    128,   0, 176,   9,  96, 239, 185, 253,  16,  18, 159, 228, 105, 186, 173, 248, 
    192,  56, 194, 101,  79,   6, 148, 252,  25, 222, 106,  27,  93,  78, 168, 130, 
    112, 237, 232, 236, 114, 179,  21, 195, 255, 171, 182,  71,  68,   1, 172,  37, 
    201, 250, 142,  65,  26,  33, 203, 211,  13, 110, 254,  38,  88, 218,  50,  15, 
     32, 169, 157, 132, 152,   5, 156, 187,  34, 140,  99, 231, 197, 225, 115, 198, 
    175,  36,  91, 135, 102,  39, 247,  87, 244, 150, 177, 183,  92, 139, 213,  84, 
    121, 223, 170, 246,  62, 163, 241,  17, 202, 245, 209,  23, 123, 147, 131, 188, 
    189,  82,  30, 235, 174, 204, 214,  53,   8, 200, 138, 180, 226, 205, 191, 217, 
    208,  80,  89,  63,  77,  98,  52,  10,  72, 136, 181,  86,  76,  46, 107, 158, 
    210,  61,  60,   3,  19, 251, 151,  81, 117,  74, 145, 113,  35, 190, 118,  42, 
     95, 249, 212,  85,  11, 220,  55,  49,  22, 116, 215, 119, 167, 230,   7, 219, 
    164,  47,  70, 243,  97,  69, 103, 227,  12, 162,  59,  28, 133,  24,   4,  29, 
     41, 160, 143, 178,  90, 216, 166, 126, 238, 141,  83,  75, 161, 154, 193,  14, 
    122,  73, 165,  44, 129, 196, 199,  54,  43, 127,  67, 149,  51, 242, 108, 104, 
    109, 240,   2,  40, 206, 221, 155, 234,  94, 153, 124,  20, 134, 207, 229,  66, 
    184,  64, 120,  45,  58, 233, 100,  31, 146, 144, 125,  57, 111, 224, 137,  48
};
 
unsigned char  l_key[33 * 16];
unsigned int  k_bytes;
 
unsigned int *set_key(const unsigned int in_key[], const unsigned int key_len)
{
    unsigned char  by, lk[33];
    unsigned int  i, j, k, l, m;
 
    get_key(lk, key_len);
    k_bytes = key_len / 8; lk[k_bytes] = 0;
 
    for(i = 0; i < k_bytes; ++i) {
        lk[k_bytes] ^= lk[i]; l_key[i] = lk[i];
    }
 
    for(i = 0; i < k_bytes; ++i) {
        for(j = 0; j <= k_bytes; ++j) {
            by = lk[j]; lk[j] = by << 3 | by >> 5;
        }
        k = 17 * i + 35; l = 16 * i + 16; m = i + 1;
 
        if(i < 16) {
            for(j = 0; j < 16; ++j) {
                l_key[l + j] = lk[m] + expf[expf[(k + j) & 255]];
                m = (m == k_bytes ? 0 : m + 1);
            }
        } else {
            for(j = 0; j < 16; ++j) {
                l_key[l + j] = lk[m] + expf[(k + j) & 255];
                m = (m == k_bytes ? 0 : m + 1);
            }
        }
    }
    return (unsigned int*)l_key;
}
 
void do_fr(unsigned char x[16], unsigned char *kp)
{
    unsigned char t;
 
    x[ 0] = expf[x[ 0] ^ kp[ 0]] + kp[16];
    x[ 1] = logf[x[ 1] + kp[ 1]] ^ kp[17]; 
    x[ 2] = logf[x[ 2] + kp[ 2]] ^ kp[18]; 
    x[ 3] = expf[x[ 3] ^ kp[ 3]] + kp[19];
 
    x[ 4] = expf[x[ 4] ^ kp[ 4]] + kp[20];
    x[ 5] = logf[x[ 5] + kp[ 5]] ^ kp[21]; 
    x[ 6] = logf[x[ 6] + kp[ 6]] ^ kp[22]; 
    x[ 7] = expf[x[ 7] ^ kp[ 7]] + kp[23];
  
    x[ 8] = expf[x[ 8] ^ kp[ 8]] + kp[24];
    x[ 9] = logf[x[ 9] + kp[ 9]] ^ kp[25]; 
    x[10] = logf[x[10] + kp[10]] ^ kp[26]; 
    x[11] = expf[x[11] ^ kp[11]] + kp[27];
 
    x[12] = expf[x[12] ^ kp[12]] + kp[28];
    x[13] = logf[x[13] + kp[13]] ^ kp[29]; 
    x[14] = logf[x[14] + kp[14]] ^ kp[30]; 
    x[15] = expf[x[15] ^ kp[15]] + kp[31];
 
    x[ 1] += x[ 0]; x[ 0] += x[ 1];
    x[ 3] += x[ 2]; x[ 2] += x[ 3];
    x[ 5] += x[ 4]; x[ 4] += x[ 5];
    x[ 7] += x[ 6]; x[ 6] += x[ 7];
    x[ 9] += x[ 8]; x[ 8] += x[ 9];
    x[11] += x[10]; x[10] += x[11];
    x[13] += x[12]; x[12] += x[13];
    x[15] += x[14]; x[14] += x[15];
 
    x[ 7] += x[ 0]; x[ 0] += x[ 7];
    x[ 1] += x[ 2]; x[ 2] += x[ 1];
    x[ 3] += x[ 4]; x[ 4] += x[ 3];
    x[ 5] += x[ 6]; x[ 6] += x[ 5];
    x[11] += x[ 8]; x[ 8] += x[11];
    x[ 9] += x[10]; x[10] += x[ 9];
    x[15] += x[12]; x[12] += x[15];
    x[13] += x[14]; x[14] += x[13];
 
    x[ 3] += x[ 0]; x[ 0] += x[ 3];
    x[15] += x[ 2]; x[ 2] += x[15];
    x[ 7] += x[ 4]; x[ 4] += x[ 7];
    x[ 1] += x[ 6]; x[ 6] += x[ 1];
    x[ 5] += x[ 8]; x[ 8] += x[ 5];
    x[13] += x[10]; x[10] += x[13];
    x[11] += x[12]; x[12] += x[11];
    x[ 9] += x[14]; x[14] += x[ 9];
 
    x[13] += x[ 0]; x[ 0] += x[13];
    x[ 5] += x[ 2]; x[ 2] += x[ 5];
    x[ 9] += x[ 4]; x[ 4] += x[ 9];
    x[11] += x[ 6]; x[ 6] += x[11];
    x[15] += x[ 8]; x[ 8] += x[15];
    x[ 1] += x[10]; x[10] += x[ 1];
    x[ 3] += x[12]; x[12] += x[ 3];
    x[ 7] += x[14]; x[14] += x[ 7];
 
    t = x[0]; x[0] = x[14]; x[14] = x[12]; x[12] = x[10]; x[10] = x[2]; 
    x[2] = x[8]; x[8] = x[4]; x[4] = t;
 
    t = x[1]; x[1] = x[7]; x[7] = x[11]; x[11] = x[5]; x[5] = x[13]; x[13] = t; 
     
    t = x[15]; x[15] = x[3]; x[3] = t;
}
 
void get_key_j(unsigned char key_in[16] ,unsigned int key_out_j[4])
{
    int i;
    unsigned char key_out[16];
    key_out[0] = 0xff & (key_in[0] + 233);
    key_out[1] = key_in[1] ^ 229;
    key_out[2] = 0xff & (key_in[2] + 223);
    key_out[3] = key_in[3] ^ 193;
    key_out[4] = 0xff & (key_in[4] + 179);
    key_out[5] = key_in[5] ^ 167 ;
    key_out[6] = 0xff & (key_in[6] + 149);
    key_out[7] = key_in[7] ^ 131;
    key_out[8] = key_in[8] ^ 233;
    key_out[9] = 0xff & (key_in[9] + 229);
    key_out[10] = key_in[10] ^ 223;
    key_out[11] = 0xff & (key_in[11] + 193);
    key_out[12] = key_in[12] ^ 179;
    key_out[13] = 0xff & (key_in[13] + 167);
    key_out[14] = key_in[14] ^ 149;
    key_out[15] = 0xff & (key_in[15] + 131);
    for(i = 0 ;i < 4;i++) {
        key_out_j[i] = (key_out[4*i] << 24) | (key_out[4*i + 1] << 16) | (key_out[4*i + 2] << 8) | (key_out[4*i + 3]);
    }
}

void ar_round_added(unsigned char data[16] ,unsigned char input[16])
{
    int i ;
    for (i = 0 ;i < 16 ;i+=4) {
        data[i] = data[i] ^ input[i];
        data[i+1] = 0xff & (data[i+1] + input[i+1]);
        data[i+2] = 0xff & (data[i+2] + input[i+2]);
        data[i+3] = data[i+3] ^ input[i+3];
    }
}

void block_backup(unsigned char backup[16] ,unsigned char block[16])
{
    int i;
    for (i = 0 ;i < 16 ;i++) {
	backup[i] = block[i];
    }
}

void char2hex(const unsigned char ch[] ,unsigned char hex[])
{
    int i;
    unsigned char temp;
    int len;
    len = strlen(ch);
    len -= 2;
    memset(hex ,0 ,len/2);
    for(i = 0 ;i < len ;i++) {
        temp = 0;
        if(ch[i+2] >= 97)
            temp = ch[i+2] - 87;
        else if(ch[i+2] >= 65)
   	    temp = ch[i+2] - 55;
	else 
	    temp = ch[i+2] - 48;
        temp =0x0f & temp;
        hex[i/2] |= temp << (4 * (1 - i%2));
    }
}

void key_input(unsigned int key[4] ,const unsigned char key_c[])
{
    int i;
    unsigned char key_hex[16];
    printf("input key:\n%s\n" ,key_c);
    char2hex(key_c ,key_hex);
    for(i = 0 ;i < 4 ;i++) {
	key[i] = (key_hex[4*i] << 24) | (key_hex[4*i + 1] << 16) | (key_hex[4*i + 2] << 8) | (key_hex[4*i + 3]);
    }
}

void key_c2key(unsigned int key[4] ,unsigned char bd_addr[16])
{
    int i;
    unsigned char key_hex[16];
    memcpy(key_hex ,bd_addr ,16);
    for(i = 0 ;i < 4 ;i++) {
        key[i] = (key_hex[4*i] << 24) | (key_hex[4*i + 1] << 16) | (key_hex[4*i + 2] << 8) | (key_hex[4*i + 3]);
    }
}

void block_input(unsigned char block[16] ,const unsigned char round[])
{
    int i;
    unsigned char block_hex[16];
    printf("input round:\n%s\n" ,round);
    char2hex(round ,block_hex);
    for (i = 0 ;i < 16 ;i++) {
	block[i] = block_hex[i];
    }
}

void bdaddr_input(unsigned char bd_addr[16] ,const unsigned char addr[])
{
    int i;
    unsigned char addr_hex[6];
    printf("input bd addr:\n%s\n" ,addr);
    char2hex(addr ,addr_hex);
    for(i = 0 ;i < 16 ;i++) {
	bd_addr[i] = addr_hex[i%6];
    }
}

void aco_input(unsigned char cof[16] ,const unsigned char cof_c[])
{
    int i ;
    unsigned char cof_hex[12];
    printf("input aco: \n%s\n",cof_c);
    char2hex(cof_c ,cof_hex);
    for (i = 0 ; i < 16 ; i++) {
	cof[i] = cof_hex[i%12];
    }
}

int E1()
{
    int i ,j ;
    unsigned int key_in[4];
    unsigned int key_in_j[4];
    unsigned char block_in[16];
    unsigned char block_in_backup[16];
    unsigned char bd_addr[16];

    bdaddr_input(bd_addr ,"0x7ca89b233c2d");
    key_input(key_in ,"0x159dd9f43fc3d328efba0cd8a861fa57");
    block_input(block_in ,"0xbc3f30689647c8d7c5a03ca80a91eceb");

    set_key(key_in ,128);
    block_backup(block_in_backup ,block_in);

    for(j = 0 ;j < 256 ;j+=32) {
    	do_fr(block_in ,&l_key[j]);
    }

    ar_round_added(block_in ,l_key + 256);
 
    for (i = 0 ;i < 16 ;i ++) {
    	block_in[i] = block_in[i] ^ block_in_backup[i];
    }

    for (i = 0 ;i < 16 ;i ++) {
    	block_in[i] = (0xff & (block_in[i] + bd_addr[i]));
    }

    /* 2th round input(Ar`) */
    block_backup(block_in_backup ,block_in);
    get_key_j(l_key, key_in_j);
    set_key(key_in_j ,128);

    for (j = 0 ;j < 64 ;j+=32) {
    	do_fr(block_in ,&l_key[j]);
    }

    ar_round_added(block_in ,block_in_backup);    

    for ( ;j < 256 ;j+=32) {
        do_fr(block_in ,&l_key[j]);
    }

    ar_round_added(block_in ,l_key + 256);
    printf("output:\n");
    printf("sres:");
    for (i = 0 ;i < 4 ;i++) {
        printf("%x" ,block_in[i]);
    }
    printf("\n");

    printf("aco:");
    for (;i < 16 ;i++) {
        printf("%x" ,block_in[i]);
    }
    printf("\n");
    return 0;
}

int E3()
{
    int i ,j ;
    unsigned int key_in[4];
    unsigned int key_in_j[4];
    unsigned char block_in[16];
    unsigned char block_in_backup[16];
    unsigned char aco_in[16];

    aco_input(aco_in , "0x68f4f472b5586ac5850f5f74");
    key_input(key_in ,"0x34e86915d20c485090a6977931f96df5");
    block_input(block_in ,"0x950e604e655ea3800fe3eb4a28918087");

    set_key(key_in ,128);
    block_backup(block_in_backup ,block_in);

    for(j = 0 ;j < 256 ;j+=32) {
        do_fr(block_in ,&l_key[j]);
    }

    ar_round_added(block_in ,l_key + 256);

    for (i = 0 ;i < 16 ;i ++) {
        block_in[i] = block_in[i] ^ block_in_backup[i];
    }

    for (i = 0 ;i < 16 ;i ++) {
        block_in[i] = (0xff & (block_in[i] + aco_in[i]));
    }

    /* 2th round input(Ar`) */
    block_backup(block_in_backup ,block_in);
    get_key_j(l_key, key_in_j);
    set_key(key_in_j ,128);

    for (j = 0 ;j < 64 ;j+=32) {
        do_fr(block_in ,&l_key[j]);
    }

    ar_round_added(block_in ,block_in_backup);

    for ( ;j < 256 ;j+=32) {
        do_fr(block_in ,&l_key[j]);
    }

    ar_round_added(block_in ,l_key + 256);
    printf("Kc:\n");
    for (i = 0 ;i < 16 ;i++) {
        printf("%x" ,block_in[i]);
    }
    printf("\n");
    return 0;
}

int E21()
{
    int i ;
    unsigned int key_in[4];
    unsigned char block_in[16];
    unsigned char block_in_backup[16];
    unsigned char key_in_c[16];
    
    bdaddr_input(block_in ,"0x02f8fd4cd661");
    block_input(key_in_c ,"0xdab3cffe9d5739d1b7bf4a667ae5ee24");
    
    key_in_c[15] = key_in_c[15] ^ 6;
    key_c2key(key_in , key_in_c);

    /* 2th(Ar') round input */
    block_backup(block_in_backup ,block_in);
    set_key(key_in ,128);

    for (i = 0 ;i < 64 ;i+=32) {
        do_fr(block_in ,&l_key[i]);
    }

    ar_round_added(block_in ,block_in_backup);

    for ( ;i < 256 ;i+=32) {
        do_fr(block_in ,&l_key[i]);
    }

    ar_round_added(block_in ,l_key + 256);
    printf("Ka:\n");
    for (i = 0 ;i < 16 ;i++) {
        printf("%x" ,block_in[i]);
    }
    printf("\n");
    return 0;
}

int E22()
{
    int i ;
    unsigned int key_in[4];
    unsigned char block_in[16];
    unsigned char block_in_backup[16];
    unsigned char key_l;
/*
    block_input(block_in ,"0x001de169248850245a5f7cc7f0d6d633");
    key_input(key_in ,"0xd5a51083a04a1971f18649ea8b79311a");
*/
    block_input(block_in ,"0x67ed56bfcf99825f0c6b349369da30ab");
    key_input(key_in ,"0x7885b515e84b1f082cc499976f1725ce");
    key_l = 16;

    block_in[15] = block_in[15] ^ key_l;

    /* 2th(Ar') round input */
    block_backup(block_in_backup ,block_in);
    set_key(key_in ,128);

    for (i = 0 ;i < 64 ;i+=32) {
        do_fr(block_in ,&l_key[i]);
    }

    ar_round_added(block_in ,block_in_backup);

    for ( ;i < 256 ;i+=32) {
        do_fr(block_in ,&l_key[i]);
    }

    ar_round_added(block_in ,l_key + 256);
    printf("Ka:\n");
    for (i = 0 ;i < 16 ;i++) {
        printf("%x" ,block_in[i]);
    }
    printf("\n");
    return 0;
}

unsigned char aug_key_input(unsigned int key[4] , const unsigned char pin[] , const unsigned char bd_addr[])
{
    int i;
    unsigned char key_temp[34];
    unsigned char pin_len = strlen(pin);
    if (pin_len == 34) {
        key_input(key , pin);
    } else if ((pin_len < 34) && (pin_len > 22)) {
 	memcpy(key_temp ,pin ,pin_len);
        memcpy(key_temp+pin_len ,bd_addr + 2 ,34 - pin_len);
    	key_input(key , key_temp);
    } else {
        memcpy(key_temp ,pin ,pin_len);
        memcpy(key_temp + pin_len ,bd_addr + 2 ,12);
	memcpy(key_temp + pin_len + 12 ,pin + 2 ,22 - pin_len);
  	key_input(key , key_temp);
    }

    return (((pin_len-2)/2) > 10)?16:(((pin_len-2)/2) + 6);
}

int E22_AUG()
{
    int i;
    unsigned int key_in[4];
    unsigned char block_in[16];
    unsigned char block_in_backup[16];
    unsigned char key_l;

    block_input(block_in ,"0x272b73a2e40db52a6a61c6520549794a");
    key_l = aug_key_input(	key_in,
				"0x549f2694f353f5145772d8ae1e",
				"0x20487681eb9f");

    block_in[15] = block_in[15] ^ key_l;

    /* 2th(Ar') round input */
    block_backup(block_in_backup ,block_in);
    set_key(key_in ,128);
    printf("\n");
    for (i = 0 ;i < 64 ;i+=32) {
        do_fr(block_in ,&l_key[i]);
    }

    ar_round_added(block_in ,block_in_backup);

    for ( ;i < 256 ;i+=32) {
        do_fr(block_in ,&l_key[i]);
    }

    ar_round_added(block_in ,l_key + 256);
    printf("Ka:\n");
    for (i = 0 ;i < 16 ;i++) {
        printf("%x" ,block_in[i]);
    }
    printf("\n");
    return 0;
}

int main()
{
    E1();
    E3();
    E21();
    E22();
    E22_AUG();
    return 0;
}



