#ifndef __LDOMBIMICROCIPHER1994_CONFIG_H
#define __LDOMBIMICROCIPHER1994_CONFIG_H



#ifndef ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL
#define ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL 0
#endif /* Optimization for Speed, generates larger code. Values: 0, 1, 2, 3 */



#ifndef ldmc_EXTERNAL_TYPE_tByte
#define ldmc_EXTERNAL_TYPE_tByte unsigned char
#endif

#ifndef ldmc_EXTERNAL_TYPE_tDial
#define ldmc_EXTERNAL_TYPE_tDial unsigned short
#endif



#ifndef ldmc_KEY_BUF_LEN
#define ldmc_KEY_BUF_LEN 0x400
#endif /* Maximizes the KeyLen */

#ifndef ldmc_DIAL_BUF_LEN
#define ldmc_DIAL_BUF_LEN 0x200
#endif /* Maximizes the Depth */



#ifndef ldmc_DEPTH_DEF
#define ldmc_DEPTH_DEF 5
#endif



#endif /* __LDOMBIMICROCIPHER1994_CONFIG_H */
