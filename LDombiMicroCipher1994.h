#ifndef __LDOMBIMICROCIPHER1994_H
#define __LDOMBIMICROCIPHER1994_H



#include "LDombiMicroCipher1994_Config.h"



#define ldmc_KEY_LEN_MAX ldmc_KEY_BUF_LEN
#define ldmc_KEY_LEN_MIN 2

#define ldmc_DEPTH_MAX ldmc_DIAL_BUF_LEN
#define ldmc_DEPTH_MIN 1



#if (ldmc_KEY_BUF_LEN < ldmc_KEY_LEN_MIN)
#error Wrong Config: ldmc_KEY_BUF_LEN < ldmc_KEY_LEN_MIN
#endif

#if (ldmc_DIAL_BUF_LEN < ldmc_DEPTH_MIN)
#error Wrong Config: ldmc_DIAL_BUF_LEN < ldmc_DEPTH_MIN
#endif

#if (ldmc_DEPTH_DEF < ldmc_DEPTH_MIN)
#error Wrong Config: ldmc_DEPTH_DEF < ldmc_DEPTH_MIN
#endif

#if (ldmc_DEPTH_DEF > ldmc_DEPTH_MAX)
#error Wrong Config: ldmc_DEPTH_DEF > ldmc_DEPTH_MAX
#endif



#define ldmc_IN_PLACE( pBuf ) pBuf, pBuf

#define ldmc_DEFAULT_ARGUMENTS_Depth ldmc_DEPTH_DEF



typedef ldmc_EXTERNAL_TYPE_tByte ldmc_tByte, *ldmc_pByte;
typedef ldmc_EXTERNAL_TYPE_tDial ldmc_tDial, *ldmc_pDial;



typedef struct ldmc_sCipherContext ldmc_tCipherContext, *ldmc_pCipherContext;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
typedef ldmc_tByte ldmc_tByteProcessor(ldmc_pCipherContext pContext, ldmc_tByte Input);
typedef ldmc_tByteProcessor *ldmc_pByteProcessor;
#endif



struct ldmc_sCipherContext
{

  ldmc_tByte Key[ldmc_KEY_BUF_LEN];
  ldmc_tDial Dials[ldmc_DIAL_BUF_LEN];
  unsigned int KeyLen;
  unsigned int Depth;
  ldmc_tByte Back;
  ldmc_tByte Mask;
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pEnCryptByte, pDeCryptByte;
#endif

};



typedef enum ldmc_eErrorCode
{

  ldmc_ErrorCode_NoError            = 0,
  ldmc_ErrorCode_ldmc_tByte_SizeNot1   ,
  ldmc_ErrorCode_ldmc_tDial_TooShort   ,
  ldmc_ErrorCode_BlockProcessorIsNULL  ,
  ldmc_ErrorCode_ContextIsNULL         ,
  ldmc_ErrorCode_KeyBufIsNULL          ,
  ldmc_ErrorCode_WrongKeyLen           ,
  ldmc_ErrorCode_WrongDepth            ,
  ldmc_ErrorCode_SrcIsNULL             ,
  ldmc_ErrorCode_DstIsNULL             

} ldmc_tErrorCode, *ldmc_pErrorCode;



typedef ldmc_tErrorCode ldmc_tBlockProcessor(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
typedef ldmc_tBlockProcessor *ldmc_pBlockProcessor;



ldmc_tErrorCode ldmc_InitCipherContext(ldmc_pCipherContext pContext, ldmc_tByte KeyBuf[], unsigned int KeyLen, unsigned int Depth);

ldmc_tErrorCode ldmc_ReSetContextForNewBlockChain(ldmc_pCipherContext pContext);

ldmc_tErrorCode ldmc_EnCryptBlock(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_DeCryptBlock(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);

ldmc_tErrorCode ldmc_ReSetContextForNewBlockChainAndCall(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);
ldmc_tErrorCode ldmc_CallAndReSetContextForNewBlockChain(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size);



#endif /* __LDOMBIMICROCIPHER1994_H */
