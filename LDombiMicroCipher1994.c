#include "LDombiMicroCipher1994.h"



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_EnCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_EnCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_EnCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_EnCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
static ldmc_tByte ldmc_EnCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input);

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_DeCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_DeCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_DeCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input);
static ldmc_tByte ldmc_DeCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input);
#endif
static ldmc_tByte ldmc_DeCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input);

#endif



static ldmc_tErrorCode ldmc_CheckConfig(void)
{
  unsigned int i, t = ((unsigned int)ldmc_KEY_LEN_MAX) - 1;

  if( sizeof(ldmc_tByte) != 1 ) return ldmc_ErrorCode_ldmc_tByte_SizeNot1;
  for( i = 0; i < sizeof(ldmc_tDial); i++ ) t >>= 8;
  if( t ) return ldmc_ErrorCode_ldmc_tDial_TooShort;

  return ldmc_ErrorCode_NoError;
}



static ldmc_tErrorCode ldmc_CachingCheckConfig(void)
{
  static ldmc_tErrorCode RetVal = ldmc_ErrorCode_NoError;
  static enum { No, Yes } Checked = No;

  if( Checked != Yes )
  {
    RetVal = ldmc_CheckConfig();
    Checked = Yes;
  }

  return RetVal;
}



ldmc_tErrorCode ldmc_InitCipherContext(ldmc_pCipherContext pContext, ldmc_tByte KeyBuf[], unsigned int KeyLen, unsigned int Depth)
{
  ldmc_tErrorCode ErrorCode = ldmc_CachingCheckConfig();
  register unsigned int i;
  register ldmc_pByte Key;
  register ldmc_pDial Dials;
  register ldmc_tByte Mask = 0;

  if( ErrorCode != ldmc_ErrorCode_NoError ) return ErrorCode;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !KeyBuf ) return ldmc_ErrorCode_KeyBufIsNULL;
  if(( KeyLen < ldmc_KEY_LEN_MIN ) || ( KeyLen > ldmc_KEY_LEN_MAX )) return ldmc_ErrorCode_WrongKeyLen;
  if(( Depth < ldmc_DEPTH_MIN ) || ( Depth > ldmc_DEPTH_MAX )) return ldmc_ErrorCode_WrongDepth;

  Key   = pContext->Key  ;
  Dials = pContext->Dials;

  for( i = 0; i < KeyLen; i++ )
  {
    Mask += (ldmc_tByte)(((i + 1) * (unsigned int)(Key[i] = KeyBuf[i])) & 0xFFU);
  }

  for( i = 0; i < Depth; i++ )
  {
    Dials[i] = 0;
  }

  pContext->KeyLen = KeyLen;
  pContext->Depth  = Depth ;

  pContext->Mask = pContext->Back = Mask;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  switch( Depth )
  {
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
    case 8:
      pContext->pEnCryptByte = ldmc_EnCryptByte8;
      pContext->pDeCryptByte = ldmc_DeCryptByte8;
      break;
    case 7:
      pContext->pEnCryptByte = ldmc_EnCryptByte7;
      pContext->pDeCryptByte = ldmc_DeCryptByte7;
      break;
    case 6:
      pContext->pEnCryptByte = ldmc_EnCryptByte6;
      pContext->pDeCryptByte = ldmc_DeCryptByte6;
      break;
    case 5:
      pContext->pEnCryptByte = ldmc_EnCryptByte5;
      pContext->pDeCryptByte = ldmc_DeCryptByte5;
      break;
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
    case 4:
      pContext->pEnCryptByte = ldmc_EnCryptByte4;
      pContext->pDeCryptByte = ldmc_DeCryptByte4;
      break;
    case 3:
      pContext->pEnCryptByte = ldmc_EnCryptByte3;
      pContext->pDeCryptByte = ldmc_DeCryptByte3;
      break;
#endif
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
    case 2:
      pContext->pEnCryptByte = ldmc_EnCryptByte2;
      pContext->pDeCryptByte = ldmc_DeCryptByte2;
      break;
    case 1:
      pContext->pEnCryptByte = ldmc_EnCryptByte1;
      pContext->pDeCryptByte = ldmc_DeCryptByte1;
      break;
#endif
    default:
      pContext->pEnCryptByte = ldmc_EnCryptByte ;
      pContext->pDeCryptByte = ldmc_DeCryptByte ;
      break;
  }
#endif

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_ReSetContextForNewBlockChain(ldmc_pCipherContext pContext)
{
  register unsigned int i;
  register ldmc_pDial Dials;
  register unsigned int Depth;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;

  Dials  = pContext->Dials ;
  Depth  = pContext->Depth ;
  for( i = 0; i < Depth; i++ )
  {
    Dials[i] = 0;
  }

  pContext->Mask = pContext->Back;

  return ldmc_ErrorCode_NoError;
}



#define ldmc_ScrambleTheInternalStates( PreFixM, PByte, CByte ) \
  PreFixM##Mask = Mask + PByte;                                 \



#define ldmc_RotateTheDialsCore( D )                         \
    {                                                        \
      register ldmc_tDial Dial;                              \
      register unsigned int KeyLen_1 = pContext->KeyLen - 1; \
                                                             \
      for( i = 0; i < D; i++ )                               \
      {                                                      \
        if( (Dial = Dials[i]) < KeyLen_1 )                   \
        {                                                    \
          Dials[i] = Dial + 1;                               \
          break;                                             \
        }                                                    \
        Dials[i] = 0;                                        \
      }                                                      \
    }                                                        \

#define ldmc_RotateTheDialsCoreI( D )                        \
  {                                                          \
    register unsigned int i;                                 \
                                                             \
    ldmc_RotateTheDialsCore( D )                             \
  }                                                          \



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) <= 0 )
static void ldmc_RotateTheDials(ldmc_pCipherContext pContext)
{
  register ldmc_pDial   Dials = pContext->Dials;
  register unsigned int Depth = pContext->Depth;

  ldmc_RotateTheDialsCoreI( Depth )
}
#endif



#define ldmc_EnCryptByteCore( I ) \
    Coder = Key[Dials[I]];        \
    Work =  ~Work        ;        \
    Work += Coder        ;        \
    Work ^= Coder &  Mask;        \
    Work -= Coder        ;        \
    Work ^= Coder & ~Mask;        \



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_EnCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 7 )
  ldmc_EnCryptByteCore( 6 )
  ldmc_EnCryptByteCore( 5 )
  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 8 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 6 )
  ldmc_EnCryptByteCore( 5 )
  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 7 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 5 )
  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 6 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 4 )
  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 5 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_EnCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 3 )
  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 4 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 2 )
  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 3 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_EnCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 1 )
  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 2 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_EnCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_EnCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 1 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



static ldmc_tByte ldmc_EnCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte   Coder;
  register ldmc_tByte   Work  = Input;
  register ldmc_pByte   Key   = pContext->Key  ;
  register ldmc_pDial   Dials = pContext->Dials;
  register unsigned int Depth = pContext->Depth;
  register ldmc_tByte   Mask  = pContext->Mask ;
  register unsigned int c = Depth, i = Depth;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
  while( c >= 8 )
  {
    ldmc_EnCryptByteCore( i - 1 )
    ldmc_EnCryptByteCore( i - 2 )
    ldmc_EnCryptByteCore( i - 3 )
    ldmc_EnCryptByteCore( i - 4 )
    ldmc_EnCryptByteCore( i - 5 )
    ldmc_EnCryptByteCore( i - 6 )
    ldmc_EnCryptByteCore( i - 7 )
    ldmc_EnCryptByteCore( i - 8 )
    i -= 8;
    c -= 8;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  2 )
  if   
#else
  while
#endif
       ( c >= 4 )
  {
    ldmc_EnCryptByteCore( i - 1 )
    ldmc_EnCryptByteCore( i - 2 )
    ldmc_EnCryptByteCore( i - 3 )
    ldmc_EnCryptByteCore( i - 4 )
    i -= 4;
    c -= 4;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  1 )
  if   
#else
  while
#endif
       ( c >= 2 )
  {
    ldmc_EnCryptByteCore( i - 1 )
    ldmc_EnCryptByteCore( i - 2 )
    i -= 2;
    c -= 2;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  if   ( c )
  {
    ldmc_EnCryptByteCore( i - 1 )
  }
#else
  while( c )
  {
    ldmc_EnCryptByteCore( --i )
    c--;
  }
#endif

  ldmc_ScrambleTheInternalStates( pContext->, Input, Work  )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCore( Depth )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



#define ldmc_DeCryptByteCore( I ) \
    Coder = Key[Dials[I]];        \
    Work ^= Coder & ~Mask;        \
    Work += Coder        ;        \
    Work ^= Coder &  Mask;        \
    Work -= Coder        ;        \
    Work =  ~Work        ;        \



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
static ldmc_tByte ldmc_DeCryptByte8(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )
  ldmc_DeCryptByteCore( 5 )
  ldmc_DeCryptByteCore( 6 )
  ldmc_DeCryptByteCore( 7 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 8 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte7(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )
  ldmc_DeCryptByteCore( 5 )
  ldmc_DeCryptByteCore( 6 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 7 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte6(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )
  ldmc_DeCryptByteCore( 5 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 6 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte5(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )
  ldmc_DeCryptByteCore( 4 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 5 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
static ldmc_tByte ldmc_DeCryptByte4(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )
  ldmc_DeCryptByteCore( 3 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 4 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte3(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )
  ldmc_DeCryptByteCore( 2 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 3 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
static ldmc_tByte ldmc_DeCryptByte2(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )
  ldmc_DeCryptByteCore( 1 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 2 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



static ldmc_tByte ldmc_DeCryptByte1(ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte Coder;
  register ldmc_tByte Work  = Input;
  register ldmc_pByte Key   = pContext->Key  ;
  register ldmc_pDial Dials = pContext->Dials;
  register ldmc_tByte Mask  = pContext->Mask ;

  ldmc_DeCryptByteCore( 0 )

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCoreI( 1 )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}
#endif



static ldmc_tByte ldmc_DeCryptByte (ldmc_pCipherContext pContext, ldmc_tByte Input)
{
  register ldmc_tByte   Coder;
  register ldmc_tByte   Work  = Input;
  register ldmc_pByte   Key   = pContext->Key  ;
  register ldmc_pDial   Dials = pContext->Dials;
  register unsigned int Depth = pContext->Depth;
  register ldmc_tByte   Mask  = pContext->Mask ;
  register unsigned int c = Depth, i = 0;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 3 )
  while( c >= 8 )
  {
    ldmc_DeCryptByteCore( i + 0 )
    ldmc_DeCryptByteCore( i + 1 )
    ldmc_DeCryptByteCore( i + 2 )
    ldmc_DeCryptByteCore( i + 3 )
    ldmc_DeCryptByteCore( i + 4 )
    ldmc_DeCryptByteCore( i + 5 )
    ldmc_DeCryptByteCore( i + 6 )
    ldmc_DeCryptByteCore( i + 7 )
    i += 8;
    c -= 8;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 2 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  2 )
  if   
#else
  while
#endif
       ( c >= 4 )
  {
    ldmc_DeCryptByteCore( i + 0 )
    ldmc_DeCryptByteCore( i + 1 )
    ldmc_DeCryptByteCore( i + 2 )
    ldmc_DeCryptByteCore( i + 3 )
    i += 4;
    c -= 4;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >= 1 )
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  1 )
  if   
#else
  while
#endif
       ( c >= 2 )
  {
    ldmc_DeCryptByteCore( i + 0 )
    ldmc_DeCryptByteCore( i + 1 )
    i += 2;
    c -= 2;
  }
#endif

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  if   ( c )
  {
    ldmc_DeCryptByteCore( i + 0 )
  }
#else
  while( c )
  {
    ldmc_DeCryptByteCore( i++ )
    c--;
  }
#endif

  ldmc_ScrambleTheInternalStates( pContext->, Work , Input )

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_RotateTheDialsCore( Depth )
#else
  ldmc_RotateTheDials(pContext);
#endif

  return Work;
}



ldmc_tErrorCode ldmc_EnCryptBlock(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pEnCryptByte;
  #define EnCryptByte (*pEnCryptByte)
#else
  #define EnCryptByte ldmc_EnCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pEnCryptByte = pContext->pEnCryptByte;
#endif

  for( i = 0; i < rSize; i++ )
  {
    *(pcDst++) = EnCryptByte(pContext, *(pcSrc++));
  }

  return ldmc_ErrorCode_NoError;
  #undef EnCryptByte
}



ldmc_tErrorCode ldmc_DeCryptBlock(ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  ldmc_pByteProcessor pDeCryptByte;
  #define DeCryptByte (*pDeCryptByte)
#else
  #define DeCryptByte ldmc_DeCryptByte
#endif
  register unsigned int i, rSize = Size;
  register ldmc_pByte pcSrc = (ldmc_pByte)pSrc;
  register ldmc_pByte pcDst = (ldmc_pByte)pDst;

  if( !pContext ) return ldmc_ErrorCode_ContextIsNULL;
  if( !pcSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pcDst ) return ldmc_ErrorCode_DstIsNULL;

#if ( (ldmc_BYTE_CIPHER_OPTIMIZATION_LEVEL) >  0 )
  pDeCryptByte = pContext->pDeCryptByte;
#endif

  for( i = 0; i < rSize; i++ )
  {
    *(pcDst++) = DeCryptByte(pContext, *(pcSrc++));
  }

  return ldmc_ErrorCode_NoError;
  #undef DeCryptByte
}



ldmc_tErrorCode ldmc_ReSetContextForNewBlockChainAndCall(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pBlockProcessor ) return ldmc_ErrorCode_BlockProcessorIsNULL;

  if( !pSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pDst ) return ldmc_ErrorCode_DstIsNULL;

  if( (ErrorCode = ldmc_ReSetContextForNewBlockChain(pContext)                  ) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode =                (*pBlockProcessor)(pContext, pSrc, pDst, Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



ldmc_tErrorCode ldmc_CallAndReSetContextForNewBlockChain(ldmc_pBlockProcessor pBlockProcessor, ldmc_pCipherContext pContext, void *pSrc, void *pDst, unsigned int Size)
{
  ldmc_tErrorCode ErrorCode;

  if( !pBlockProcessor ) return ldmc_ErrorCode_BlockProcessorIsNULL;

  if( !pSrc ) return ldmc_ErrorCode_SrcIsNULL;
  if( !pDst ) return ldmc_ErrorCode_DstIsNULL;

  if( (ErrorCode =                (*pBlockProcessor)(pContext, pSrc, pDst, Size)) != ldmc_ErrorCode_NoError ) return ErrorCode;
  if( (ErrorCode = ldmc_ReSetContextForNewBlockChain(pContext                  )) != ldmc_ErrorCode_NoError ) return ErrorCode;

  return ldmc_ErrorCode_NoError;
}



