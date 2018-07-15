// LDombiMicroCipher1994_SFE.cpp : Defines the entry point for the console application.
//

#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#include "ErrorCodes.h"

#include "LDombiMicroCipher1994.hpp"



#define MAX_BUF_LEN 0x1000000
#define DEFAULT_Depth ldmc_DEPTH_DEF



ldmc_tByte Key[ldmc_KEY_LEN_MAX];

ldmc_tCipherContext CipherContext;



int TranslateCipherError(ldmc_tErrorCode ErrorCode);
int VisualizeReturnValue(int ReturnValue);
BOOL GetNumber(char sNumber[], uint64_t *pNumber);
const char *ParseDstFileParameter(const char *SrcName, const char *DstName, BOOL *pSrcFileIsDstFile);
BOOL ParseModeParameter(char sPar[], BOOL *pDeCrypt);
const char *ParseKeyParameter(char sPar[], BOOL *pKeyFile);
BOOL ParseDepthParameter(char sPar[], uint64_t *pDepth);
int LoadKey(BOOL KeyFile, const char KeyPar[], ldmc_tByte Key[], uint64_t *pKeyLen);



int main(int argc, char *argv[])
{
  int RetVal = ERROR_CODE_NO_ERROR;
  const char *SrcFileName = NULL, *DstFileName = NULL;
  BOOL SrcFileIsDstFile = FALSE;
  BOOL DeCrypt = FALSE;
  const char *KeyPar = NULL;
  BOOL KeyFile = FALSE;
  uint64_t KeyLen = 0;
  uint64_t Depth = DEFAULT_Depth;
  ldmc_pBlockProcessor pBlockProcessor;

  switch ( argc )
  {
    case 6:
      if ( !ParseDepthParameter(argv[5], &Depth) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
    case 5:
      if ( (KeyPar = ParseKeyParameter(argv[4], &KeyFile)) == NULL )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      if ( !ParseModeParameter(argv[3], &DeCrypt) )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      if ( (DstFileName = ParseDstFileParameter(SrcFileName = argv[1], argv[2], &SrcFileIsDstFile)) == NULL )
        RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      break;

    default:
      RetVal = ERROR_CODE_COMMAND_LINE_ERROR;
      break;
  }

  if ( RetVal == ERROR_CODE_NO_ERROR )
  {
    pBlockProcessor = DeCrypt ? ldmc_DeCryptBlock : ldmc_EnCryptBlock;
  }

  if ( RetVal == ERROR_CODE_NO_ERROR )
  {
    RetVal = LoadKey(KeyFile, KeyPar, Key, &KeyLen);
  }

  if ( RetVal == ERROR_CODE_NO_ERROR )
  {
    ldmc_tErrorCode ChiperErrorCode;
    if ( (ChiperErrorCode = ldmc_InitCipherContext(&CipherContext, Key, (unsigned int)KeyLen, (unsigned int)Depth)) == ldmc_ErrorCode_NoError )
    {
      HANDLE InputFileHandle;
      if ( (InputFileHandle = CreateFile(SrcFileName, GENERIC_READ, FILE_SHARE_READ | ((SrcFileIsDstFile) ? FILE_SHARE_WRITE : 0), NULL, OPEN_EXISTING, 0, INVALID_HANDLE_VALUE)) != INVALID_HANDLE_VALUE )
      {
        uint64_t InputFileSize;
        if ( GetFileSizeEx(InputFileHandle, (PLARGE_INTEGER)&InputFileSize) )
        {
          HANDLE OutputFileHandle;
          if ( (OutputFileHandle = CreateFile(DstFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, ((SrcFileIsDstFile) ? OPEN_ALWAYS : CREATE_ALWAYS), FILE_ATTRIBUTE_ARCHIVE, INVALID_HANDLE_VALUE)) != INVALID_HANDLE_VALUE )
          {
            if ( InputFileSize )
            {
              HGLOBAL MemoryHandle;
              if ( (MemoryHandle = GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, ((InputFileSize > MAX_BUF_LEN) ? MAX_BUF_LEN : (DWORD)InputFileSize) )) != NULL )
              {
                do
                {
                  DWORD ToProcess = ((InputFileSize > MAX_BUF_LEN) ? MAX_BUF_LEN : (DWORD)InputFileSize);
                  DWORD ReadSize;
                  if ( ReadFile(InputFileHandle, MemoryHandle, ToProcess, &ReadSize, NULL) )
                  {
                    if ( ReadSize == ToProcess )
                    {
                      if ( (ChiperErrorCode = pBlockProcessor(&CipherContext, ldmc_IN_PLACE( MemoryHandle ), ToProcess)) == ldmc_ErrorCode_NoError )
                      {
                        DWORD WriteSize;
                        if ( WriteFile(OutputFileHandle, MemoryHandle, ToProcess, &WriteSize, NULL) )
                        {
                          if ( WriteSize != ToProcess )
                          {
                            RetVal = ERROR_CODE_FILE_WRITE_ERROR;
                            break;
                          }
                        }
                        else
                        {
                          RetVal = ERROR_CODE_FILE_WRITE_ERROR;
                          break;
                        }
                      }
                      else
                      {
                        RetVal = TranslateCipherError(ChiperErrorCode);
                        break;
                      }
                    }
                    else
                    {
                      RetVal = ERROR_CODE_FILE_READ_ERROR;
                      break;
                    }
                  }
                  else
                  {
                    RetVal = ERROR_CODE_FILE_READ_ERROR;
                    break;
                  }
                  InputFileSize -= ToProcess;
                } while ( InputFileSize );
                GlobalFree(MemoryHandle);
              }
              else
              {
                RetVal = ERROR_CODE_MEMORY_ALLOCATION_ERROR;
              }
            }
            CloseHandle(OutputFileHandle);
          }
          else
          {
            RetVal = ERROR_CODE_DST_FILE_OPEN_ERROR;
          }
        }
        else
        {
          RetVal = ERROR_CODE_GETFILESIZEEX_ERROR;
        }
        CloseHandle(InputFileHandle);
      }
      else
      {
        RetVal = ERROR_CODE_SRC_FILE_OPEN_ERROR;
      }
    }
    else
    {
      RetVal = TranslateCipherError(ChiperErrorCode);
    }
  }

  return VisualizeReturnValue( RetVal );
}



int TranslateCipherError(ldmc_tErrorCode ErrorCode)
{
  int RetVal = ERROR_CODE_CIPHER_UNKNOWN_ERROR;
  switch ( ErrorCode )
  {
    case ldmc_ErrorCode_ldmc_tByte_SizeNot1:
      RetVal = ERROR_CODE_CIPHER_TBYTE_SIZE_NOT_1_ERROR;
      break;

    case ldmc_ErrorCode_ldmc_tDial_TooShort:
      RetVal = ERROR_CODE_CIPHER_TDIAL_TOO_SHORT_ERROR;
      break;

    case ldmc_ErrorCode_BlockProcessorIsNULL:
      RetVal = ERROR_CODE_CIPHER_BLOCK_PROCESSOR_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_ContextIsNULL:
      RetVal = ERROR_CODE_CIPHER_CONTEXT_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_KeyBufIsNULL:
      RetVal = ERROR_CODE_CIPHER_KEY_BUF_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_WrongKeyLen:
      RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
      break;

    case ldmc_ErrorCode_WrongDepth:
      RetVal = ERROR_CODE_CIPHER_WRONG_DEPTH_ERROR;
      break;

    case ldmc_ErrorCode_SrcIsNULL:
      RetVal = ERROR_CODE_CIPHER_SRC_IS_NULL_ERROR;
      break;

    case ldmc_ErrorCode_DstIsNULL:
      RetVal = ERROR_CODE_CIPHER_DST_IS_NULL_ERROR;
      break;
  }

  return RetVal;
}



int VisualizeReturnValue(int ReturnValue)
{
  switch ( ReturnValue )
  {
    case ERROR_CODE_COMMAND_LINE_ERROR:
      {
        char PathAndFileName[MAX_PATH], *FileName;

        FileName = PathAndFileName + GetModuleFileName(NULL, PathAndFileName, sizeof(PathAndFileName));
        while( FileName > PathAndFileName )
        {
          if( FileName[-1] == '\\' ) break;
          FileName--;
        }

        printf("Command line error!\n");
        printf("Usage:\n");
        printf("\n");
        printf("  %s InputFileName OutputFileName|* Mode Key [Depth]\n", FileName);
        printf("    Mode:\n");
        printf("      e - Encryption mode\n");
        printf("      d - Decryption mode\n");
        printf("    Key:\n");
        printf("      p:PassPhrase  - Primary PassPhrase for encryption/decryption\n");
        printf("      f:KeyFileName - Primary KeyFileName for encryption/decryption\n");
        printf("      KeyLen: %u ... %u\n", ldmc_KEY_LEN_MIN, ldmc_KEY_LEN_MAX);
        printf("    Depth:\n");
        printf("      %u ... %u - Primary Depth for encryption/decryption\n", ldmc_DEPTH_MIN, ldmc_DEPTH_MAX);
        printf("      default: %u\n", DEFAULT_Depth);
        printf("    * means: OutputFileName = InputFileName\n");
        printf("\n");
        printf("  Numbers:\n");
        printf("    10  is Decimal     and is Ten\n");
        printf("    10b is Binary      and is Two\n");
        printf("    10o is Octal       and is Eight\n");
        printf("    10d is Decimal     and is Ten\n");
        printf("    10h is HexaDecimal and is SixTeen\n");
        printf("\n");
      }
      break;

    case ERROR_CODE_NO_ERROR:
      printf("Success!\n");
      break;

    case ERROR_CODE_KEY_FILE_OPEN_ERROR:
      printf("KeyFile open error!\n");
      break;

    case ERROR_CODE_SRC_FILE_OPEN_ERROR:
      printf("InputFile open error!\n");
      break;

    case ERROR_CODE_DST_FILE_OPEN_ERROR:
      printf("OutputFile open error!\n");
      break;

    case ERROR_CODE_GETFILESIZEEX_ERROR:
      printf("GetFileSizeEx error!\n");
      break;

    case ERROR_CODE_MEMORY_ALLOCATION_ERROR:
      printf("Memory allocation error!\n");
      break;

    case ERROR_CODE_FILE_READ_ERROR:
      printf("File read error!\n");
      break;

    case ERROR_CODE_FILE_WRITE_ERROR:
      printf("File write error!\n");
      break;

    case ERROR_CODE_CIPHER_UNKNOWN_ERROR:
      printf("Cipher Error: Unknown error!\n");
      break;

    case ERROR_CODE_CIPHER_TBYTE_SIZE_NOT_1_ERROR:
      printf("Cipher Error: tByte is not 1 byte error!\n");
      break;

    case ERROR_CODE_CIPHER_TDIAL_TOO_SHORT_ERROR:
      printf("Cipher Error: tDial is too short error!\n");
      break;

    case ERROR_CODE_CIPHER_BLOCK_PROCESSOR_IS_NULL_ERROR:
      printf("Cipher Error: BlockProcessor is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_CONTEXT_IS_NULL_ERROR:
      printf("Cipher Error: Context is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_KEY_BUF_IS_NULL_ERROR:
      printf("Cipher Error: KeyBuf is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR:
      printf("Cipher Error: Wrong KeyLen error!\n");
      break;

    case ERROR_CODE_CIPHER_WRONG_DEPTH_ERROR:
      printf("Cipher Error: Wrong Depth error!\n");
      break;

    case ERROR_CODE_CIPHER_SRC_IS_NULL_ERROR:
      printf("Cipher Error: Src is NULL error!\n");
      break;

    case ERROR_CODE_CIPHER_DST_IS_NULL_ERROR:
      printf("Cipher Error: Dst is NULL error!\n");
      break;

    default:
      printf("Unknown Error Occured!\n");
      break;
  }

  return ReturnValue;
}



BOOL GetNumber(char sNumber[], uint64_t *pNumber)
{
  uint64_t Num = 0, MulLim;
  DWORD NumSys = 10, d, i, l = 0;
  unsigned char c;

  while ( sNumber[l] ) l++;
  if ( !l ) return FALSE;

  l--;
  switch ( sNumber[l] | 0x20 )
  {
    case 'b':
      NumSys = 0x02;
      break;
    case 'o':
      NumSys = 0x08;
      break;
    case 'd':
      NumSys = 0x0A;
      break;
    case 'h':
      NumSys = 0x10;
      break;
    default:
      l++;
      break;
  }
  if ( !l ) return FALSE;
  MulLim = 0xFFFFFFFFFFFFFFFFULL / NumSys;

  for ( i = 0; i < l; i++ )
  {
    c = sNumber[i];
    if ( (c >= '0') && (c <= '9') )
      d = c - '0';
    else
    {
      c |= 0x20;
      if ( (c >= 'a') && (c <= 'f') )
        d = c - 'a' + 0xA;
      else
        return FALSE;
    }
    if ( d >= NumSys ) return FALSE;
    if ( Num > MulLim) return FALSE;
    Num *= NumSys;
    if ( d > 0xFFFFFFFFFFFFFFFFULL - Num) return FALSE;
    Num += d;
  }

  *pNumber = Num;
  return TRUE;
}



const char *ParseDstFileParameter(const char *SrcName, const char *DstName, BOOL *pSrcFileIsDstFile)
{
  if ( DstName[0] == '*' )
  {
    *pSrcFileIsDstFile = TRUE;
    return ( DstName[1] ) ? NULL : SrcName; 
  }

  return DstName;
}



BOOL ParseModeParameter(char sPar[], BOOL *pDeCrypt)
{
  BOOL DeCrypt = FALSE;

  switch ( sPar[0] | 0x20 )
  {
    case 'd':
      DeCrypt = TRUE;
    case 'e':
      break;
    default:
      return FALSE;
  }
  if ( sPar[1] ) return FALSE;

  *pDeCrypt = DeCrypt;

  return TRUE;
}



const char *ParseKeyParameter(char sPar[], BOOL *pKeyFile)
{
  BOOL KeyFile = FALSE;

  switch ( sPar[0] | 0x20 )
  {
    case 'f':
      KeyFile = TRUE;
    case 'p':
      break;
    default:
      return NULL;
  }
  if ( sPar[1] != ':' ) return NULL;

  *pKeyFile = KeyFile;

  return sPar + 2;
}



BOOL ParseDepthParameter(char sPar[], uint64_t *pDepth)
{
  uint64_t Depth;

  if ( !GetNumber(sPar, &Depth) ) return FALSE;
  if (( Depth < ldmc_DEPTH_MIN ) || ( Depth > ldmc_DEPTH_MAX )) return FALSE;

  *pDepth = Depth;

  return TRUE;
}



int LoadKey(BOOL KeyFile, const char KeyPar[], ldmc_tByte Key[], uint64_t *pKeyLen)
{
  int RetVal = ERROR_CODE_NO_ERROR;
  uint64_t KeyLen = 0;

  if ( KeyFile )
  {
    HANDLE KeyFileHandle;
    if ( (KeyFileHandle = CreateFile(KeyPar, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, INVALID_HANDLE_VALUE)) != INVALID_HANDLE_VALUE )
    {
      if ( GetFileSizeEx(KeyFileHandle, (PLARGE_INTEGER)&KeyLen) )
      {
        if (( KeyLen >= ldmc_KEY_LEN_MIN ) && ( KeyLen <= ldmc_KEY_LEN_MAX ))
        {
          DWORD ReadSize;
          if ( ReadFile(KeyFileHandle, Key, (DWORD)KeyLen, &ReadSize, NULL) )
          {
            if ( ReadSize != KeyLen )
            {
              RetVal = ERROR_CODE_FILE_READ_ERROR;
            }
          }
          else
          {
            RetVal = ERROR_CODE_FILE_READ_ERROR;
          }
        }
        else
        {
          RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
        }
      }
      else
      {
        RetVal = ERROR_CODE_GETFILESIZEEX_ERROR;
      }
      CloseHandle(KeyFileHandle);
    }
    else
    {
      RetVal = ERROR_CODE_KEY_FILE_OPEN_ERROR;
    }
  }
  else
  {
    while ( KeyPar[KeyLen] )
    {
      if ( KeyLen < ldmc_KEY_LEN_MAX )
      {
        Key[KeyLen] = KeyPar[KeyLen];
        KeyLen++;
      }
      else
      {
        RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
        break;
      }
    }
    if ( KeyLen < ldmc_KEY_LEN_MIN ) RetVal = ERROR_CODE_CIPHER_WRONG_KEY_LEN_ERROR;
  }

  if ( RetVal == ERROR_CODE_NO_ERROR ) *pKeyLen = KeyLen;

  return RetVal;
}



