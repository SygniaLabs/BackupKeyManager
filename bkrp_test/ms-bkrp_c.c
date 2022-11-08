

/* this ALWAYS GENERATED file contains the RPC client stubs */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 11:14:07 2038
 */
/* Compiler settings for ms-bkrp.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0622 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#if defined(_M_AMD64)


#pragma warning( disable: 4049 )  /* more than 64k source lines */
#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning( disable: 4211 )  /* redefine extern to static */
#pragma warning( disable: 4232 )  /* dllimport identity*/
#pragma warning( disable: 4024 )  /* array to pointer mapping*/

#include <string.h>

#include "ms-bkrp.h"

#define TYPE_FORMAT_STRING_SIZE   65                                
#define PROC_FORMAT_STRING_SIZE   73                                
#define EXPR_FORMAT_STRING_SIZE   1                                 
#define TRANSMIT_AS_TABLE_SIZE    0            
#define WIRE_MARSHAL_TABLE_SIZE   0            

typedef struct _ms2Dbkrp_MIDL_TYPE_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ TYPE_FORMAT_STRING_SIZE ];
    } ms2Dbkrp_MIDL_TYPE_FORMAT_STRING;

typedef struct _ms2Dbkrp_MIDL_PROC_FORMAT_STRING
    {
    short          Pad;
    unsigned char  Format[ PROC_FORMAT_STRING_SIZE ];
    } ms2Dbkrp_MIDL_PROC_FORMAT_STRING;

typedef struct _ms2Dbkrp_MIDL_EXPR_FORMAT_STRING
    {
    long          Pad;
    unsigned char  Format[ EXPR_FORMAT_STRING_SIZE ];
    } ms2Dbkrp_MIDL_EXPR_FORMAT_STRING;


static const RPC_SYNTAX_IDENTIFIER  _RpcTransferSyntax = 
{{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}};


extern const ms2Dbkrp_MIDL_TYPE_FORMAT_STRING ms2Dbkrp__MIDL_TypeFormatString;
extern const ms2Dbkrp_MIDL_PROC_FORMAT_STRING ms2Dbkrp__MIDL_ProcFormatString;
extern const ms2Dbkrp_MIDL_EXPR_FORMAT_STRING ms2Dbkrp__MIDL_ExprFormatString;

#define GENERIC_BINDING_TABLE_SIZE   0            


/* Standard interface: BackupKey, ver. 1.0,
   GUID={0x3dde7c30,0x165d,0x11d1,{0xab,0x8f,0x00,0x80,0x5f,0x14,0xdb,0x40}} */



static const RPC_CLIENT_INTERFACE BackupKey___RpcClientInterface =
    {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x3dde7c30,0x165d,0x11d1,{0xab,0x8f,0x00,0x80,0x5f,0x14,0xdb,0x40}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,
    0,
    0,
    0,
    0,
    0x00000000
    };
RPC_IF_HANDLE BackupKey_v1_0_c_ifspec = (RPC_IF_HANDLE)& BackupKey___RpcClientInterface;

extern const MIDL_STUB_DESC BackupKey_StubDesc;

static RPC_BINDING_HANDLE BackupKey__MIDL_AutoBindHandle;


/* [code] */ NET_API_STATUS BackuprKey( 
    /* [in] */ handle_t h,
    /* [in] */ GUID *pguidActionAgent,
    /* [size_is][in] */ byte *pDataIn,
    /* [in] */ DWORD cbDataIn,
    /* [size_is][size_is][out] */ byte **ppDataOut,
    /* [out] */ DWORD *pcbDataOut,
    /* [in] */ DWORD dwParam)
{

    CLIENT_CALL_RETURN _RetVal;

    _RetVal = NdrClientCall2(
                  ( PMIDL_STUB_DESC  )&BackupKey_StubDesc,
                  (PFORMAT_STRING) &ms2Dbkrp__MIDL_ProcFormatString.Format[0],
                  h,
                  pguidActionAgent,
                  pDataIn,
                  cbDataIn,
                  ppDataOut,
                  pcbDataOut,
                  dwParam);
    return ( NET_API_STATUS  )_RetVal.Simple;
    
}


#if !defined(__RPC_WIN64__)
#error  Invalid build platform for this stub.
#endif

static const ms2Dbkrp_MIDL_PROC_FORMAT_STRING ms2Dbkrp__MIDL_ProcFormatString =
    {
        0,
        {

	/* Procedure BackuprKey */

			0x0,		/* 0 */
			0x48,		/* Old Flags:  */
/*  2 */	NdrFcLong( 0x0 ),	/* 0 */
/*  6 */	NdrFcShort( 0x0 ),	/* 0 */
/*  8 */	NdrFcShort( 0x40 ),	/* X64 Stack size/offset = 64 */
/* 10 */	0x32,		/* FC_BIND_PRIMITIVE */
			0x0,		/* 0 */
/* 12 */	NdrFcShort( 0x0 ),	/* X64 Stack size/offset = 0 */
/* 14 */	NdrFcShort( 0x54 ),	/* 84 */
/* 16 */	NdrFcShort( 0x24 ),	/* 36 */
/* 18 */	0x47,		/* Oi2 Flags:  srv must size, clt must size, has return, has ext, */
			0x7,		/* 7 */
/* 20 */	0xa,		/* 10 */
			0x7,		/* Ext Flags:  new corr desc, clt corr check, srv corr check, */
/* 22 */	NdrFcShort( 0x1 ),	/* 1 */
/* 24 */	NdrFcShort( 0x1 ),	/* 1 */
/* 26 */	NdrFcShort( 0x0 ),	/* 0 */
/* 28 */	NdrFcShort( 0x0 ),	/* 0 */

	/* Parameter pguidActionAgent */

/* 30 */	NdrFcShort( 0x10a ),	/* Flags:  must free, in, simple ref, */
/* 32 */	NdrFcShort( 0x8 ),	/* X64 Stack size/offset = 8 */
/* 34 */	NdrFcShort( 0xc ),	/* Type Offset=12 */

	/* Parameter pDataIn */

/* 36 */	NdrFcShort( 0x10b ),	/* Flags:  must size, must free, in, simple ref, */
/* 38 */	NdrFcShort( 0x10 ),	/* X64 Stack size/offset = 16 */
/* 40 */	NdrFcShort( 0x1c ),	/* Type Offset=28 */

	/* Parameter cbDataIn */

/* 42 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 44 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 46 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter ppDataOut */

/* 48 */	NdrFcShort( 0x2013 ),	/* Flags:  must size, must free, out, srv alloc size=8 */
/* 50 */	NdrFcShort( 0x20 ),	/* X64 Stack size/offset = 32 */
/* 52 */	NdrFcShort( 0x28 ),	/* Type Offset=40 */

	/* Parameter pcbDataOut */

/* 54 */	NdrFcShort( 0x2150 ),	/* Flags:  out, base type, simple ref, srv alloc size=8 */
/* 56 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 58 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Parameter dwParam */

/* 60 */	NdrFcShort( 0x48 ),	/* Flags:  in, base type, */
/* 62 */	NdrFcShort( 0x30 ),	/* X64 Stack size/offset = 48 */
/* 64 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

	/* Return value */

/* 66 */	NdrFcShort( 0x70 ),	/* Flags:  out, return, base type, */
/* 68 */	NdrFcShort( 0x38 ),	/* X64 Stack size/offset = 56 */
/* 70 */	0x8,		/* FC_LONG */
			0x0,		/* 0 */

			0x0
        }
    };

static const ms2Dbkrp_MIDL_TYPE_FORMAT_STRING ms2Dbkrp__MIDL_TypeFormatString =
    {
        0,
        {
			NdrFcShort( 0x0 ),	/* 0 */
/*  2 */	
			0x11, 0x0,	/* FC_RP */
/*  4 */	NdrFcShort( 0x8 ),	/* Offset= 8 (12) */
/*  6 */	
			0x1d,		/* FC_SMFARRAY */
			0x0,		/* 0 */
/*  8 */	NdrFcShort( 0x8 ),	/* 8 */
/* 10 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 12 */	
			0x15,		/* FC_STRUCT */
			0x3,		/* 3 */
/* 14 */	NdrFcShort( 0x10 ),	/* 16 */
/* 16 */	0x8,		/* FC_LONG */
			0x6,		/* FC_SHORT */
/* 18 */	0x6,		/* FC_SHORT */
			0x4c,		/* FC_EMBEDDED_COMPLEX */
/* 20 */	0x0,		/* 0 */
			NdrFcShort( 0xfff1 ),	/* Offset= -15 (6) */
			0x5b,		/* FC_END */
/* 24 */	
			0x11, 0x0,	/* FC_RP */
/* 26 */	NdrFcShort( 0x2 ),	/* Offset= 2 (28) */
/* 28 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 30 */	NdrFcShort( 0x1 ),	/* 1 */
/* 32 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x0,		/*  */
/* 34 */	NdrFcShort( 0x18 ),	/* X64 Stack size/offset = 24 */
/* 36 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 38 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 40 */	
			0x11, 0x14,	/* FC_RP [alloced_on_stack] [pointer_deref] */
/* 42 */	NdrFcShort( 0x2 ),	/* Offset= 2 (44) */
/* 44 */	
			0x12, 0x0,	/* FC_UP */
/* 46 */	NdrFcShort( 0x2 ),	/* Offset= 2 (48) */
/* 48 */	
			0x1b,		/* FC_CARRAY */
			0x0,		/* 0 */
/* 50 */	NdrFcShort( 0x1 ),	/* 1 */
/* 52 */	0x29,		/* Corr desc:  parameter, FC_ULONG */
			0x54,		/* FC_DEREFERENCE */
/* 54 */	NdrFcShort( 0x28 ),	/* X64 Stack size/offset = 40 */
/* 56 */	NdrFcShort( 0x0 ),	/* Corr flags:  */
/* 58 */	0x1,		/* FC_BYTE */
			0x5b,		/* FC_END */
/* 60 */	
			0x11, 0xc,	/* FC_RP [alloced_on_stack] [simple_pointer] */
/* 62 */	0x8,		/* FC_LONG */
			0x5c,		/* FC_PAD */

			0x0
        }
    };

static const unsigned short BackupKey_FormatStringOffsetTable[] =
    {
    0
    };


static const MIDL_STUB_DESC BackupKey_StubDesc = 
    {
    (void *)& BackupKey___RpcClientInterface,
    MIDL_user_allocate,
    MIDL_user_free,
    &BackupKey__MIDL_AutoBindHandle,
    0,
    0,
    0,
    0,
    ms2Dbkrp__MIDL_TypeFormatString.Format,
    1, /* -error bounds_check flag */
    0x60000, /* Ndr library version */
    0,
    0x801026e, /* MIDL Version 8.1.622 */
    0,
    0,
    0,  /* notify & notify_flag routine table */
    0x1, /* MIDL flag */
    0, /* cs routines */
    0,   /* proxy/server info */
    0
    };
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif


#endif /* defined(_M_AMD64)*/

