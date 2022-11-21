

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 11:14:07 2038
 */
/* Compiler settings for ms-bkrp.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.01.0622 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __ms2Dbkrp_h__
#define __ms2Dbkrp_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"

#ifdef __cplusplus
extern "C"{
#endif 


#ifndef __BackupKey_INTERFACE_DEFINED__
#define __BackupKey_INTERFACE_DEFINED__

/* interface BackupKey */
/* [explicit_handle][nocode][unique][version][uuid] */ 

typedef DWORD NET_API_STATUS;

/* [code] */ NET_API_STATUS BackuprKey( 
    /* [in] */ handle_t h,
    /* [in] */ GUID *pguidActionAgent,
    /* [size_is][in] */ byte *pDataIn,
    /* [in] */ DWORD cbDataIn,
    /* [size_is][size_is][out] */ byte **ppDataOut,
    /* [out] */ DWORD *pcbDataOut,
    /* [in] */ DWORD dwParam);



extern RPC_IF_HANDLE BackupKey_v1_0_c_ifspec;
extern RPC_IF_HANDLE BackupKey_v1_0_s_ifspec;
#endif /* __BackupKey_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


