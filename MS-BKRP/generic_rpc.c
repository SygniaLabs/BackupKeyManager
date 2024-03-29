/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "generic_rpc.h"

// IDL & ACF	https://msdn.microsoft.com/library/windows/desktop/aa378708.aspx
// IDL			https://msdn.microsoft.com/library/windows/desktop/aa378712.aspx
// ACF			https://msdn.microsoft.com/library/windows/desktop/aa378704.aspx

BOOL kull_m_rpc_createBinding(LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *))
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	RPC_WSTR StringBinding = NULL;
	RPC_SECURITY_QOS SecurityQOS = {RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH, RPC_C_QOS_IDENTITY_STATIC, ImpersonationType};
	LPWSTR fullServer;
	DWORD szServer = (DWORD) (wcslen(NetworkAddr) * sizeof(wchar_t)), szPrefix = (DWORD) (wcslen(Service) * sizeof(wchar_t));

	*hBinding = NULL;
	rpcStatus = RpcStringBindingCompose(NULL, (RPC_WSTR) ProtSeq, (RPC_WSTR) NetworkAddr, (RPC_WSTR) Endpoint, NULL, &StringBinding);
	if(rpcStatus == RPC_S_OK)
	{
		rpcStatus = RpcBindingFromStringBinding(StringBinding, hBinding);
		if(rpcStatus == RPC_S_OK)
		{
			if(*hBinding)
			{
				if(fullServer = (LPWSTR) LocalAlloc(LPTR, szPrefix + sizeof(wchar_t) + szServer + sizeof(wchar_t)))
				{
					RtlCopyMemory(fullServer, Service, szPrefix);
					RtlCopyMemory((PBYTE) fullServer + szPrefix + sizeof(wchar_t), NetworkAddr, szServer);
					((PBYTE) fullServer)[szPrefix] = L'/';
					rpcStatus = RpcBindingSetAuthInfoEx(*hBinding, (RPC_WSTR) fullServer, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, /*(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_VISTA) ? RPC_C_AUTHN_GSS_KERBEROS :*/ RPC_C_AUTHN_GSS_NEGOTIATE, NULL, 0, &SecurityQOS);
					if(rpcStatus == RPC_S_OK)
					{
						if(RpcSecurityCallback)
						{
							rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK, (ULONG_PTR) RpcSecurityCallback);
							status = (rpcStatus == RPC_S_OK);
							if(!status)
								wprintf(L"[ERROR] RPC Create Binding RpcBindingSetOption: 0x%08x (%u)\n", rpcStatus, rpcStatus);
						}
						else status = TRUE;
					}
					else wprintf(L"[ERROR] RPC Create Binding RpcBindingSetAuthInfoEx: 0x%08x (%u)\n", rpcStatus, rpcStatus);
					LocalFree(fullServer);
				}
			}
			else wprintf(L"[ERROR] RPC Create Binding No Binding!\n");
		}
		else wprintf(L"[ERROR] RPC Create Binding RpcBindingFromStringBinding: 0x%08x (%u)\n", rpcStatus, rpcStatus);
		RpcStringFree(&StringBinding);
	}
	else wprintf(L"[ERROR] RPC Create Binding RpcStringBindingCompose: 0x%08x (%u)\n", rpcStatus, rpcStatus);
	return status;
}

BOOL kull_m_rpc_deleteBinding(RPC_BINDING_HANDLE *hBinding)
{
	BOOL status = FALSE;
	if(status = (RpcBindingFree(hBinding) == RPC_S_OK))
		*hBinding = NULL;
	return status;
}

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes)
{
	return LocalAlloc(LPTR, cBytes);
}

void __RPC_USER midl_user_free(void __RPC_FAR * p)
{
	LocalFree(p);
}

void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize)
{
	*pBuffer = (char *) ((PKULL_M_RPC_FCNSTRUCT) State)->addr;
	((PKULL_M_RPC_FCNSTRUCT) State)->addr = *pBuffer + *pSize;
	((PKULL_M_RPC_FCNSTRUCT) State)->size -= *pSize;
}

void __RPC_USER WriteFcn(void *State, char *Buffer, unsigned int Size)
{
}

BOOL generic_rpc_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE fDecode)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	PVOID buffer;
	KULL_M_RPC_FCNSTRUCT UserState;
	handle_t pHandle;

	if(buffer = UserState.addr = LocalAlloc(LPTR, size))
	{
		UserState.size = size;
		RtlCopyMemory(UserState.addr, data, size); // avoid data alteration
		rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle);
		if(NT_SUCCESS(rpcStatus))
		{
			rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_DECODE);
			if(NT_SUCCESS(rpcStatus))
			{
				RpcTryExcept
				{
					fDecode(pHandle, pObject);
					status = TRUE;
				}
				RpcExcept(EXCEPTION_EXECUTE_HANDLER)
					wprintf(L"[ERROR] RPC Decode Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
				RpcEndExcept
			}
			else wprintf(L"[ERROR] RPC Decode MesIncrementalHandleReset: %08x\n", rpcStatus);
			MesHandleFree(pHandle);
		}
		else wprintf(L"[ERROR] RPC Decode MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
		LocalFree(buffer);
	}
	return status;
}

void generic_rpc_Free(PVOID pObject, PGENERIC_RPC_FREE fFree)
{
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState = {NULL, 0};
	handle_t pHandle;

	rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle); // for legacy
	if(NT_SUCCESS(rpcStatus))
	{
		RpcTryExcept
			fFree(pHandle, pObject);
		RpcExcept(EXCEPTION_EXECUTE_HANDLER)
			wprintf(L"[ERROR] RPC Free Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept
		MesHandleFree(pHandle);
	}
	else wprintf(L"[ERROR] RPC Free MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
}

BOOL generic_rpc_Encode(PVOID pObject, PVOID *data, DWORD *size, PGENERIC_RPC_ENCODE fEncode, PGENERIC_RPC_ALIGNSIZE fAlignSize)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState;
	handle_t pHandle;

	rpcStatus = MesEncodeIncrementalHandleCreate(&UserState, ReadFcn, WriteFcn, &pHandle);
	if(NT_SUCCESS(rpcStatus))
	{
		*size = (DWORD) fAlignSize(pHandle, pObject);
		if(*data = LocalAlloc(LPTR, *size))
		{
			rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_ENCODE);
			if(NT_SUCCESS(rpcStatus))
			{
				UserState.addr = *data;
				UserState.size = *size;
				RpcTryExcept
				{
					fEncode(pHandle, pObject);
					status = TRUE;
				}
				RpcExcept(EXCEPTION_EXECUTE_HANDLER)
					wprintf(L"[ERROR] RPC Encode Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
				RpcEndExcept
			}
			else wprintf(L"[ERROR] RPC Encode MesIncrementalHandleReset: %08x\n", rpcStatus);

			if(!status)
			{
				*data = LocalFree(*data);
				*size = 0;
			}
		}
		MesHandleFree(pHandle);
	}
	else wprintf(L"[ERROR] RPC Encode MesEncodeIncrementalHandleCreate: %08x\n", rpcStatus);
	return status;
}