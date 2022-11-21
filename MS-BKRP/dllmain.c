// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "dllmain.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


BOOL get_bkrp_cert(LPCWSTR dc, PVOID *pDataOut, DWORD *dwDataOut)
{
    RPC_BINDING_HANDLE hBinding;
	BOOL status = FALSE;

	if (kull_m_rpc_createBinding(L"ncacn_np", dc, L"\\pipe\\protected_storage", L"ProtectedStorage", RPC_C_IMP_LEVEL_IMPERSONATE, &hBinding, NULL)) {
		wprintf(L"[+] Retrieving the current BackupKey public certificate via MS-BKRP...");
		if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, (PVOID)0xaaaaaaaa, 0, pDataOut, dwDataOut)) {
			wprintf(L"OK -> Certificate size: %u\n", *dwDataOut);
			status = TRUE;
		}	
		kull_m_rpc_deleteBinding(&hBinding);
	}
	return status;
}


void free_bkrp(void * pBuffer) {
	MIDL_user_free(pBuffer);
}


BOOL bkrp_test(LPCWSTR dc) {

	RPC_BINDING_HANDLE hBinding;
	BOOL status = FALSE;
	wchar_t dataIn[] = L"MySecret!";
	PVOID pDataOut, pDataOut2;
	DWORD dwDataOut, dwDataOut2;

	if (kull_m_rpc_createBinding(L"ncacn_np", dc, L"\\pipe\\protected_storage", L"ProtectedStorage", RPC_C_IMP_LEVEL_IMPERSONATE, &hBinding, NULL))
	{
		wprintf(L"    > Attempting secret encrypt (%s)....", dataIn);
		if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_BACKUP_GUID, &dataIn, sizeof(dataIn), &pDataOut, &dwDataOut))
		{
			wprintf(L" OK\n");

			wprintf(L"    > Attempting secret decrypt....");
			if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_RESTORE_GUID, pDataOut, dwDataOut, &pDataOut2, &dwDataOut2))
			{
				wprintf(L" OK -> %s\n", pDataOut2);
				MIDL_user_free(pDataOut2);
				status = TRUE;
			}
			MIDL_user_free(pDataOut);
		}
	kull_m_rpc_deleteBinding(&hBinding);
	}
	return status;
}




BOOL kull_m_rpc_bkrp_generic(RPC_BINDING_HANDLE* hBinding, const GUID* pGuid, PVOID DataIn, DWORD dwDataIn, PVOID* pDataOut, DWORD* pdwDataOut)
{
	BOOL status = FALSE;
	NET_API_STATUS netStatus;
	*pDataOut = NULL;
	*pdwDataOut = 0;
	RpcTryExcept
	{
		netStatus = BackuprKey(*hBinding, (GUID*)pGuid, (PBYTE)DataIn, dwDataIn, (PBYTE*)pDataOut, pdwDataOut, 0);
		if (!(status = (netStatus == 0)))
			wprintf(L"[ERROR] BackuprKey: 0x%08x (%u)\n", netStatus, netStatus);
	}
		RpcExcept(RPC_EXCEPTION)
		wprintf(L"[ERROR] RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
	RpcEndExcept
		return status;
}