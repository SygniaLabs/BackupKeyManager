#include "bkrp-mgr.h"

BOOL get_bkrp_cert(LPCWSTR dc,
	PVOID* pDataOut,
	DWORD* dwDataOut)
{
	RPC_BINDING_HANDLE hBinding = NULL;
	BOOL status = FALSE;

	if (kull_m_rpc_createBinding(L"ncacn_np", dc, L"\\pipe\\protected_storage", L"ProtectedStorage", RPC_C_IMP_LEVEL_IMPERSONATE, &hBinding, NULL)) {
		wprintf(L"[-] Retrieving the current BackupKey public certificate via MS-BKRP...");
		// 0xaaaaaaaa (pDataIn) and 0 (cbDataIn) are ignored by the server as specified in MS-BKRP section 3.1.4.1
		if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, (PVOID)0xaaaaaaaa, 0, pDataOut, dwDataOut)) {
			wprintf(L"OK -> Certificate size: %u\n", *dwDataOut);
			status = TRUE;
		}
		kull_m_rpc_deleteBinding(&hBinding);
	}
	return status;
}


void free_bkrp(void* pBuffer) {
	MIDL_user_free(pBuffer);
}


BOOL bkrp_test(LPCWSTR dc) {

	RPC_BINDING_HANDLE hBinding;
	BOOL status = FALSE;
	wchar_t dataIn[] = L"MySecret!";
	PVOID pEncryptDataOut = NULL;
	DWORD dwEncryptDataOut = 0;
	PVOID pDecryptDataOut = NULL;
	DWORD dwDecryptDataOut = 0;

	if (kull_m_rpc_createBinding(L"ncacn_np", dc, L"\\pipe\\protected_storage", L"ProtectedStorage", RPC_C_IMP_LEVEL_IMPERSONATE, &hBinding, NULL))
	{
		wprintf(L"    > Attempting secret encrypt (%s)....", dataIn);
		if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_BACKUP_GUID, &dataIn, sizeof(dataIn), &pEncryptDataOut, &dwEncryptDataOut))
		{
			wprintf(L" OK\n");

			wprintf(L"    > Attempting secret decrypt....");
			if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_RESTORE_GUID, pEncryptDataOut, dwEncryptDataOut, &pDecryptDataOut, &dwDecryptDataOut))
			{
				wprintf(L" OK -> %s\n", pDecryptDataOut);
				MIDL_user_free(pDecryptDataOut);
				status = TRUE;
			}
			MIDL_user_free(pEncryptDataOut);
		}
		kull_m_rpc_deleteBinding(&hBinding);
	}
	return status;
}




BOOL kull_m_rpc_bkrp_generic(RPC_BINDING_HANDLE* hBinding,
	const GUID* pGuid,
	PVOID DataIn,
	DWORD dwDataIn,
	PVOID* pDataOut,
	DWORD* pdwDataOut)
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