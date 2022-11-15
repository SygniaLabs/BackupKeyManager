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


void example()
{
    printf("Hello workd");
}

int bkrp_example(LPCWSTR dc)
{
    RPC_BINDING_HANDLE hBinding;
    wchar_t dataIn[] = L"MySecret!";
    PVOID pDataOut, pDataOut2;
    DWORD dwDataOut, dwDataOut2;

	if (kull_m_rpc_createBinding(L"ncacn_np", dc, L"\\pipe\\protected_storage", L"ProtectedStorage", RPC_C_IMP_LEVEL_IMPERSONATE, &hBinding, NULL))
	{
		wprintf(L"[+] Retrieving the current BackupKey public certificate\n");
		if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, (PVOID)0xaaaaaaaa, 0, &pDataOut, &dwDataOut))
		{
			wprintf(L"   > Certificate size: %u\n", dwDataOut);
			int ctxOffset = getContextSpecificOffset(pDataOut, dwDataOut);
			if (ctxOffset == 0) {
				wprintf(L"[ERROR] Could not parse certificate\n");
				return 1;
			}
			parseGuidBytesFromCtx(pDataOut, dwDataOut, ctxOffset);
			MIDL_user_free(pDataOut);
		}

		wprintf(L"    > Attempting secret encrypt (%s)....", dataIn);
		if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_BACKUP_GUID, &dataIn, sizeof(dataIn), &pDataOut, &dwDataOut))
		{
			wprintf(L" OK\n");

			wprintf(L"    > Attempting secret decrypt....");
			if (kull_m_rpc_bkrp_generic(&hBinding, &BACKUPKEY_RESTORE_GUID, pDataOut, dwDataOut, &pDataOut2, &dwDataOut2))
			{
				wprintf(L" OK -> %s\n", pDataOut2);
				MIDL_user_free(pDataOut2);
			}
			MIDL_user_free(pDataOut);
		}

		kull_m_rpc_deleteBinding(&hBinding);
	}
	return ERROR_SUCCESS;
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



int getContextSpecificOffset(PVOID data, DWORD size)
{

	int ctx1Offset = 0;
	DWORD i;
	for (i = 0; i < (size - 16); i++)
	{
		if (((PBYTE)data)[i] == ctx1Tag && ((PBYTE)data)[i + 1] == guidSize + 1 && ((PBYTE)data)[i + 2] == 0x00 &&
			((PBYTE)data)[i + 19] == ctx2Tag && ((PBYTE)data)[i + 20] == guidSize + 1)
		{
			ctx1Offset = i;
			//wprintf(L"Found Context specific 1 at offset: %d\n", i);
		}

	}
	return ctx1Offset;
}


void parseGuidBytesFromCtx(PVOID pCert, DWORD certSize, DWORD ctxOffset)
{
	byte certBytes[1024];
	byte guidBytes[16];
	int guidOffset = ctxOffset + 3;


	if (certSize > 1024) {
		wprintf(L"[ERROR] Certificate size is too big\n");
		return;
	}


	memcpy(&certBytes, pCert, certSize);
	memcpy(&guidBytes, &certBytes[guidOffset], guidSize);

	printBkpAsGuid(guidBytes);

}

void printBkpAsGuid(byte guidBytes[16]) {

	wprintf(L"   > Guid: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
		guidBytes[3], guidBytes[2], guidBytes[1], guidBytes[0],
		guidBytes[5], guidBytes[4],
		guidBytes[7], guidBytes[6],
		guidBytes[8], guidBytes[9],
		guidBytes[10], guidBytes[11], guidBytes[12], guidBytes[13], guidBytes[14], guidBytes[15]);
}