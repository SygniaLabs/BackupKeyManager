#pragma once

#include <stdio.h>
#include <Windows.h>
#include <stdio.h>
#include "generic_rpc.h"
#include "ms-bkrp.h"


const GUID BACKUPKEY_BACKUP_GUID = { 0x7f752b10, 0x178e, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40} };
const GUID BACKUPKEY_RESTORE_GUID_WIN2K = { 0x7fe94d50, 0x178e, 0x11d1, {0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40} };
const GUID BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID = { 0x018ff48a, 0xeaba, 0x40c6, {0x8f, 0x6d, 0x72, 0x37, 0x02, 0x40, 0xe9, 0x67} };
const GUID BACKUPKEY_RESTORE_GUID = { 0x47270c64, 0x2fc7, 0x499b, {0xac, 0x5b, 0x0e, 0x37, 0xcd, 0xce, 0x89, 0x9a} };

BOOL kull_m_rpc_bkrp_generic(RPC_BINDING_HANDLE* hBinding, const GUID* pGuid, PVOID DataIn, DWORD dwDataIn, PVOID* pDataOut, DWORD* pdwDataOut);
BOOL get_bkrp_cert(LPCWSTR dc, intptr_t *pDataOut, DWORD *dwDataOut);
BOOL bkrp_test(LPCWSTR dc);
void free_bkrp(void* pBuffer);