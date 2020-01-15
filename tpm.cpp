#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <iostream>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

bool bTPMSupport=false;

NCRYPT_PROV_HANDLE hProvider=NULL;

#define TPMProviderName L"Microsoft Platform Crypto Provider"

void EnumProviders()
{
    NTSTATUS status;
    ULONG cbBuffer = 0;
    PCRYPT_PROVIDERS pBuffer = NULL;

    /*
    Get the providers, letting the BCryptEnumRegisteredProviders
    function allocate the memory.
    */
    status = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);

    if (NT_SUCCESS(status))
    {
        if (pBuffer != NULL)
        {
            // Enumerate the providers.
            for (ULONG i = 0; i < pBuffer->cProviders; i++)
            {
                printf("%S\n", pBuffer->rgpszProviders[i]);
                if (wcscmp(pBuffer->rgpszProviders[i], TPMProviderName)==0) {
                    bTPMSupport = true;
                }
            }
        }
    }
    else
    {
        printf("BCryptEnumRegisteredProviders failed with error code 0x%08x\n", status);
    }

    if (NULL != pBuffer)
    {
        /*
        Free the memory allocated by the
        BCryptEnumRegisteredProviders function.
        */
        BCryptFreeBuffer(pBuffer);
    }
}

void GetKeyStorageProvider()
{
    SECURITY_STATUS status;
    status = NCryptOpenStorageProvider(&hProvider, TPMProviderName, 0);
    if (status != ERROR_SUCCESS) {
        printf("Fail on NCryptOpenStorageProvider!\n");
        exit(-1);
    }
    printf("Key Storage Provider=0x%08x\n", hProvider);
}

void CreateKey()
{
    SECURITY_STATUS status;
    NCRYPT_KEY_HANDLE handle;

    status = NCryptCreatePersistedKey(hProvider, &handle, L"AES", L"HEMA_AES", 0, NCRYPT_MACHINE_KEY_FLAG);

    if (status == ERROR_SUCCESS) {
        printf("CreateKey with handle: 0x%08x", handle);
    }
    else {
        printf("NCryptCreatePersistedKey failed with error code 0x%08x\n", status);
        printf("0x%08x\n", NTE_BAD_FLAGS);
        printf("0x%08x\n", NTE_EXISTS);
        printf("0x%08x\n", NTE_INVALID_HANDLE);
        printf("0x%08x\n", NTE_INVALID_PARAMETER);
        printf("0x%08x\n", NTE_NO_MEMORY);
        printf("0x%08x\n", NTE_NOT_SUPPORTED);
    }
    if (handle != NULL) {
        NCryptFreeObject(handle);
    }
}

void EnumKeys()
{
    NCryptKeyName *pKeyName = NULL;
    PVOID pEnumState = NULL;
    SECURITY_STATUS status;

    status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, NCRYPT_MACHINE_KEY_FLAG);

    if (status == ERROR_SUCCESS) {
        printf("Key Name: %S", pKeyName->pszName);
    }
    else {
        printf("NCryptEnumKeys failed with error code 0x%08x\n", status);
        printf("0x%08x\n", NTE_BAD_FLAGS);
        printf("0x%08x\n", NTE_INVALID_HANDLE);
        printf("0x%08x\n", NTE_INVALID_PARAMETER);
        printf("0x%08x\n", NTE_NO_MEMORY);
        printf("0x%08x\n", NTE_NO_MORE_ITEMS);
        printf("0x%08x\n", NTE_SILENT_CONTEXT
        );
    }

    if(pKeyName!=NULL) {
        NCryptFreeBuffer(pKeyName);
    }
}

int main()
{
    EnumProviders();

    if (bTPMSupport == true) {
        printf("Have TPM Support!\n");
    } else {
        printf("No TPM Support!\n");
        exit(-1);
    }

    GetKeyStorageProvider();

    CreateKey();

    EnumKeys();
}
