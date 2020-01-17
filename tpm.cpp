#include <assert.h>
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


//#define KeyProviderName MS_PLATFORM_CRYPTO_PROVIDER


#define KEY_NAME L"ECDH Key"

void ReportError(SECURITY_STATUS dwErrCode)
{
    printf("Error: 0x%08x\n", dwErrCode);

    printf("0x%08x: NTE_BAD_FLAGS\n", NTE_BAD_FLAGS);
    printf("0x%08x: NTE_NO_MEMORY\n", NTE_NO_MEMORY);
    printf("0x%08x: NTE_EXISTS\n", NTE_EXISTS);
    printf("0x%08x: NTE_SILENT_CONTEXT\n", NTE_SILENT_CONTEXT);
    printf("0x%08x: NTE_INVALID_HANDLE\n", NTE_INVALID_HANDLE);
    printf("0x%08x: NTE_INVALID_PARAMETER\n", NTE_INVALID_PARAMETER);
    printf("0x%08x: NTE_NOT_SUPPORTED\n", NTE_NOT_SUPPORTED);
    printf("0x%08x: NTE_NO_MORE_ITEMS\n", NTE_NO_MORE_ITEMS);
}

void EnumProviders()
{
    NTSTATUS status;
    ULONG cbBuffer = 0;
    PCRYPT_PROVIDERS pBuffer = NULL;

    //
    // Get the providers, letting the BCryptEnumRegisteredProviders
    // function allocate the memory.
    //

    status = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);
    if (NT_SUCCESS(status))
    {
        if (pBuffer != NULL)
        {
            // Enumerate the providers.
            for (ULONG i = 0; i < pBuffer->cProviders; i++)
            {
                printf("%S\n", pBuffer->rgpszProviders[i]);
                if (wcscmp(pBuffer->rgpszProviders[i], MS_PLATFORM_CRYPTO_PROVIDER)==0) {
                    bTPMSupport = true;
                }
            }
        }
    }
    else
    {
        ReportError(status);
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

NCRYPT_PROV_HANDLE GetKeyStorageProvider(LPCWSTR sProvider)
{
    SECURITY_STATUS status;
    NCRYPT_PROV_HANDLE hProvider;

    status = NCryptOpenStorageProvider(&hProvider, sProvider, 0);
    if (status != ERROR_SUCCESS) {
        printf("Fail on NCryptOpenStorageProvider!\n");
        ReportError(status);
        exit(-1);
    }
    //printf("Key Storage Provider=0x%08x\n", hProvider);

    return hProvider;
}

void dump_key(PBYTE pData, DWORD len)
{
    DWORD i;

    printf("Key:\n");
    printf("length=%d\n", len);
    for (i = 0; i < len; i++) {
        printf("0x%02x ", pData[i]);
    }
    printf("\n");
}

void write_key_to_file(const char *pFileName, PBYTE PubBlob, DWORD PubBlobLength)
{
    FILE *fp;
    errno_t err;
    size_t size;
    err = fopen_s(&fp, pFileName, "w");
    assert(fp != NULL);
    size = fwrite(PubBlob, PubBlobLength, 1, fp);
    assert(size == 1);
    fclose(fp);
}

void read_key_from_file(const char* pFileName, PBYTE *pByte, DWORD *pLength)
{
    FILE* fp;
    errno_t err;
    size_t size;
    struct stat st;

    stat(pFileName, &st);
    *pLength = st.st_size;
    printf("length=%d\n", *pLength);

    *pByte = (PBYTE)malloc(*pLength);

    err = fopen_s(&fp, pFileName, "r");
    assert(fp != NULL);

    size = fread(*pByte, *pLength, 1, fp);
    assert(size == 1);
    fclose(fp);
}
void NExportKey(NCRYPT_KEY_HANDLE key_handle, PBYTE *pPubBlob, DWORD *pPubBlobLength)
{
    SECURITY_STATUS status;

    *pPubBlobLength = 0;
    *pPubBlob = NULL;

    // Export Public Key
    status = NCryptExportKey(key_handle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, pPubBlobLength, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptExportKey failed!\n");
        ReportError(status);
        goto cleanup;
    }
    *pPubBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *pPubBlobLength);
    if (NULL == pPubBlob)
    {
        status = NTE_NO_MEMORY;
        ReportError(status);
        goto cleanup;
    }
    status = NCryptExportKey(key_handle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, *pPubBlob, *pPubBlobLength, pPubBlobLength, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptExportKey failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }
    printf("Key exported\n");
cleanup:
    0;
}

void CreateKey(NCRYPT_PROV_HANDLE hProvider)
{
    SECURITY_STATUS status;
    NCRYPT_KEY_HANDLE key_handle;
    DWORD KeyPolicy = 0;

    // delete existing key
    status = NCryptOpenKey(hProvider, &key_handle, KEY_NAME, 0, NCRYPT_MACHINE_KEY_FLAG);
    if (status == ERROR_SUCCESS) {
        printf("Key exists\n");
        status = NCryptDeleteKey(key_handle, 0);
        if (status != ERROR_SUCCESS) {
            ReportError(status);
            goto cleanup;
        }
        key_handle = NULL;
        printf("Existing key deleted\n");
    }

    // generate an ECDH key
    status = NCryptCreatePersistedKey(hProvider, &key_handle, NCRYPT_ECDH_P256_ALGORITHM, KEY_NAME, 0, NCRYPT_MACHINE_KEY_FLAG);
    if (status == ERROR_SUCCESS) {
        //printf("CreateKey with handle: 0x%08x\n", key_handle);
    }
    else {
        printf("NCryptCreatePersistedKey failed!\n");
        ReportError(status);
    }

#if 0
    // Make the key exportable
    KeyPolicy = NCRYPT_ALLOW_EXPORT_FLAG;
    status = NCryptSetProperty(key_handle, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&KeyPolicy, sizeof(KeyPolicy), NCRYPT_PERSIST_FLAG);
    if (status != ERROR_SUCCESS) {
        printf("NCryptSetProperty failed!\n");
        ReportError(status);
        goto cleanup;
    }
#endif

    // Finalize Key
    status = NCryptFinalizeKey(key_handle, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptFinalizeKey failed!\n");
        ReportError(status);
        goto cleanup;
    }
    printf("Key finalized\n");

cleanup:
    if (key_handle != NULL) {
        NCryptFreeObject(key_handle);
    }
}

void EnumKeys(NCRYPT_PROV_HANDLE hProvider)
{
    NCryptKeyName *pKeyName = NULL;
    PVOID pEnumState = NULL;
    SECURITY_STATUS status;

    status = NCryptEnumKeys(hProvider, NULL, &pKeyName, &pEnumState, NCRYPT_MACHINE_KEY_FLAG);

    if (status == ERROR_SUCCESS) {
        printf("Key Name: %S\n", pKeyName->pszName);
    }
    else {
        printf("NCryptEnumKeys failed!\n");
        ReportError(status);
    }

    if(pKeyName!=NULL) {
        NCryptFreeBuffer(pKeyName);
    }
}

NCRYPT_KEY_HANDLE target_open_key(NCRYPT_PROV_HANDLE hProvider)
{
    SECURITY_STATUS status;
    NCRYPT_KEY_HANDLE key_handle = NULL;

    status = NCryptOpenKey(hProvider, &key_handle, KEY_NAME, 0, NCRYPT_MACHINE_KEY_FLAG);
    if (status != ERROR_SUCCESS) {
        printf("NCryptOpenKey failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }
cleanup:
    0;

    return key_handle;
}

void target_create_key(NCRYPT_PROV_HANDLE hProvider)
{
    CreateKey(hProvider);
}

void target_export_public_key(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE key_handle)
{
    PBYTE PubBlob;
    DWORD PubBlobLength;

    EnumKeys(hProvider);

    NExportKey(key_handle, &PubBlob, &PubBlobLength);

    dump_key(PubBlob, PubBlobLength);
    write_key_to_file("target.key", PubBlob, PubBlobLength);
}

void target_generate_shared_secret(NCRYPT_PROV_HANDLE hProvider)
{
    DWORD BlobLenMaster = 0;
    PBYTE BlobMaster = NULL;

    SECURITY_STATUS status;
    NCRYPT_KEY_HANDLE key_handle_master;

    status = NCryptImportKey(hProvider, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, &key_handle_master, BlobMaster, BlobLenMaster, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptImportKey failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }
cleanup:
    0;
}

void BExportKey(BCRYPT_KEY_HANDLE key_handle, PBYTE* pPubBlob, DWORD* pPubBlobLength)
{
    SECURITY_STATUS status;

    // Export Public Key
    status = BCryptExportKey(key_handle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, pPubBlobLength, 0);
    if (status != ERROR_SUCCESS) {
        printf("BCryptExportKey failed!\n");
        ReportError(status);
        goto cleanup;
    }
    *pPubBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *pPubBlobLength);
    if (NULL == *pPubBlob)
    {
        status = NTE_NO_MEMORY;
        ReportError(status);
        goto cleanup;
    }
    status = BCryptExportKey(key_handle, NULL, BCRYPT_ECCPUBLIC_BLOB, *pPubBlob, *pPubBlobLength, pPubBlobLength, 0);
    if (status != ERROR_SUCCESS) {
        printf("BCryptExportKey failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }
    printf("Key exported\n");

cleanup:
    0;
}

void master_export_public_key()
{
    SECURITY_STATUS status;
    BCRYPT_ALG_HANDLE ExchAlgHandle = NULL;
    BCRYPT_KEY_HANDLE key_handle;
    PBYTE PubBlob;
    DWORD PubBlobLength;
 
    status = BCryptOpenAlgorithmProvider(&ExchAlgHandle, BCRYPT_ECDH_P256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
        printf("BCryptOpenAlgorithmProvider failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }

    status = BCryptGenerateKeyPair(ExchAlgHandle, &key_handle, 256, 0);
    if (status != ERROR_SUCCESS) {
        printf("BCryptGenerateKeyPair failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }

    status = BCryptFinalizeKeyPair(key_handle, 0);
    if (status != ERROR_SUCCESS) {
        printf("BCryptFinalizeKeyPair failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }

    BExportKey(key_handle, &PubBlob, &PubBlobLength);
    dump_key(PubBlob, PubBlobLength);
    write_key_to_file("master.key", PubBlob, PubBlobLength);
cleanup:
    0;
}

void master_derive_shared_secret()
{

}

static const BYTE SecretPrependArray[] =
{
    0x12, 0x34, 0x56
};

static const BYTE SecretAppendArray[] =
{
    0xab, 0xcd, 0xef
};

void target_derive_shared_secret(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE key_handle_target)
{
    SECURITY_STATUS status;
    NCRYPT_KEY_HANDLE key_handle_master_public;
    PBYTE PubBlob = NULL;
    DWORD PubBlobLength;
    PBYTE AgreedSecret = NULL;
    DWORD AgreedSecretLength;
    NCRYPT_SECRET_HANDLE AgreedSecretHandle = NULL;
    const DWORD BufferLength = 3;
    BCryptBuffer BufferArray[BufferLength] = { 0 };
    BCryptBufferDesc ParameterList = { 0 };

    //
    // target import master's public key
    //

    read_key_from_file("master.key", &PubBlob, &PubBlobLength);
    dump_key(PubBlob, PubBlobLength);

    status = NCryptImportKey(hProvider, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, &key_handle_master_public, PubBlob, PubBlobLength, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptImportKey failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }

    //
    // target generates the agreed secret
    //

    status = NCryptSecretAgreement(key_handle_target, key_handle_master_public, &AgreedSecretHandle, 0);
    if (status != ERROR_SUCCESS) {
        printf("NCryptSecretAgreement failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }

    //
    // Build KDF parameter list
    //

    //specify hash algorithm
    BufferArray[0].BufferType = KDF_HASH_ALGORITHM;
    BufferArray[0].cbBuffer = (DWORD)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
    BufferArray[0].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;

    //specify secret to append
    BufferArray[1].BufferType = KDF_SECRET_APPEND;
    BufferArray[1].cbBuffer = sizeof(SecretAppendArray);
    BufferArray[1].pvBuffer = (PVOID)SecretAppendArray;

    //specify secret to prepend
    BufferArray[2].BufferType = KDF_SECRET_PREPEND;
    BufferArray[2].cbBuffer = sizeof(SecretPrependArray);
    BufferArray[2].pvBuffer = (PVOID)SecretPrependArray;

    ParameterList.cBuffers = 3;
    ParameterList.pBuffers = BufferArray;
    ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

    status = NCryptDeriveKey(AgreedSecretHandle, BCRYPT_KDF_HASH , &ParameterList, NULL, 0, &AgreedSecretLength, KDF_USE_SECRET_AS_HMAC_KEY_FLAG);
    if (status != ERROR_SUCCESS) {
        printf("NCryptDeriveKey failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }

    AgreedSecret = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AgreedSecretLength);
    if (NULL == AgreedSecret)
    {
        status = NTE_NO_MEMORY;
        ReportError(status);
        goto cleanup;
    }

    status = NCryptDeriveKey(AgreedSecretHandle, BCRYPT_KDF_HMAC, &ParameterList, AgreedSecret, AgreedSecretLength, &AgreedSecretLength, KDF_USE_SECRET_AS_HMAC_KEY_FLAG);
    if (NULL == AgreedSecret)
    {
        printf("NCryptDeriveKey failed, line=%d!\n", __LINE__);
        ReportError(status);
        goto cleanup;
    }

    dump_key(AgreedSecret, AgreedSecretLength);

 cleanup:
    if (PubBlob!= NULL) {
        free(PubBlob);
    }
}

int main()
{
    NCRYPT_PROV_HANDLE hTPMProvider = NULL;
    NCRYPT_PROV_HANDLE hMSProvider = NULL;
    NCRYPT_KEY_HANDLE key_handle_target = NULL;

    EnumProviders();

    if (bTPMSupport == true) {
        printf("Have TPM Support!\n");
    } else {
        printf("No TPM Support!\n");
        exit(-1);
    }

    // MS_PLATFORM_CRYPTO_PROVIDER: Identifies the TPM key storage provider 
    // MS_KEY_STORAGE_PROVIDER: Identifies the software key storage provider
    hTPMProvider = GetKeyStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER);
    hMSProvider = GetKeyStorageProvider(MS_KEY_STORAGE_PROVIDER);

    key_handle_target = target_open_key(hTPMProvider);

    //target_export_public_key();

    //master_export_public_key();

    //master_derive_shared_secret();

    target_derive_shared_secret(hTPMProvider, key_handle_target);
}
