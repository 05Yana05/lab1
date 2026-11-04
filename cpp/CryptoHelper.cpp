#include "CryptoHelper.h"
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "crypt32.lib")

static HCRYPTHASH createHash(HCRYPTPROV hProv, const std::string& key) {
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) throw std::runtime_error("Hash failed");
    if (!CryptHashData(hHash, (const BYTE*)key.c_str(), key.length(), 0)) throw std::runtime_error("Hash data failed");
    return hHash;
}

std::string CryptoHelper::encrypt(const std::string& plaintext, const std::string& key) {
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) throw std::runtime_error("CryptoAcquire failed");

    HCRYPTHASH hHash = createHash(hProv, key);
    HCRYPTKEY hKey = 0;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) throw std::runtime_error("DeriveKey failed");

    DWORD dataLen = plaintext.length();
    DWORD bufLen = dataLen + 32;
    std::vector<BYTE> buffer(bufLen);
    memcpy(buffer.data(), plaintext.c_str(), dataLen);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &dataLen, bufLen)) throw std::runtime_error("Encrypt failed");

    DWORD base64Len = 0;
    CryptBinaryToStringA(buffer.data(), dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Len);
    std::string result(base64Len, '\0');
    CryptBinaryToStringA(buffer.data(), dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &base64Len);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

std::string CryptoHelper::decrypt(const std::string& ciphertext, const std::string& key) {
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) throw std::runtime_error("CryptoAcquire failed");

    HCRYPTHASH hHash = createHash(hProv, key);
    HCRYPTKEY hKey = 0;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) throw std::runtime_error("DeriveKey failed");

    DWORD binLen = 0;
    CryptStringToBinaryA(ciphertext.c_str(), ciphertext.length(), CRYPT_STRING_BASE64, NULL, &binLen, NULL, NULL);
    std::vector<BYTE> buffer(binLen);
    CryptStringToBinaryA(ciphertext.c_str(), ciphertext.length(), CRYPT_STRING_BASE64, buffer.data(), &binLen, NULL, NULL);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &binLen)) throw std::runtime_error("Decrypt failed");

    std::string result((char*)buffer.data(), binLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}