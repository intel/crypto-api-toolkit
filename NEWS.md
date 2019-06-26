# Crypto API Toolkit for Intel(R) SGX

## Release v1.4

### General
This is the update to Crypto API Toolkit for Intel(R) SGX. This version supports:

* Key generation, encryption and decryption for symmetric crypto algorithms AES-CTR, AES-GCM and AES-CBC (128/192/256 bit).
* Asymmetric key pair generation, encryption and decryption, sign and verify operation for RSA (1024/2048/3072/4096 bits).
* Message digest generation (SHA-256 & SHA-512 and HMAC-SHA256 & HMAC-SHA512).
* Support for wrapping and unwrapping symmetric keys with symmetric key and asymmetric key, unwrapping an asymmetric private key with a symmetric key, export and import of RSA public key, sealing (platform binding) of symmetric and asymmetric keys.
* Enclave quote generation with public key hash using EPID and ECDSA (DCAP) attestation primitives.

This version has been built and validated on CentOS 7.5, Ubuntu Desktop & Server v18.04.

## Known Issues & Limitations
* There is no full support for token objects. The token objects won’t be persisted. This will be supported in a future update. In this release, the token object creation is supported and will be available until the application’s call to C_Finalize.
* For asymmetric mechanisms with PSS padding only SHA256 is supported.
* CKU_CONTEXT_SPECIFIC user is not supported.
* C_Initialize API does not accept application provided mutexes for locking. This API will fail if the CK_INITIALIZE_ARGS contain application provided mutexes.
* C_Initialize does not support CK_INITIALIZE_ARGS with CKF_LIBRARY_CANT_CREATE_OS_THREADS set in flags member.
* Support for multithreading will be enabled in a future release.

## Release v1.3

### General
This is the initial release of Crypto API Toolkit for Intel(R) SGX. This version supports:

* Key generation, encryption and decryption for symmetric crypto algorithms AES-CTR, AES-GCM and AES-CBC (128/192/256 bit).
* Asymmetric key pair generation, encryption and decryption, sign and verify operation for RSA (1024/2048/3072/4096 bits).
* Support for wrapping and unwrapping symmetric keys with symmetric key and asymmetric key, export and import of RSA public key, sealing (platform binding) of symmetric and asymmetric keys.
* Message digest generation (SHA-256 & SHA-512 and HMAC-SHA256 & HMAC-SHA512).
* Enclave quote generation with public key hash.

This version has been built and validated on 64-bit versions of CentOS 7.5, Ubuntu Desktop v16.04 and v18.04.

## Known Issues & Limitations
* There is no full support for token objects. The token objects won’t be persisted. This will be supported in a future update. In this release, the token object creation is supported and will be available until the application’s call to C_Finalize.
* For asymmetric mechanisms with PSS padding only SHA256 is supported.
* CKU_CONTEXT_SPECIFIC user is not supported.
* C_Initialize API does not accept application provided mutexes for locking. This API will fail if the CK_INITIALIZE_ARGS contain application provided mutexes.
* C_Initialize does not support CK_INITIALIZE_ARGS with CKF_LIBRARY_CANT_CREATE_OS_THREADS set in flags member.
