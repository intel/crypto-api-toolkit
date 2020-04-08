Crypto API Toolkit for Intel(R) SGX
==================================

- [Introduction](#introduction)
- [License](#license)
- [Prerequisites](#prerequisites)
  - [System requirements](#system-requirements)
  - [Software requirements](#software-requirements)
- [Building the source](#building-the-source)
  - [Build configuration](#build-configuration)
  - [Preparing the source for the build](#preparing-the-source-for-the-build)
  - [Configuration options](#configuration-options)
  - [Compiling](#compiling)
  - [Installation](#installation)
  - [Running the tests](#running-the-tests)
  - [Uninstallation](#uninstallation)
- [APIs, Mechanisms and Attributes](#apis-mechanisms-and-attributes)
  - [APIs](#apis)
  - [Mechanisms](#mechanisms)
  - [Attributes](#attributes)
- [Quote Generation and Verification](#quote-generation-and-verification)
  - [Quote Generation](#quote-generation)
  - [Quote Verification](#quote-verification)
- [Multithreading support](#multithreading-support)
- [Restrictions](#restrictions)
- [Using Crypto API Toolkit](#using-crypto-api-toolkit)



## Introduction

Crypto API Toolkit for Intel(R) SGX (CTK) aims at enhancing the security of data and key protection applications by exposing interfaces that run the key generation and cryptographic operations securely inside an Intel(R) Software Guard Extensions (SGX) enclave. The operations are exposed and supported via PKCS11 interface for Linux.

The current release of CTK implements <a href="http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html">PKCS11 v2.40 Plus Errata 01</a>

## License
See [LICENSE.md](LICENSE.md) for details.

## Prerequisites

### System requirements
Intel(R) SGX capable system running Ubuntu 18.04-LTS 64-bit. For using Data Center Attestation Primitives (DCAP), the system must support Flexible Launch Control (FLC).

Please check <a href="https://ark.intel.com/content/www/us/en/ark/search/featurefilter.html?productType=873&2_SoftwareGuardExtensions=Yes%20with%20both%20Intel%C2%AE%20SPS%20and%20Intel%C2%AE%20ME">this page</a> for the server platforms that support Intel(R) SGX.

### Software requirements
The common software requirements for building the CTK are listed below. Please refer to your distro's documentation for how to fetch and install these tools if they do not come preinstalled.

- autotools (autoconf, automake, libtool)
- g++ compiler with C++11 support
- libcppunit-dev (for building and running the tests)

  For example in Ubuntu, the build tools and libraries can be obtained by running the command  

  ``$ sudo apt-get update``  
  ``$ sudo apt-get install dkms libprotobuf10 autoconf libcppunit-dev autotools-dev libc6-dev libtool build-essential``

- Intel(R) SGX software components  
  -  The SDK, driver and PSW can be downloaded and installed from <a href=https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-linux-2.9-release-version-string-2.9.100.2>Intel SGX Linux 2.9 Release</a> or can be built from the source from https://github.com/intel/linux-sgx.  
  - Intel(R) SGX SSL - built with All-Loads-Mitigation for CVE-2020-0551  
    Can be built from the source and installed from https://github.com/intel/intel-sgx-ssl. CTK has been validated with Intel(R) SGX SSL built with OpenSSL version 1.1.1d.
  - (For DCAP support) The latest version of DCAP binaries and driver can be downloaded and installed from https://01.org/intel-software-guard-extensions/downloads or built from the source from https://github.com/intel/SGXDataCenterAttestationPrimitives.

> **NOTE** This version of CTK is configured to build with, and validated against Intel SGX SDK v2.9, SGX driver v2.6.0_95eaa6f, DCAP v1.5 and SGXSSL binaries with All-Loads-Mitigation for CVE-2020-0551.

## Building the source

### Build configuration
-  The enclave is configured to have `DisableDebug` set to 0 in the enclave configuration XML ([src/p11/enclave_config/p11Enclave.config.xml](src/p11/enclave_config/p11Enclave.config.xml)) for the purpose of debug during development and integration. This means that the enclave will be debuggable. For a production enclave, this value must be set to to 1 before building the enclave. Please refer to the section Enclave Project Configurations in the [Intel(R) SGX Developer Reference for Linux* OS](https://download.01.org/intel-sgx/latest/linux-latest/docs/) for more information. Please also note that the provider that loads the enclave needs to be built with `NDEBUG` preprocessor macro that disables the `SGX_DEBUG_FLAG` (will be defined as 0).
- Based on the default `StackSize` (0x40000) defined in the enclave configuration XML ([src/p11/enclave_config/p11Enclave.config.xml](src/p11/enclave_config/p11Enclave.config.xml)), the maximum data that can be transfered from untrusted to trusted during an OCALL is limited to 180KB. This could limit the number of persistent token objects. Please tune this parameter (`StackSize`) based on the requirements and system capability.
> **NOTE** For platforms with FLC support, the release enclave does not need to be whitelisted. For other platforms, the release enclave will need to be whitelisted. The process of whitelisting and onboarding is detailed in https://software.intel.com/en-us/articles/intel-software-guard-extensions-product-licensing-faq.

### Preparing the source for the build  
After downloading the souce, run ``sh autogen.sh``

``$ sh autogen.sh``

### Configuration options
The source can be configured by running ``./configure``

``$ ./configure``

The options that ``configure`` supports can be obtained by running ``./configure --help``. Below are the options that are specific to CTK:

| Option  | Detail | Default value |
| ------------- | ------------- | ----- |
|--with-sgxsdk | SGX SDK installation path | /opt/intel/sgxsdk |
|--with-sgxssl | SGX SSL installation path | /opt/intel/sgxssl |
|--with-token-path | Path where PKCS11 tokens and objects will be stored | /opt/intel/cryptoapitoolkit |
|--enable-dcap | Build with DCAP support | Build without DCAP support  |
|--enable-ephemeral-quote | Destroy the key used for quote generation after one unwrap | Don't destroy |
|--with-p11-kit-path | p11-kit include directory path | Build without p11-kit, using PKCS11 headers from CTK |

### Compiling
``$ make``

> **NOTE** Please note that the enclave is signed with a test signing key. A production enclave should go through the process of signing an enclave as explained in the section Enclave Signing Tool in the [Intel(R) SGX Developer Reference for Linux* OS](https://download.01.org/intel-sgx/latest/linux-latest/docs/).

### Installation
``$ sudo make install``

### Running the tests
The tests will be built into an executable and can be executed by running
``./p11test`` from the directory ``$(srcroot)/src/tests``

Please note that the built libraries must be installed before running the tests.


### Uninstallation
``$ sudo make uninstall``

## APIs, Mechanisms and Attributes

CTK implements the APIs according to <a href="http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html">PKCS11 v2.40 (Plus Errata 01) specification</a> with some restrictions (please see the section on **Restrictions** below in this document). The developers are strongly encouraged to go through the PKCS11 specification for the details on the APIs, mechanisms and attributes.

### APIs

CTK **does not** support the APIs listed below.

C_GetOperationState  
C_SetOperationState  
C_DigestKey  
C_SignRecoverInit  
C_SignRecover  
C_VerifyRecoverInit  
C_VerifyRecover  
C_DigestEncryptUpdate  
C_DecryptDigestUpdate  
C_SignEncryptUpdate  
C_DecryptVerifyUpdate  
C_DeriveKey  
C_SeedRandom  
C_WaitForSlotEvent

### Mechanisms

CTK supports only the mechanisms listed below.

CKM_AES_KEY_GEN  
CKM_AES_CTR  
CKM_AES_GCM  
CKM_AES_CBC  
CKM_AES_CBC_PAD  
CKM_AES_KEY_WRAP  
CKM_AES_KEY_WRAP_PAD  
CKM_RSA_PKCS_KEY_PAIR_GEN  
CKM_RSA_PKCS  
CKM_RSA_PKCS_OAEP  
CKM_SHA1_RSA_PKCS<sup>1</sup>  
CKM_SHA224_RSA_PKCS<sup>1</sup>  
CKM_SHA256_RSA_PKCS  
CKM_SHA384_RSA_PKCS  
CKM_SHA512_RSA_PKCS   
CKM_RSA_PKCS_PSS  
CKM_SHA1_RSA_PKCS_PSS<sup>1</sup>  
CKM_SHA224_RSA_PKCS_PSS<sup>1</sup>  
CKM_SHA256_RSA_PKCS_PSS  
CKM_SHA384_RSA_PKCS_PSS  
CKM_SHA512_RSA_PKCS_PSS  
CKM_RSA_X_509  
CKM_SHA256  
CKM_SHA384  
CKM_SHA512  
CKM_SHA256_HMAC  
CKM_SHA384_HMAC  
CKM_SHA512_HMAC  
CKM_EC_KEY_PAIR_GEN  
CKM_EC_EDWARDS_KEY_PAIR_GEN  
CKM_ECDSA  
CKM_EDDSA  
CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY<sup>2</sup>

#### Supported Key Sizes
 - **AES**: 128, 192, 256 bits
 - **RSA**: 2048-16K bits
 - **ECDSA**: P-256, P-384, P-521 curves
 - **EDDSA**: Ed25519

> <sup>1</sup> **IMPORTANT** Intel Corporation strongly recommends **not to use** RSA sign & verify mechanisms based on SHA1 and SHA224 digest schemes as they are not considered cryptographically strong and vulnerable to collision based attacks. They are supported only for interoperability and backward compatibility towards existing applications that require these mechanisms. They are deprecated and will be removed in a future update.  
>
> <sup>2</sup> Custom mechanism to support ECDSA based quote generation based on RSA public key.

### Attributes

CTK supports most of the attributes listed in the PKCS11 specification with some restrictions. Please see the section on **Restrictions** below in this document.

## Quote Generation and Verification

### Quote Generation

After performing the initialization (load library, initialize and opening the session) and after creating the key pair (whose public key is to be exported along with the enclave quote), the application

1. Sets the mechanism to `CKM_EXPORT_ECDSA_QUOTE_RSA_PUBLIC_KEY` and fills the mechanism parameters in the structure `CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS`.

```cpp
typedef struct CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS {
    CK_LONG qlPolicy;
} CK_ECDSA_QUOTE_RSA_PUBLIC_KEY_PARAMS;
```

2. The application calls `C_WrapKey` with the mechanism details, the object handle of the key to be exported and passes a `NULL_PTR` for the `hWrappingKey` and destination buffer.
3. If the key handle is valid, the enclave returns the size of the destination buffer required to hold the exported public key and quote which is the total size of the actual public key buffer and `sizeof(CK_RSA_PUBLIC_KEY_PARAMS)` and the size of the quote itself. The quote is of the format `sgx_quote_t` and contains the hash of the public key and the quote generated based on this.
4. If the call is successful, the application allocates the buffer as per the returned buffer size.
5. The application calls `C_WrapKey` with the same parameters, with the allocated buffer for `pWrappedKey` parameter and the allocated size in `pulWrappedKeyLen`.
6. The Crypto API Toolkit for Intel(R) SGX enclave calculates the hash of the public key, generates a quote and returns it in the `pWrappedKey` buffer (in the below format).

<!-- language: lang-none -->

    --------------------------------------------------------------------------------------------------------------
    | Size |   CK_RSA_PUBLIC_KEY_PARAMS   | ulExponentLen | ulModulusLen |              sgx_quote_t              |
    --------------------------------------------------------------------------------------------------------------
    | Data | ulExponentLen | ulModulusLen |    exponent   |    modulus   | SHA256 hash of the public key | quote |
    --------------------------------------------------------------------------------------------------------------

Please refer `testeQuoteGeneration()` from [src/test/AsymWrapUnwrapTests.cpp](src/test/AsymWrapUnwrapTests.cpp) to see how the quote from the enclave based on the public key’s hash can be retrieved.

This public key, after verification, may be used to provision a secret key inside the enclave.

> **NOTE**: If the enclave has only the public key available (imported) and the private key is not available as part of the key pair, the quote generation will fail.

### Quote Verification

CTK does not support verifiying the quote. Please refer to the sample application in Intel(R) SGX DCAP to verify the quote (https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteVerification).

## Multithreading support

CTK is multithread safe, but the enclave is configured to not support multithreaded applications by default. Support for multithreaded applications can be enabled by updating the TCSNum tag in the enclave configuration XML. The enclave support for threads is limited by the number of TCSs and the available EPC memory. The maximum number of threads that an enclave can run simultaneously inside the enclave is the same as the number of logical processors in the system. This is typically the value set in the TCSNum tag. Please refer to the [Intel(R) SGX Developer Reference for Linux* OS](https://download.01.org/intel-sgx/latest/linux-latest/docs/) for configuring stack size and heap size in the XML for multithreaded applications.

## Restrictions

CTK imposes certain restrictions to further harden the security. They are listed below:

- CTK does not support application provided function pointers or callbacks and mutexes.

  - **C_Initialize**: The members *CreateMutex*, *DestroyMutex*, *LockMutex* and *UnlockMutex* in CK_C_INITIALIZE_ARGS are not supported and must be set to NULL_PTR.
  - **C_OpenSession**: The members *pApplication* and *Notify* are not supported and must be set to NULL_PTR.

 - **C_CreateObject**: CTK does not support creation of secret key objects using C_CreateObject API using the attribute CKA_VALUE. This is to prevent memory scraping attacks getting access to the key when it is being created in this manner. As an alternative, an application can call C_CreateObject to create a key inside the enclave by passing the mechanism and key's length in the template via CKA_VALUE_LEN.

- **C_GetAttributeValue**, **C_SetAttributeValue**: CTK does not allow setting and getting attributes that can expose the keys in the clear or affect its stability. The attributes listed below are not supported for **C_GetAttributeValue** and **C_SetAttributeValue** APIs:
  - CKA_VALUE
  - CKA_PRIVATE_EXPONENT
  - CKA_VALUE_LEN (restricted only for C_SetAttributeValue API)
  - CKA_PRIME_1
  - CKA_PRIME_2
  - CKA_EXPONENT_1
  - CKA_EXPONENT_2
  - CKA_COEEFICIENT
  
- **C_WrapKey**, **C_UnwrapKey**:
  - A wrapped key can get unwrapped only inside the enclave. It cannot be extracted to come out in the clear.
  - A key used for wrapping cannot be used for encryption or decryption.
  - If the key that is used for wrapping another key was used for encrypting data earlier, that encrypted data cannot be decrypted after the wrapping operation.
  - The key used to generate a quote can only be an RSA public key.
  - The key used to generate a quote cannot be created with CKA_TOKEN attribute set to true. It must be a session key object.
  - If CTK is built with ephemeral key for quote generation, the key (pair) will be destroyed after using the key for one unwrap operation.
  - The key used to generate a quote cannot be used for sign and verify operations in addition to encryption and decryption operations.

## Using Crypto API Toolkit

This section demonstrates how to use pkcs11-tool to create a token and an RSA keypair. The CTK build results in two shared object files: `libp11sgx.so` (untrusted) and `libp11SgxEnclave.signed.so` (trusted). The untrusted shared object (`lip11sgx.so` from the installation directory) should be used in the place of PKCS11 module for use with tools like pkcs11-tool.

### Creating a token
`$pkcs11-tool --module /usr/local/lib/libp11sgx.so --init-token --label "ctk" --slot 0 --so-pin 1234 --init-pin --pin 1234`

### Creating an RSA keypair
`$pkcs11-tool --module /usr/local/lib/libp11sgx.so --login --pin 1234 --id 0001 --token "ctk" --keypairgen --key-type rsa:3072 --label "cert-key" --usage-sign`

### Listing the objects
`$pkcs11-tool --module /usr/local/lib/libp11sgx.so --list-objects -login --pin 1234 --login-type user`