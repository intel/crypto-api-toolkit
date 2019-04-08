# Crypto API Toolkit for Intel(R) SGX

Crypto API Toolkit for Intel(R) SGX is an SDK for using the crypto capabilities in SGX with PKCS11 interface.

# Introduction

Crypto API Toolkit for Intel(R) SGX  aims at enhancing the security of ISVs’ and OEMs’ data protection applications by exposing enhanced and optimized interfaces that run the cryptographic operations securely within Intel(R) SGX. The operations are exposed and supported via PKCS11 interface for Linux.

# Dependencies/Prerequisites
Crypto API Toolkit for Intel(R) SGX depends on

## autotools (autoconf, automake, libtool)
 On CentOS, autotools can be installed with the command
 
```
sudo yum install autotools-latest
```

 On Ubuntu, autotools can be installed with the command

 ```
sudo apt-get install autoconf automake libtool
 ```
## g++ compiler with C++11 support
## Intel(R) SGX SDK for Linux.
 * The latest Intel(R) SGX SDK can be installed from <a href="https://01.org/intel-software-guard-extensions/downloads">https://01.org/intel-software-guard-extensions/downloads</a> for the operating systems supported.
 * Install the driver, libsgx-enclave-common and SDK in that order.
 * Please refer to <a href="https://download.01.org/intel-sgx/linux-2.5/docs/Intel_SGX_Installation_Guide_Linux_2.5_Open_Source.pdf">Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS Installation Guide</a>
## Intel(R) SGX SSL add-on
* Please download the Intel(R) SGX SSL from https://github.com/intel/intel-sgx-ssl, follow the instructions there to install it. Please note that the current release of Crypto API Toolkit for Intel(R) SGX has been validated with Intel(R) SGX SSL that uses OpenSSL version 1.1.1a.
* The build scripts have been configured to build with the release versions of SGX SSL libraries.

# Installation

## Configure
Configure the installation/compilation scripts:

```
sh ./autogen.sh
./configure
```

The build can be configured using the following additional options.

| Option        | Description |
| ----------- | ----------- |
| --prefix=/path-to-install/      | Sets the installation directory. Defaults to /usr/local/ if this option is not specified.       |
| --with-toolkit-path=/path-for-tokens/   | Sets the location for tokens to be created. Defaults to /opt/intel/cryptoapitoolkit/ if this option is not specified. |
| --with-sgxsdk=/path-to-sgxsdk-installation/ | The SGX SDK installation directory. Defaults to /opt/intel/sgxsdk/ if this option is not specified. |
| --with-sgxssl=/path-to-sgxssl-installation/ | The SGX SSL installation directory. Defaults to /opt/intel/sgxssl/ if this option is not specified. |
| --enable-import-raw-symkey-support= "yes" | Setting this option to ‘yes’ allows importing a data buffer (raw key import) into Crypto API Toolkit. |
| --enable-import-raw-symkey-support-for-hmac="yes" | Setting this option to ‘yes’ allows the use of raw key imported as the secret buffer for HMAC operations. |


After configuring, Crypto API Toolkit for Intel(R) SGX can be built with 
```
sudo make
```

## Install
The provider (untrusted) and the enclave (trusted) libraries can be installed with the command
```
sudo make install
```

## Uninstall
The provider (untrusted) and the enclave (trusted) libraries can be uninstalled with the command
```
sudo make uninstall
```

