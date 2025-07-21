/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include "../Enclave2/Enclave2_u.h"
#include "../Enclave3/Enclave3_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <iostream>
#include "apptest.h"
#include "sgx_utils/sgx_utils.h"
#include <string>


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;

uint32_t enclave_temp_no=0;

sgx_enclave_id_t e2_enclave_id = 2;
sgx_enclave_id_t e3_enclave_id = 3;


#define ENCLAVE2_PATH "/root/Desktop/tee_git/Integrate/Session/libenclave2.so"
#define ENCLAVE3_PATH "/root/Desktop/tee_git/Integrate/Session/libenclave3.so"

void ocall_print_string(char *str)
{
    printf("%s\n", str);
}

void ocall_print_number(int num)
{
    printf("the uint32_t number: %d\n", num);
}


void waitForKeyPress()
{
    char ch;
    int temp;
    printf("\n\nHit a key....\n");
    temp = scanf_s("%c", &ch);
}

int ocall_decryptkeyring(char *path, uint8_t *keyvalue, uint8_t *cipher, uint8_t *plaintext, int path_len, int keyvalue_len, int cipher_len, int plain_len) {
    if (initialize_enclave(&e2_enclave_id, "enclave.token", ENCLAVE2_PATH) < 0) {
        std::cerr << "Fail to initialize enclave." << std::endl;
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_status_t status = SGX_SUCCESS;
    uint32_t ret_status;
    status = Enclave2_decryptkeyring(e2_enclave_id, &ret_status, path, keyvalue, cipher, plaintext, path_len, keyvalue_len, cipher_len, plain_len);
    if (status != SGX_SUCCESS) {
        std::cerr << "Enclave have not called sucessfully" << std::endl;
        return 1;
    }
    sgx_destroy_enclave(e2_enclave_id);
    return 0;
}

int ocall_encryptkeyring(char *path, uint32_t term, uint8_t *keyvalue, uint8_t *plain, uint8_t *ciphertext, int path_len, int keyvalue_len, int plain_len, int cipher_len) {
    if (initialize_enclave(&e2_enclave_id, "enclave.token", ENCLAVE2_PATH) < 0) {
        std::cerr << "Fail to initialize enclave." << std::endl;
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_status_t status = SGX_SUCCESS;
    uint32_t ret_status;
    status = Enclave2_encryptkeyring(e2_enclave_id, &ret_status, path, term, keyvalue, plain, ciphertext,  path_len, keyvalue_len, plain_len, cipher_len);
    if (status != SGX_SUCCESS) {
        std::cerr << "Enclave have not called sucessfully" << std::endl;
        return 1;
    }
    sgx_destroy_enclave(e2_enclave_id);
    return 0;
}

int ocall_decrypt_store_keyring(char *path, uint8_t *keyvalue, uint8_t *cipher, uint8_t *plaintext, int path_len, int keyvalue_len, int cipher_len, int plain_len, int *term) {
    if (initialize_enclave(&e2_enclave_id, "enclave.token", ENCLAVE2_PATH) < 0) {
        std::cerr << "Fail to initialize enclave." << std::endl;
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    if (sgx_ret != SGX_SUCCESS) {
        std::cerr << "Enclave have not called sucessfully" << std::endl;
        return 1;
    }

    if (e3_enclave_id == 3) {
        if (initialize_enclave(&e3_enclave_id, "enclave.token", ENCLAVE3_PATH) < 0) {
            std::cerr << "Fail to initialize enclave." << std::endl;
            return SGX_ERROR_UNEXPECTED;
        }
        g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e3_enclave_id, 3));
    }
    uint32_t ret_status;

    status = Enclave2_create_local_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
    if (status!=SGX_SUCCESS)
    {
        printf("Enclave2_create_local_session Ecall failed: Error code is %x", status);
        return 1;
    }
    else
    {
        if(ret_status!=0)
        {
            std::cerr <<"\n\nSession establishment and key exchange failure between Source (E2) and Destination (E3): Error code is"<< std::endl;
            return 1;
        }
    }


    status = Enclave2_decrypt_store_keyring_call(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id, path, keyvalue, cipher, plaintext, path_len, keyvalue_len, cipher_len, plain_len, term);


    if (status!=SGX_SUCCESS)
    {
        printf("Enclave2_decrypt_store_keyring_call Ecall failed: Error code is %x", status);
        return 1;
    }
    else
    {
        if(ret_status!=0)
        {
            printf("\n\nEnclave to Enclave Call failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
            return 1;
        }
    }
    
    status = Enclave2_close_local_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
    if (status!=SGX_SUCCESS)
    {
        printf("Enclave2_close_local_session Ecall failed: Error code is %x", status);
        return 1;
    }
    else
    {
        if(ret_status!=0)
        {
            printf("\n\nClose session failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
            return 1;
        }
    }

    sgx_destroy_enclave(e2_enclave_id);
    return 0;

}

int ocall_crypto(char *path, uint32_t term, uint8_t *plaintext, uint8_t *ciphertext, int path_len, int plain_len, int cipher_len, int encryptmode) {
    
    if (initialize_enclave(&e2_enclave_id, "enclave.token", ENCLAVE2_PATH) < 0) {
        std::cerr << "Fail to initialize enclave." << std::endl;
        return SGX_ERROR_UNEXPECTED;
    }
    sgx_status_t sgx_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    if (sgx_ret != SGX_SUCCESS) {
        std::cerr << "Enclave have not called sucessfully" << std::endl;
        return 1;
    }
    
    //Create session between Enclave2(Source) and Enclave3(Destination)
    uint32_t ret_status;
    status = Enclave2_create_local_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
    if (status!=SGX_SUCCESS)
    {
        printf("Enclave2_create_local_session Ecall failed: Error code is %x", status);
        return 1;
    }
    else
    {
        if(ret_status!=0)
        {
            std::cerr <<"\n\nSession establishment and key exchange failure between Source (E2) and Destination (E3): Error code is"<< std::endl;
            return 1;
        }
    }
    //Enclave to Enclave call between Enclave2(Source) and Enclave3(Destination)
    status = Enclave2_retrieve_encryptionkey_and_crypto_call(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id, path, term, plaintext, ciphertext,  path_len, plain_len, cipher_len, encryptmode);
    if (status!=SGX_SUCCESS)
    {
        printf("Enclave2_retrieve_encryptionkey_and_crypto_call Ecall failed: Error code is %x", status);
        return 1;
    }
    else
    {
        if(ret_status!=0)
        {
            printf("\n\nEnclave to Enclave Call failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
            return 1;
        }
    }
    status = Enclave2_close_local_session(e2_enclave_id, &ret_status, e2_enclave_id, e3_enclave_id);
    if (status!=SGX_SUCCESS)
    {
        printf("Enclave2_close_local_session Ecall failed: Error code is %x", status);
        return 1;
    }
    else
    {
        if(ret_status!=0)
        {
            printf("\n\nClose session failure between Source (E2) and Destination (E3): Error code is %x", ret_status);
            return 1;
        }
    }
    sgx_destroy_enclave(e2_enclave_id);
    return 0;
}


