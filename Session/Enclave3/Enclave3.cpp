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


// Enclave3.cpp : Defines the exported functions for the DLL application
#include "sgx_eid.h"
#include "Enclave3_t.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E3.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include <map>

#define UNUSED(val) (void)(val)

param_struct_t keymap[10];

std::map<sgx_enclave_id_t, dh_session_t>g_src_session_info_map;

void putkey(uint8_t *keyvalue, int keyvalue_len, int item) {
    keymap[item].len = keyvalue_len;
    memcpy(keymap[item].Value, keyvalue, keyvalue_len);
}

void getkey(uint8_t **keyvalue, int *len, int item) {

  *keyvalue = new uint8_t [keymap[item].len];
  memcpy(*keyvalue, keymap[item].Value, keymap[item].len);
  *len = keymap[item].len;
}

static uint32_t e3_foo1_wrapper(ms_in_msg_exchange_t *ms, size_t param_lenth, char** resp_buffer, size_t* resp_length);

//Function pointer table containing the list of functions that the enclave exposes
const struct {
    size_t num_funcs;
    const void* table[1];
} func_table = {
    1,
    {
        (const void*)e3_foo1_wrapper,
    }
};

extern "C" uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
    {
        return ENCLAVE_TRUST_ERROR;
    }
    else
    {
        return SUCCESS;
    }
}


//Dispatch function that calls the approriate enclave function based on the function id
//Each enclave can have its own way of dispatching the calls from other enclave
extern "C" uint32_t enclave_to_enclave_call_dispatcher(char* decrypted_data,
                                                       size_t decrypted_data_length,
                                                       char** resp_buffer,
                                                       size_t* resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t (*fn1)(ms_in_msg_exchange_t *ms, size_t, char**, size_t*);
    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;
    if(ms->target_fn_id >= func_table.num_funcs)
    {
        return INVALID_PARAMETER_ERROR;
    }
    fn1 = (uint32_t (*)(ms_in_msg_exchange_t*, size_t, char**, size_t*))func_table.table[ms->target_fn_id];
    return fn1(ms, decrypted_data_length, resp_buffer, resp_length);
}

//Operates on the input secret and generates the output secret
uint32_t get_message_exchange_response(uint32_t inp_secret_data)
{
    uint32_t secret_response;

    //User should use more complex encryption method to protect their secret, below is just a simple example
    secret_response = inp_secret_data & 0x11111111;

    return secret_response;

}
//Generates the response from the request message

extern "C" uint32_t message_exchange_response_generator(char* decrypted_data,
                                              char** resp_buffer,
                                              size_t* resp_length)
{
    ms_in_msg_exchange_t *ms;
    uint32_t inp_secret_data;
    uint32_t out_secret_data;
    if(!decrypted_data || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    ms = (ms_in_msg_exchange_t *)decrypted_data;

    if(umarshal_message_exchange_request(&inp_secret_data,ms) != SUCCESS)
        return ATTESTATION_ERROR;

    out_secret_data = get_message_exchange_response(inp_secret_data);

    if(marshal_message_exchange_response(resp_buffer, resp_length, out_secret_data) != SUCCESS)
        return MALLOC_ERROR;

    return SUCCESS;

}



static uint32_t e3_foo1(param_struct_t *p_struct_var)
{
    if(!p_struct_var)
    {
        return INVALID_PARAMETER_ERROR;
    }
    int key_opt = p_struct_var->getkey;
    int item = p_struct_var->len;
    if (key_opt) {
        memcpy(p_struct_var->Value, keymap[item].Value, keymap[item].len);
        p_struct_var->len=keymap[item].len;
    }
    else {
        keymap[item].len = KEY_LEN;
        memcpy(keymap[item].Value, p_struct_var->Value, KEY_LEN);
    }
    return keymap[item].len;
}

//Function which is executed on request from the source enclave
static uint32_t e3_foo1_wrapper(ms_in_msg_exchange_t *ms,
                    size_t param_lenth,
                    char** resp_buffer,
                    size_t* resp_length)
{
    UNUSED(param_lenth);
    uint32_t ret;
    param_struct_t *p_struct_var;
    if(!ms || !resp_length)
    {
        return INVALID_PARAMETER_ERROR;
    }
    p_struct_var = (param_struct_t*)malloc(sizeof(param_struct_t));
    if(!p_struct_var)
        return MALLOC_ERROR;
    if(unmarshal_input_parameters_e3_foo1(p_struct_var, ms) != SUCCESS)
    {
        SAFE_FREE(p_struct_var);
        return ATTESTATION_ERROR;
    }
    ret = e3_foo1(p_struct_var);
    if(marshal_retval_and_output_parameters_e3_foo1(resp_buffer, resp_length, ret, p_struct_var) != SUCCESS)
    {
        SAFE_FREE(p_struct_var);
        return MALLOC_ERROR;
    }
    SAFE_FREE(p_struct_var);
    return SUCCESS;
}
