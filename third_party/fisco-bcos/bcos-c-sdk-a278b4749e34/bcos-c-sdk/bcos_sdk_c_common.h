/*
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @file bcos_sdk_c_common.h
 * @author: octopus
 * @date 2021-12-15
 */

#ifndef __INCLUDE_BCOS_SDK_CONFIG__
#define __INCLUDE_BCOS_SDK_CONFIG__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// #define _BCOS_SDK_JNI_DEBUG_

#define BCOS_C_SDK_ECDSA_TYPE (0)
#define BCOS_C_SDK_SM_TYPE (1)

#ifdef __cplusplus
extern "C" {
#endif
//--------------- config items begin ----------------

/**
 * @brief: connect endpoint
 *
 */
struct bcos_sdk_c_endpoint
{
    char* host;  // c-style string，end with '\0', support: ipv4 / ipv6 / domain name
    uint16_t port;
};

/**
 * @brief cerf config for ssl connection
 */
struct bcos_sdk_c_cert_config
{
    char* ca_cert;  // cert and key should be in pem format
    char* node_key;
    char* node_cert;
};

/**
 * @brief cerf config for sm ssl connection
 */
struct bcos_sdk_c_sm_cert_config
{
    char* ca_cert;  // cert and key should be in pem format
    char* node_key;
    char* node_cert;
    char* en_node_key;
    char* en_node_cert;
};

/**
 * @brief bcos-c-sdk initialization config
 */
struct bcos_sdk_c_config
{
    // common config
    int thread_pool_size;
    int message_timeout_ms;
    int reconnect_period_ms;
    int heartbeat_period_ms;
    // enable send rpc request to the highest block number node, default: true
    int send_rpc_request_to_highest_block_node;

    // connected peers
    struct bcos_sdk_c_endpoint* peers;
    size_t peers_count;

    // the switch for disable ssl connection
    int disable_ssl;

    // ssl or sm_ssl
    char* ssl_type;
    // cert config items is the content of the cert or the path of the cert file
    int is_cert_path;
    // ssl connection cert, effective with ssl_type is 'ssl'
    struct bcos_sdk_c_cert_config* cert_config;
    // sm ssl connection cert, effective with ssl_type is 'sm_ssl'
    struct bcos_sdk_c_sm_cert_config* sm_cert_config;
};

enum transaction_version
{
    TRANSACTION_VERSION_0 = 0,
    /*
     * @brief enable (value,gasPrice,gasLimit,maxFeePerGas,maxPriorityFeePerGas) fields
     * @note version 1 transaction only supported in FISCO BCOS 3.6.0 and later
     */
    TRANSACTION_VERSION_1 = 1,
    /*
     * @brief enable (extension) fields
     * @note version 2 transaction only supported in FISCO BCOS 3.7.0 and later
     */
    TRANSACTION_VERSION_2 = 2,
};
/**
 * @brief create bcos_sdk_c_config in default value
 * @return struct bcos_sdk_c_config*
 */
struct bcos_sdk_c_config* bcos_sdk_c_config_create_empty(void);

/**
 * @brief duplicate string
 * @return char*
 */
char* my_strdup(const char* s);

/**
 * @brief create bcos_sdk_c_config
 * @return struct bcos_sdk_c_config*
 */
struct bcos_sdk_c_config* bcos_sdk_create_config(int sm_ssl, char* host, int port);

/**
 * @brief destroy config object, release resource of the object
 *
 * @param p: pointer to the bcos_sdk_c_config object
 */
void bcos_sdk_c_config_destroy(void* p);

void bcos_sdk_c_cert_config_destroy(void* p);
void bcos_sdk_c_sm_cert_config_destroy(void* p);

struct bcos_sdk_c_bytes* create_bytes_struct(uint32_t field_size, const char* field_data);
struct bcos_sdk_c_bytes* bytes_struct_copy(const struct bcos_sdk_c_bytes* bytes_struct_src);

//--------------- config items end ------------------------------

//--------------- callback begin---------------------------------

/**
 * @brief: response structure definition for asynchronous interface in c-sdk
 */
struct bcos_sdk_c_struct_response
{
    int error;   // response status, 0: success others failure
    char* desc;  // error message, effective in failure scenarios

    void* data;   // response buffer, effective in success scenarios
                  // !!! IMPORTANT: non threaded safe, if the data would be used in another
                  // thread, the user must copy it to it's own buffer for thread safe
    size_t size;  // response size, work with data

    void* context;  // callback context
};

/**
 * @brief: callback typedef
 *
 */
typedef void (*bcos_sdk_c_struct_response_cb)(struct bcos_sdk_c_struct_response* resp);

/**
 * @brief: handle response from c++ style interface, and return c style response to callback
 *
 * @param error: response error, pointer to Error::Ptr in cpp-sdk
 * @param data: response buffer, effective in success
 * @param size: response buffer size, effective in success
 * @param callback: callback in c stype
 * @param context: callback context
 */
void bcos_sdk_c_handle_response(
    void* error, void* data, size_t size, bcos_sdk_c_struct_response_cb callback, void* context);

/**
 * @brief free char* pointer
 * Note: The *p must be created by malloc or it may have serious bad effects
 *
 * @param p
 */
void bcos_sdk_c_free(void* p);

//--------------- callback end------------


//--------------- transaction begin---------------------------------

/**
 * @brief: signature result
 *
 */
struct bcos_sdk_c_signature_result
{
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v[512];
};

struct bcos_sdk_c_bytes
{
    uint8_t* buffer;
    uint32_t length;
};

/**
 * @brief: transaction data
 *
 */
struct bcos_sdk_c_transaction_data
{
    int32_t version;
    int64_t block_limit;
    char* chain_id;
    char* group_id;
    char* nonce;
    char* to;
    char* abi;
    struct bcos_sdk_c_bytes* input;
};

struct bcos_sdk_c_transaction_data_v1
{
    struct bcos_sdk_c_transaction_data base;
    char* value;
    char* gas_price;
    int64_t gas_limit;
    char* max_fee_per_gas;
    char* max_priority_fee_per_gas;
};

struct bcos_sdk_c_transaction_data_v2
{
    struct bcos_sdk_c_transaction_data_v1 base_v1;
    struct bcos_sdk_c_bytes* extension;
};

/**
 * @brief: transaction
 *
 */
struct bcos_sdk_c_transaction
{
    struct bcos_sdk_c_transaction_data* transaction_data;
    struct bcos_sdk_c_bytes* data_hash;
    struct bcos_sdk_c_bytes* signature;
    struct bcos_sdk_c_bytes* sender;
    int64_t import_time;
    int32_t attribute;
    char* extra_data;
};

struct bcos_sdk_c_transaction_v1
{
    struct bcos_sdk_c_transaction_data_v1* transaction_data;
    struct bcos_sdk_c_bytes* data_hash;
    struct bcos_sdk_c_bytes* signature;
    struct bcos_sdk_c_bytes* sender;
    int64_t import_time;
    int32_t attribute;
    char* extra_data;
};

struct bcos_sdk_c_transaction_v2
{
    struct bcos_sdk_c_transaction_data_v2* transaction_data;
    struct bcos_sdk_c_bytes* data_hash;
    struct bcos_sdk_c_bytes* signature;
    struct bcos_sdk_c_bytes* sender;
    int64_t import_time;
    int32_t attribute;
    char* extra_data;
};

//--------------- transaction end---------------------------------

#ifdef __cplusplus
}
#endif
#endif
