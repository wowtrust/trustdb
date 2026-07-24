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
 * @file bcos_sdk_c_util_tx.h
 * @author: octopus
 * @date 2022-01-17
 */

#ifndef __INCLUDE_BCOS_SDK_C_UTIL_TX__
#define __INCLUDE_BCOS_SDK_C_UTIL_TX__

#include "bcos_sdk_c_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief
 *
 * @param group_id
 * @param chain_id
 * @param to
 * @param data
 * @param abi
 * @param block_limit
 * @return void*
 */
void* bcos_sdk_create_transaction_data(const char* group_id, const char* chain_id, const char* to,
    const char* data, const char* abi, int64_t block_limit);

/**
 * @param json
 *              version:number
 *              groupID:string
 *              chainID:string
 *              to:string
 *              data:hex string
 *              abi:string
 *              blockLimit:number
 *              nonce:string
 * @return void*
 */
void* bcos_sdk_create_transaction_data_with_json(const char* json);

/**
 * @brief
 *
 * @param transaction_data
 */
void bcos_sdk_destroy_transaction_data(void* transaction_data);

/**
 * @brief
 *
 * @param transaction_data
 * @return const char*
 */
const char* bcos_sdk_encode_transaction_data(void* transaction_data);

/**
 * @brief
 *
 * @param transaction_data
 * @return const char*
 */
const char* bcos_sdk_decode_transaction_data(const char* transaction_bytes);

/**
 * @brief
 *
 * @param crypto_type: int
 * @param transaction_data: void*
 * @return const char*
 */
const char* bcos_sdk_calc_transaction_data_hash(int crypto_type, void* transaction_data);

/**
 * @brief
 *
 * @param keypair
 * @param transcation_hash
 * @return const char*
 */
const char* bcos_sdk_sign_transaction_data_hash(void* keypair, const char* transcation_hash);

/**
 * @brief
 *
 * @param key_pair
 * @param group_id
 * @param chain_id
 * @param to
 * @param data
 * @param abi
 * @param block_limit
 * @param attribute
 * @param tx_hash
 * @param signed_tx
 * @return void*
 */
void bcos_sdk_create_signed_transaction(void* key_pair, const char* group_id, const char* chain_id,
    const char* to, const char* data, const char* abi, int64_t block_limit, int32_t attribute,
    char** tx_hash, char** signed_tx);

/**
 * @brief
 *
 * @param key_pair
 * @param group_id
 * @param chain_id
 * @param to
 * @param data
 * @param abi
 * @param block_limit
 * @param attribute
 * @param extra_data
 * @param tx_hash
 * @param signed_tx
 * @return void
 */
void bcos_sdk_create_signed_transaction_ver_extra_data(void* key_pair, const char* group_id,
    const char* chain_id, const char* to, const char* data, const char* abi, int64_t block_limit,
    int32_t attribute, const char* extra_data, char** tx_hash, char** signed_tx);

/**
 * @brief
 *
 * @param transaction_data: void*
 * @param signature
 * @param transaction_data_hash
 * @param attribute
 * @return const char*
 */
const char* bcos_sdk_create_signed_transaction_with_signed_data(void* transaction_data,
    const char* signature, const char* transaction_data_hash, int32_t attribute);

/**
 * @brief
 *
 * @param transaction_data: void*
 * @param signature
 * @param transaction_data_hash
 * @param attribute
 * @param extra_data
 * @return const char*
 */
const char* bcos_sdk_create_signed_transaction_with_signed_data_ver_extra_data(
    void* transaction_data, const char* signature, const char* transaction_data_hash,
    int32_t attribute, const char* extra_data);


/**
 * @brief Decode transaction hex string to Transaction object raw pointer
 * @param transaction_bytes encoded transaction hex string
 * @return Transaction object pointer
 */
void* bcos_sdk_decode_transaction(const char* transaction_bytes);

/**
 * @brief Decode transaction hex string to Transaction object json string
 * @param transaction_bytes encoded transaction hex string
 * @return Transaction object json string
 */
const char* bcos_sdk_decode_transaction_to_json_obj(const char* transaction_bytes);

/**
 * @brief Destroy transaction object
 *
 * @param transaction transaction object pointer
 */
void bcos_sdk_destroy_transaction(void* transaction);

/**
 * @brief
 *
 * @param sdk
 * @param group_id
 * @return void*
 */
void* bcos_sdk_create_transaction_builder_service(void* sdk, const char* group_id);

/**
 * @brief
 *
 * @param sdk
 * @param group_id
 * @return void*
 */
void bcos_sdk_destroy_transaction_builder_service(void* service);

/**
 * @brief
 * @param tx_builder_service
 * @param to
 * @param data
 * @param abi
 * @return void*
 */
void* bcos_sdk_create_transaction_data_with_tx_builder_service(
    void* tx_builder_service, const char* to, const char* data, const char* abi);

/**
 * @brief
 *
 * @param tx_builder_service
 * @param key_pair
 * @param to
 * @param data
 * @param abi
 * @param attribute
 * @param tx_hash
 * @param signed_tx
 * @return void*
 */
void bcos_sdk_create_signed_transaction_with_tx_builder_service(void* tx_builder_service,
    void* key_pair, const char* to, const char* data, const char* abi, int32_t attribute,
    char** tx_hash, char** signed_tx);

/**
 * @brief
 *
 * @param tx_builder_service
 * @param key_pair
 * @param to
 * @param data
 * @param abi
 * @param attribute
 * @param extra_data
 * @param tx_hash
 * @param signed_tx
 * @return void*
 */
void bcos_sdk_create_signed_transaction_with_tx_builder_service_ver_extra_data(
    void* tx_builder_service, void* key_pair, const char* to, const char* data, const char* abi,
    int32_t attribute, const char* extra_data, char** tx_hash, char** signed_tx);

#ifdef __cplusplus
}
#endif
#endif
