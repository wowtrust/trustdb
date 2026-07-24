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
 * @file bcos_sdk_c.h
 * @author: octopus
 * @date 2021-12-15
 */

#ifndef __INCLUDE_BCOS_SDK__
#define __INCLUDE_BCOS_SDK__

#if defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN32_)
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#include "bcos_sdk_c_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief: obtain the c-sdk version information
 *
 * @return const char*
 */
const char* bcos_sdk_version(void);

/**
 * @brief: create bcos sdk object by config object
 *
 * @param config: config for sdk, refer to the bcos_sdk_c_config definition
 * @return void*: pointer to sdk object, to call the sdk interface
 * Note: if a null pointer is returned,bcos_sdk_get_last_error and bcos_sdk_get_last_error_msg can
 * be used to get the error code and error message
 */
void* bcos_sdk_create(struct bcos_sdk_c_config* config);

/**
 * @brief: create bcos sdk object by config file
 *
 * @param config_file: config file, refer to sample/config/config_sample.ini for details
 * @return void*: pointer to sdk object, to call the sdk interface
 */
void* bcos_sdk_create_by_config_file(const char* config_file);

/**
 * @brief: start the bcos sdk
 *
 * @param sdk: pointer to sdk, create by bcos_sdk_create or bcos_sdk_create_by_config_file
 * @return:
 * Note: bcos_sdk_get_last_error can be used to check whether the start operation is success or not
 */
void bcos_sdk_start(void* sdk);

/**
 * @brief: stop the sdk
 *
 * @param sdk
 */
void bcos_sdk_stop(void* sdk);

/**
 * @brief: stop and release the resource of sdk
 *
 * @param sdk
 */
void bcos_sdk_destroy(void* sdk);

// --------------------------------------------------------------------
/**
 * @brief: register default block notifier
 *
 * @param sdk
 * @param group
 * @param context
 * @param callback
 */
void bcos_sdk_register_block_notifier(void* sdk, const char* group, void* context,
    void (*callback)(const char* group, int64_t block_number, void* context));
// --------------------------------------------------------------------

// --------------------------------------------------------------------

/**
 * @brief: query group wasm && sm crypto info
 *
 * @param sdk: c sdk object pinter
 * @param group: group id
 * @param wasm: if the group runs the WASM contract engine
 *          0: No, 1: Yes
 * @param sm_crypto: if the group runs sm cryptography component
 *          0: No sm, 1: Yes
 */
void bcos_sdk_get_group_wasm_and_crypto(void* sdk, const char* group, int* wasm, int* sm_crypto);

/**
 * @brief: query chain id of the group
 *
 * @param sdk: c sdk object pinter
 * @param group: group id
 * @return const char* : chain id
 */
const char* bcos_sdk_get_group_chain_id(void* sdk, const char* group);

uint32_t bcos_sdk_get_local_protocol_info(void* sdk);

uint32_t bcos_sdk_get_negotiated_protocol_info(void* sdk);
// --------------------------------------------------------------------

#ifdef __cplusplus
}
#endif
#endif
