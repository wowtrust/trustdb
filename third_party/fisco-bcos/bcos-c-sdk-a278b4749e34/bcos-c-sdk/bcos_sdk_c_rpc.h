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
 * @file bcos_sdk_c_rpc.h
 * @author: octopus
 * @date 2021-12-15
 */

#ifndef __INCLUDE_BCOS_SDK_RPC__
#define __INCLUDE_BCOS_SDK_RPC__

#include "bcos_sdk_c_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BCOS_SDK_C_RPC_PARAMS_VERIFICATION(p, ctx, cb)                  \
    do                                                                  \
    {                                                                   \
        if (!p)                                                         \
        {                                                               \
            if (cb)                                                     \
            {                                                           \
                bcos_sdk_c_struct_response resp;                        \
                resp.error = -1;                                        \
                resp.desc = (char*)"illegal parameter, " #p " is NULL"; \
                resp.ctx = ctx;                                         \
                cb(&resp);                                              \
            }                                                           \
            return;                                                     \
        }                                                               \
    } while (0);


/**
 *  these are rpc interfaces
 */

// ------------------------common send message interface begin----------------
// send message to rpc server
void bcos_rpc_generic_method_call(
    void* sdk, const char* data, bcos_sdk_c_struct_response_cb callback, void* context);

// send message to group
void bcos_rpc_generic_method_call_to_group(void* sdk, const char* group, const char* data,
    bcos_sdk_c_struct_response_cb callback, void* context);

// send message to group of node
void bcos_rpc_generic_method_call_to_group_node(void* sdk, const char* group, const char* node,
    const char* data, bcos_sdk_c_struct_response_cb callback, void* context);
// ------------------------common send message interface end----------------

// ------------------------------rpc interface begin -------------------------
// call
void bcos_rpc_call(void* sdk, const char* group, const char* node, const char* to, const char* data,
    bcos_sdk_c_struct_response_cb callback, void* context);

// sendTransaction
void bcos_rpc_send_transaction(void* sdk, const char* group, const char* node, const char* data,
    int proof, bcos_sdk_c_struct_response_cb callback, void* context);

// getTransaction
void bcos_rpc_get_transaction(void* sdk, const char* group, const char* node, const char* tx_hash,
    int proof, bcos_sdk_c_struct_response_cb callback, void* context);

// getTransactionReceipt
void bcos_rpc_get_transaction_receipt(void* sdk, const char* group, const char* node,
    const char* tx_hash, int proof, bcos_sdk_c_struct_response_cb callback, void* context);

// getBlockByHash
void bcos_rpc_get_block_by_hash(void* sdk, const char* group, const char* node,
    const char* block_hash, int only_header, int only_tx_hash,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getBlockByNumber
void bcos_rpc_get_block_by_number(void* sdk, const char* group, const char* node,
    int64_t block_number, int only_header, int only_tx_hash, bcos_sdk_c_struct_response_cb callback,
    void* context);

// getBlockHashByNumber
void bcos_rpc_get_block_hash_by_number(void* sdk, const char* group, const char* node,
    int64_t block_number, bcos_sdk_c_struct_response_cb callback, void* context);

// getBlockLimit
int64_t bcos_rpc_get_block_limit(void* sdk, const char* group);

// getBlockNumber
void bcos_rpc_get_block_number(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getCode
void bcos_rpc_get_code(void* sdk, const char* group, const char* node, const char* address,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getSealerList
void bcos_rpc_get_sealer_list(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getObserverList
void bcos_rpc_get_observer_list(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getPbftView
void bcos_rpc_get_pbft_view(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getPendingTxSize
void bcos_rpc_get_pending_tx_size(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getSyncStatus
void bcos_rpc_get_sync_status(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getConsensusStatus
void bcos_rpc_get_consensus_status(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getSystemConfigByKey
void bcos_rpc_get_system_config_by_key(void* sdk, const char* group, const char* node,
    const char* key, bcos_sdk_c_struct_response_cb callback, void* context);

// getTotalTransactionCount
void bcos_rpc_get_total_transaction_count(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// getGroupPeers
void bcos_rpc_get_group_peers(
    void* sdk, const char* group, bcos_sdk_c_struct_response_cb callback, void* context);

// getPeers
void bcos_rpc_get_peers(void* sdk, bcos_sdk_c_struct_response_cb callback, void* context);

// getGroupList
void bcos_rpc_get_group_list(void* sdk, bcos_sdk_c_struct_response_cb callback, void* context);

// getGroupInfo
void bcos_rpc_get_group_info(
    void* sdk, const char* group, bcos_sdk_c_struct_response_cb callback, void* context);

// getGroupInfoList
void bcos_rpc_get_group_info_list(void* sdk, bcos_sdk_c_struct_response_cb callback, void* context);

// getGroupNodeInfo
void bcos_rpc_get_group_node_info(void* sdk, const char* group, const char* node,
    bcos_sdk_c_struct_response_cb callback, void* context);

// ------------------------------rpc interface end -------------------------

#ifdef __cplusplus
}
#endif
#endif
