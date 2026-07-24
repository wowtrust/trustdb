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
 * @file bcos_sdk_c_amop.h
 * @author: octopus
 * @date 2021-12-15
 */

#ifndef __INCLUDE_BCOS_SDK_AMOP__
#define __INCLUDE_BCOS_SDK_AMOP__

#include "bcos_sdk_c_common.h"

#ifdef __cplusplus
extern "C" {
#endif

//------------------------- amop callback begin----------------------------
/**
 * @brief: callback for amop subscribe
 * @param endpoint:
 * @param seq:
 * @param resp:
 * @return void
 */
typedef void (*bcos_sdk_c_amop_subscribe_cb)(
    const char* endpoint, const char* seq, struct bcos_sdk_c_struct_response* resp);

/**
 * @brief: callback for amop publish
 * @param resp:
 * @return void
 */
typedef void (*bcos_sdk_c_amop_publish_cb)(struct bcos_sdk_c_struct_response* resp);
//------------------------- amop callback end -----------------------------

// -------------------------amop interface begin --------------------------

/**
 * @brief : subscribe amop topics
 *
 * @param sdk: pointer to sdk, create by bcos_sdk_create or bcos_sdk_create_by_config_file
 * @param topics: topics
 * @param count: topics count
 */
void bcos_amop_subscribe_topic(void* sdk, char** topics, size_t count);

/**
 * @brief : subscribe amop topic with callback
 *
 * @param sdk: pointer to sdk, create by bcos_sdk_create or bcos_sdk_create_by_config_file
 * @param topic: topic
 * @param cb: topic callback, when recv message with the topic, cb should be call
 * @param context:
 */
void bcos_amop_subscribe_topic_with_cb(
    void* sdk, const char* topic, bcos_sdk_c_amop_subscribe_cb cb, void* context);

/**
 * @brief: unsubscribe amop topics
 *
 * @param sdk: pointer to sdk, create by bcos_sdk_create or bcos_sdk_create_by_config_file
 * @param topics: topics
 * @param count: topics count
 */
void bcos_amop_unsubscribe_topic(void* sdk, char** topics, size_t count);

/**
 * @brief: publish amop message
 *
 * @param sdk: pointer to sdk, create by bcos_sdk_create or bcos_sdk_create_by_config_file
 * @param topic: publish the message with the topic
 * @param data: data buffer
 * @param size: data size
 * @param timeout: timeout for the message
 * @param cb: callback for the response
 * @param context
 */
void bcos_amop_publish(void* sdk, const char* topic, void* data, size_t size, uint32_t timeout,
    bcos_sdk_c_amop_publish_cb cb, void* context);

/**
 * @brief: broadcast message
 *
 * @param sdk: pointer to sdk, create by bcos_sdk_create or bcos_sdk_create_by_config_file
 * @param topic: broadcast the message with the topic
 * @param data: data buffer
 * @param size: data size
 */
void bcos_amop_broadcast(void* sdk, const char* topic, void* data, size_t size);

void bcos_amop_set_subscribe_topic_cb(void* sdk, bcos_sdk_c_amop_subscribe_cb cb, void* context);

void bcos_amop_send_response(
    void* sdk, const char* peer, const char* seq, void* data, size_t size);

// -------------------------- amop interface end ----------------------------
#ifdef __cplusplus
}
#endif
#endif
