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
 * @file bcos_sdk_c_event_sub.h
 * @author: octopus
 * @date 2021-12-15
 */

#ifndef __INCLUDE_BCOS_SDK_EVENT__
#define __INCLUDE_BCOS_SDK_EVENT__

#include "bcos_sdk_c_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// ------------------------------event interface begin ----------------------

/**
 * @brief: subscribe event
 *
 * @param sdk: pointer to sdk, create by bcos_sdk_create or bcos_sdk_create_by_config_file
 * @param group: group id
 * @param params: params
 * @param callback: response callback, refer to bcos_sdk_c_struct_response_cb definition for defails
 * @param context: callback context
 * @return const char*: event sub task id, it can be used to unsubscribe the task
 */
const char* bcos_event_sub_subscribe_event(void* sdk, const char* group, const char* params,
    bcos_sdk_c_struct_response_cb callback, void* context);

/**
 * @brief: unsubscribe the event sub
 *
 * @param sdk
 * @param event_sub_id: the id id create by bcos_event_sub_subscribe_event
 */
void bcos_event_sub_unsubscribe_event(void* sdk, const char* event_sub_id);

// ------------------------------event interface end -------------------------

#ifdef __cplusplus
}
#endif
#endif
