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
 * @file bcos_sdk_c_error.h
 * @author: octopus
 * @date 2021-12-15
 */

#ifndef __INCLUDE_BCOS_SDK_C_ERROR__
#define __INCLUDE_BCOS_SDK_C_ERROR__

#ifdef __cplusplus
extern "C" {
#endif

#define BCOS_SDK_C_PARAMS_VERIFY_CONDITION(p, msg, r) \
    do                                                \
    {                                                 \
        if (!(p))                                     \
        {                                             \
            bcos_sdk_set_last_error_msg(-1, msg);     \
            return r;                                 \
        }                                             \
    } while (0);

#define BCOS_SDK_C_PARAMS_VERIFICATION(p, r)                                      \
    do                                                                            \
    {                                                                             \
        if (!p)                                                                   \
        {                                                                         \
            bcos_sdk_set_last_error_msg(-1, "illegal parameter, " #p " is NULL"); \
            return r;                                                             \
        }                                                                         \
    } while (0);

#define BCOS_SDK_C_SUCCESS (0)

/**
 * @brief the last sync operation success or not
 *  Note: thread safe operation
 *
 * @return int
 */
extern int bcos_sdk_is_last_opr_success(void);

/**
 * @brief gets status of the recent sync operation
 *  Note: thread safe operation
 *
 * @return int
 */
extern int bcos_sdk_get_last_error(void);

/**
 * @brief gets error message of the recent sync operation, effect if bcos_sdk_get_last_error,
 * return not zero
 * Note: thread safe operation
 *
 * @return const char*
 */
extern const char* bcos_sdk_get_last_error_msg(void);

/**
 * @brief clear the last error
 */
extern void bcos_sdk_clear_last_error(void);

/**
 * @brief set the last error and error message
 */
extern void bcos_sdk_set_last_error_msg(int error, const char* msg);

#ifdef __cplusplus
}
#endif
#endif
