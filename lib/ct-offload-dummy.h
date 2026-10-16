/*
 * Copyright (c) 2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CT_OFFLOAD_DUMMY_H
#define CT_OFFLOAD_DUMMY_H 1

#include "ct-offload.h"

/* Software-only CT offload provider used together with the dpif-offload
 * dummy provider.  It is registered when the matching "dummy" dpif offload
 * class is registered, and activated or deactivated by that provider
 * through ct_offload_open() and ct_offload_close(). */
extern const struct ct_offload_class ct_offload_dummy_class;

#endif /* CT_OFFLOAD_DUMMY_H */
