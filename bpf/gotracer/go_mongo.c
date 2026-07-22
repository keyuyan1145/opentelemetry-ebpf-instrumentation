// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build obi_bpf_ignore

#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/ringbuf.h>

#include <gotracer/go_common.h>
#include <gotracer/go_str.h>

#include <gotracer/maps/mongo.h>

#include <logger/bpf_dbg.h>

#include <shared/obi_ctx.h>

#define MONGO_OP_DEF(name, str)                                                                    \
    static const char name[] = str;                                                                \
    static const u32 name##_size = sizeof(name) - 1;

MONGO_OP_DEF(insert, "insert")
MONGO_OP_DEF(delete, "delete")
MONGO_OP_DEF(find, "find")
MONGO_OP_DEF(drop, "drop")
MONGO_OP_DEF(findAndModify, "findAndModify")
MONGO_OP_DEF(updateOrReplace, "updateOrReplace")
MONGO_OP_DEF(aggregate, "aggregate")
MONGO_OP_DEF(countDocuments, "countDocuments")
MONGO_OP_DEF(estimatedDocumentCount, "estimatedDocumentCount")
MONGO_OP_DEF(distinct, "distinct")

// Extracts the MongoDB server address from the Operation.Deployment pointer chain.
// Follows: Operation.Deployment (interface) → *topology.Topology → cfg (*Config) → SeedList[0] (string)
// SeedList[0] is the first address from the connection URI, e.g. "mongo:27017".
// Returns true if the hostname was written to req->hostname.
static __always_inline bool
read_mongo_hostname_from_operation(void *op_ptr, off_table_t *ot, mongo_go_client_req_t *req) {
    bpf_dbg_printk("=== read_mongo_hostname_from_operation op_ptr=%llx ===", op_ptr);

    // Step 1: Read the interface data pointer from Operation.Deployment.
    // A Go interface is {itab ptr (8 bytes), data ptr (8 bytes)}.
    // We want the data ptr, which is 8 bytes past the start of the interface field.
    u64 deployment_offset = go_offset_of(ot, (go_offset){.v = _mongo_deployment_pos});
    bpf_dbg_printk("step1: deployment_offset=%llu", deployment_offset);
    if (!deployment_offset) {
        bpf_dbg_printk("step1 failed: can't find mongo deployment offset");
        return false;
    }
    void *topology_ptr = NULL;
    if (bpf_probe_read(&topology_ptr, sizeof(topology_ptr),
                       (void *)((u64)op_ptr + deployment_offset + 8))) {
        bpf_dbg_printk("step1 failed: can't read mongo Operation.Deployment data ptr");
        return false;
    }
    if (!topology_ptr) {
        bpf_dbg_printk("step1 failed: topology_ptr is NULL");
        return false;
    }
    bpf_dbg_printk("step1 ok: topology_ptr=%llx", topology_ptr);

    // Step 2: Read topology.Topology.cfg (*Config pointer).
    u64 cfg_offset = go_offset_of(ot, (go_offset){.v = _mongo_topo_cfg_pos});
    bpf_dbg_printk("step2: cfg_offset=%llu", cfg_offset);
    if (!cfg_offset) {
        bpf_dbg_printk("step2 failed: can't find mongo topology cfg offset");
        return false;
    }
    void *cfg_ptr = NULL;
    if (bpf_probe_read(&cfg_ptr, sizeof(cfg_ptr),
                       (void *)((u64)topology_ptr + cfg_offset))) {
        bpf_dbg_printk("step2 failed: can't read mongo topology.cfg");
        return false;
    }
    if (!cfg_ptr) {
        bpf_dbg_printk("step2 failed: cfg_ptr is NULL");
        return false;
    }
    bpf_dbg_printk("step2 ok: cfg_ptr=%llx", cfg_ptr);

    // Step 3: Read the array pointer from Config.SeedList slice header.
    // A Go slice is {array ptr (8 bytes), len (8 bytes), cap (8 bytes)}.
    // The array ptr is the first word of the slice header.
    u64 seedlist_offset = go_offset_of(ot, (go_offset){.v = _mongo_cfg_seedlist_pos});
    bpf_dbg_printk("step3: seedlist_offset=%llu", seedlist_offset);
    if (!seedlist_offset) {
        bpf_dbg_printk("step3 failed: can't find mongo cfg seedlist offset");
        return false;
    }
    void *seedlist_array_ptr = NULL;
    if (bpf_probe_read(&seedlist_array_ptr, sizeof(seedlist_array_ptr),
                       (void *)((u64)cfg_ptr + seedlist_offset))) {
        bpf_dbg_printk("step3 failed: can't read mongo cfg.SeedList array ptr");
        return false;
    }
    if (!seedlist_array_ptr) {
        bpf_dbg_printk("step3 failed: seedlist_array_ptr is NULL");
        return false;
    }
    bpf_dbg_printk("step3 ok: seedlist_array_ptr=%llx", seedlist_array_ptr);

    // Step 4: Read SeedList[0] — the first string in the array (offset 0).
    // A Go string is {ptr (8 bytes), len (8 bytes)}, so offset 0 is the first string's ptr.
    if (!read_go_str("server addr", seedlist_array_ptr, 0,
                     req->hostname, sizeof(req->hostname))) {
        bpf_dbg_printk("step4 failed: can't read mongodb server address from SeedList[0]");
        return false;
    }
    bpf_dbg_printk("step4 ok: hostname=%s", req->hostname);

    return true;
}

static __always_inline int
obi_uprobe_mongo_coll_op(struct pt_regs *ctx, const char *op, const u32 op_len) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *coll_ptr = (void *)GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    mongo_go_client_req_t req = {0};
    req.type = EVENT_GO_MONGO;
    req.start_monotime_ns = bpf_ktime_get_ns();

    if (!read_go_str("name",
                     coll_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_conn_name_pos}),
                     &req.coll,
                     sizeof(req.coll))) {
        bpf_dbg_printk("can't read mongodb Collection.name");
        return 0;
    }

    __builtin_memcpy(req.op, op, op_len);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    client_trace_parent(goroutine_addr, &req.tp);

    bpf_d_printk("op=%s, [%s]", req.op, __FUNCTION__);

    bpf_map_update_elem(&ongoing_mongo_requests, &g_key, &req, BPF_ANY);

    obi_ctx__set(bpf_get_current_pid_tgid(), &req.tp);

    return 0;
}

SEC("uprobe/op_coll_insert")
int obi_uprobe_mongo_op_insert(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, insert, insert_size);
}

SEC("uprobe/op_coll_delete")
int obi_uprobe_mongo_op_delete(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, delete, delete_size);
}

SEC("uprobe/op_coll_find")
int obi_uprobe_mongo_op_find(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, find, find_size);
}

SEC("uprobe/op_coll_drop")
int obi_uprobe_mongo_op_drop(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, drop, drop_size);
}

SEC("uprobe/op_coll_findAndModify")
int obi_uprobe_mongo_op_findAndModify(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, findAndModify, findAndModify_size);
}

SEC("uprobe/op_coll_updateOrReplace")
int obi_uprobe_mongo_op_updateOrReplace(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, updateOrReplace, updateOrReplace_size);
}

SEC("uprobe/op_coll_aggregate")
int obi_uprobe_mongo_op_aggregate(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, aggregate, aggregate_size);
}

SEC("uprobe/op_coll_countDocuments")
int obi_uprobe_mongo_op_countDocuments(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, countDocuments, countDocuments_size);
}

SEC("uprobe/op_coll_estimatedDocumentCount")
int obi_uprobe_mongo_op_estimatedDocumentCount(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, estimatedDocumentCount, estimatedDocumentCount_size);
}

SEC("uprobe/op_coll_distinct")
int obi_uprobe_mongo_op_distinct(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, distinct, distinct_size);
}

// go.mongodb.org/mongo-driver/x/mongo/driver.Operation.Execute
// func (op Operation) Execute(ctx context.Context) error
SEC("uprobe/op_execute")
int obi_uprobe_mongo_op_execute(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/op_execute ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *op_ptr = (void *)PT_REGS_SP(ctx) + 8;
    off_table_t *ot = get_offsets_table();

    mongo_go_client_req_t fresh_req = {0};
    fresh_req.type = EVENT_GO_MONGO;
    fresh_req.start_monotime_ns = bpf_ktime_get_ns();

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);

    if (!req) {
        client_trace_parent(goroutine_addr, &fresh_req.tp);
        req = &fresh_req;
    }

    if (!req) {
        return 0;
    }

    bpf_dbg_printk("op_ptr=%llx", op_ptr);

    const u64 new_mongo_version = go_offset_of(ot, (go_offset){.v = _mongo_op_name_new});

    // If we see driver > 1.13.1 we read the operation name
    if (new_mongo_version) {
        if (!read_go_str("name",
                         op_ptr,
                         go_offset_of(ot, (go_offset){.v = _mongo_op_name_pos}),
                         &req->op,
                         sizeof(req->op))) {
            bpf_dbg_printk("can't read mongodb Operation.Name");
            return 0;
        }
    }

    if (!read_go_str("database",
                     op_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_db_name_pos}),
                     &req->db,
                     sizeof(req->db))) {
        bpf_dbg_printk("can't read mongodb Operation.Database");
        return 0;
    }

    // Non-fatal: the span is still emitted if hostname extraction fails.
    if (read_mongo_hostname_from_operation(op_ptr, ot, req)) {
        bpf_dbg_printk("mongo hostname extracted: %s", req->hostname);
    } else {
        bpf_dbg_printk("mongo hostname extraction failed, server.address will be empty");
    }

    bpf_map_update_elem(&ongoing_mongo_requests, &g_key, req, BPF_ANY);

    obi_ctx__set(bpf_get_current_pid_tgid(), &req->tp);

    return 0;
}

SEC("uprobe/op_execute")
int obi_uprobe_mongo_op_execute_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/op_execute ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *err_ptr = (void *)GO_PARAM1(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    if (req) {
        if (err_ptr) {
            req->err = 1;
        } else {
            req->err = 0;
        }

        mongo_go_client_req_t *trace =
            bpf_ringbuf_reserve(&events, sizeof(mongo_go_client_req_t), 0);
        if (trace) {
            bpf_dbg_printk("Sending mongo Go client go trace");
            __builtin_memcpy(trace, req, sizeof(mongo_go_client_req_t));
            trace->end_monotime_ns = bpf_ktime_get_ns();
            task_pid(&trace->pid);
            bpf_ringbuf_submit(trace, get_flags());
        }
    }

    bpf_map_delete_elem(&ongoing_mongo_requests, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    return 0;
}
