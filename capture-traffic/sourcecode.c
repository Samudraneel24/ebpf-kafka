// +build ignore

/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <linux/in6.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <net/inet_sock.h>

// Defines

#define socklen_t size_t

// Data buffer message size. BPF can submit at most this amount of data to a perf buffer.
// Kernel size limit is 32KiB. See https://github.com/iovisor/bcc/issues/2519 for more details.
#define MAX_MSG_SIZE 30720  // 30KiB

// This defines how many chunks a perf_submit can support.
// This applies to messages that are over MAX_MSG_SIZE,
// and effectively makes the maximum message size to be CHUNK_LIMIT*MAX_MSG_SIZE.
#define CHUNK_LIMIT 4

enum traffic_direction_t {
    kEgress,
    kIngress,
};

// Structs

// A struct representing a unique ID that is composed of the pid, the file
// descriptor and the creation time of the struct.
struct conn_id_t {
    // Process ID
    uint32_t pid;
    // The file descriptor to the opened network connection.
    int32_t fd;
    // Timestamp at the initialization of the struct.
    uint64_t tsid;
};

// This struct contains information collected when a connection is established,
// via an accept4() syscall.
struct conn_info_t {
    // Connection identifier.
    struct conn_id_t conn_id;

    // The number of bytes written/read on this connection.
    int64_t wr_bytes;
    int64_t rd_bytes;

    // A flag indicating we identified the connection as HTTP.
    bool is_http;
    bool is_kafka;

    size_t prev_count;
    char prev_buf[4];
    int32_t message_length;
    bool prepend_length_header;
};

// An helper struct that hold the addr argument of the syscall.
struct accept_args_t {
    struct sockaddr_in* addr;
};

struct connect_args_t {
    const struct sockaddr_in* addr;
    int32_t fd;
};                        

// An helper struct to cache input argument of read/write syscalls between the
// entry hook and the exit hook.
struct data_args_t {
    int32_t fd;
    const char* buf;
    const struct iovec* iov;
  	size_t iovlen;
  	unsigned int* msg_len;
};

// An helper struct that hold the input arguments of the close syscall.
struct close_args_t {
    int32_t fd;
};

// A struct describing the event that we send to the user mode upon a new connection.
struct socket_open_event_t {
    // The time of the event.
    uint64_t timestamp_ns;
    // A unique ID for the connection.
    struct conn_id_t conn_id;
    // The address of the client.
    struct sockaddr_in addr;
    // char comm[TASK_COMM_LEN];
};

// Struct describing the close event being sent to the user mode.
struct socket_close_event_t {
    // Timestamp of the close syscall
    uint64_t timestamp_ns;
    // The unique ID of the connection
    struct conn_id_t conn_id;
    // Total number of bytes written on that connection
    int64_t wr_bytes;
    // Total number of bytes read on that connection
    int64_t rd_bytes;
};

struct kafka_headers_t {
    int16_t api_id;
    int16_t api_version;
    int32_t correlation_id;
};

struct socket_data_event_t {
  // We split attributes into a separate struct, because BPF gets upset if you do lots of
  // size arithmetic. This makes it so that it's attributes followed by message.
  struct attr_t {
    char comm[TASK_COMM_LEN];
    struct kafka_headers_t kafka_headers;
    // The timestamp when syscall completed (return probe was triggered).
    uint64_t timestamp_ns;

    // Connection identifier (PID, FD, etc.).
    struct conn_id_t conn_id;

    // The type of the actual data that the msg field encodes, which is used by the caller
    // to determine how to interpret the data.
    enum traffic_direction_t direction;

	// The size of the original message. We use this to truncate msg field to minimize the amount
    // of data being transferred.
    uint32_t msg_size;

    // A 0-based position number for this event on the connection, in terms of byte position.
    // The position is for the first byte of this message.
    uint64_t pos;

    bool prepend_length_header;
    uint32_t length_header;
    uint32_t protocol;
  } attr;
  char msg[MAX_MSG_SIZE];
};

// Maps

// A map of the active connections. The name of the map is conn_info_map
// the key is of type uint64_t, the value is of type struct conn_info_t,
// and the map won't be bigger than 128KB.
BPF_HASH(conn_info_map, uint64_t, struct conn_info_t, 131072);
// An helper map that will help us cache the input arguments of the accept syscall
// between the entry hook and the return hook.
BPF_HASH(active_accept_args_map, uint64_t, struct accept_args_t);
BPF_HASH(active_connect_args_map, uint64_t, struct connect_args_t);
// Perf buffer to send to the user-mode the data events.
BPF_PERF_OUTPUT(socket_data_events);
// A perf buffer that allows us send events from kernel to user mode.
// This perf buffer is dedicated for special type of events - open events.
BPF_PERF_OUTPUT(socket_open_events);
// Perf buffer to send to the user-mode the close events.
BPF_PERF_OUTPUT(socket_close_events);
BPF_PERCPU_ARRAY(socket_data_event_buffer_heap, struct socket_data_event_t, 1);
BPF_HASH(active_write_args_map, uint64_t, struct data_args_t);
// Helper map to store read syscall arguments between entry and exit hooks.
BPF_HASH(active_read_args_map, uint64_t, struct data_args_t);
// An helper map to store close syscall arguments between entry and exit syscalls.
BPF_HASH(active_close_args_map, uint64_t, struct close_args_t);

// Helper functions

// Generates a unique identifier using a tgid (Thread Global ID) and a fd (File Descriptor).
static __inline uint64_t gen_tgid_fd(uint32_t tgid, int fd) {
    return ((uint64_t)tgid << 32) | (uint32_t)fd;
}

static __inline void process_implicit_conn(struct pt_regs* ctx, uint64_t id,
                                           const struct connect_args_t* args) {
  uint32_t tgid = id >> 32;

  if (args->fd < 0) {
    return;
  }

  uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);

  struct conn_info_t* conn_info_tmp = conn_info_map.lookup(&tgid_fd);
  if (conn_info_tmp != NULL) {
    return;
  }

  // submit_new_conn(ctx, tgid, args->fd, args->addr, /*socket*/ NULL, kRoleUnknown, source_fn);
  struct conn_info_t conn_info = {};
  conn_info.conn_id.pid = tgid;
  conn_info.conn_id.fd = args->fd;
  conn_info.conn_id.tsid = bpf_ktime_get_ns();

  // uint64_t pid_fd = gen_tgid_fd(pid, args->fd);
  conn_info_map.update(&tgid_fd, &conn_info);

  struct socket_open_event_t open_event = {};
  open_event.timestamp_ns = bpf_ktime_get_ns();
  open_event.conn_id = conn_info.conn_id;
  // bpf_get_current_comm(&open_event.comm, sizeof(open_event.comm));
  bpf_probe_read(&open_event.addr, sizeof(open_event.addr), args->addr);
  bpf_trace_printk("%d %d %d", args->addr->sin_family, args->addr->sin_port, args->addr->sin_addr);
  // bpf_trace_printk("%d %d %d\n", bpf_ntohl(args->addr->sin_family), bpf_ntohl(args->addr->sin_port), bpf_ntohl(args->addr->sin_addr.s_addr));

  socket_open_events.perf_submit(ctx, &open_event, sizeof(struct socket_open_event_t));
}

static __inline void process_syscall_connect(struct pt_regs* ctx, uint64_t id,
                                             const struct connect_args_t* args) {
  uint32_t pid = id >> 32;
  int ret_val = PT_REGS_RC(ctx);

  if (args->fd < 0) {
    return;
  }

  if (ret_val < 0 && ret_val != -EINPROGRESS) {
    return;
  }

  // submit_new_conn(ctx, tgid, args->fd, args->addr, /*socket*/ NULL, kRoleClient, kSyscallConnect);
  struct conn_info_t conn_info = {};
  conn_info.conn_id.pid = pid;
  conn_info.conn_id.fd = args->fd;
  conn_info.conn_id.tsid = bpf_ktime_get_ns();

  uint64_t pid_fd = gen_tgid_fd(pid, args->fd);
  conn_info_map.update(&pid_fd, &conn_info);

  struct socket_open_event_t open_event = {};
  open_event.timestamp_ns = bpf_ktime_get_ns();
  open_event.conn_id = conn_info.conn_id;
  // bpf_get_current_comm(&open_event.comm, sizeof(open_event.comm));
  bpf_probe_read(&open_event.addr, sizeof(open_event.addr), args->addr);
  bpf_trace_printk("%d %d %d", args->addr->sin_family, args->addr->sin_port, args->addr->sin_addr);
  // bpf_trace_printk("%d %d %d\n", bpf_ntohl(args->addr->sin_family), bpf_ntohl(args->addr->sin_port), bpf_ntohl(args->addr->sin_addr.s_addr));

  socket_open_events.perf_submit(ctx, &open_event, sizeof(struct socket_open_event_t));
}

// An helper function that checks if the syscall finished successfully and if it did
// saves the new connection in a dedicated map of connections
static __inline void process_syscall_accept(struct pt_regs* ctx, uint64_t id, const struct accept_args_t* args) {
    // Extracting the return code, and checking if it represent a failure,
    // if it does, we abort the as we have nothing to do.
    int ret_fd = PT_REGS_RC(ctx);
    if (ret_fd < 0) {
        return;
    }

    struct conn_info_t conn_info = {};
    uint32_t pid = id >> 32;
    conn_info.conn_id.pid = pid;
    conn_info.conn_id.fd = ret_fd;
    conn_info.conn_id.tsid = bpf_ktime_get_ns();

    uint64_t pid_fd = ((uint64_t)pid << 32) | (uint32_t)ret_fd;
    // Saving the connection info in a global map, so in the other syscalls
    // (read, write and close) we will be able to know that we have seen
    // the connection
    conn_info_map.update(&pid_fd, &conn_info);

    // Sending an open event to the user mode, to let the user mode know that we
    // have identified a new connection.
    struct socket_open_event_t open_event = {};
    open_event.timestamp_ns = bpf_ktime_get_ns();
    open_event.conn_id = conn_info.conn_id;
    // bpf_get_current_comm(&open_event.comm, sizeof(open_event.comm));
	bpf_probe_read(&open_event.addr, sizeof(open_event.addr), args->addr);
  bpf_trace_printk("%d %d %d", args->addr->sin_family, args->addr->sin_port, args->addr->sin_addr);
  // bpf_trace_printk("%d %d %d\n", bpf_ntohl(args->addr->sin_family), bpf_ntohl(args->addr->sin_port), bpf_ntohl(args->addr->sin_addr.s_addr));

    socket_open_events.perf_submit(ctx, &open_event, sizeof(struct socket_open_event_t));
}

static inline __attribute__((__always_inline__)) void process_syscall_close(struct pt_regs* ctx, uint64_t id,
                                                                            const struct close_args_t* close_args) {
    int ret_val = PT_REGS_RC(ctx);
    if (ret_val < 0) {
        return;
    }

    uint32_t tgid = id >> 32;
    uint64_t tgid_fd = gen_tgid_fd(tgid, close_args->fd);
    struct conn_info_t* conn_info = conn_info_map.lookup(&tgid_fd);
    if (conn_info == NULL) {
        // The FD being closed does not represent an IPv4 socket FD.
        return;
    }

    // Send to the user mode an event indicating the connection was closed.
    struct socket_close_event_t close_event = {};
    close_event.timestamp_ns = bpf_ktime_get_ns();
    close_event.conn_id = conn_info->conn_id;
    close_event.rd_bytes = conn_info->rd_bytes;
    close_event.wr_bytes = conn_info->wr_bytes;

    socket_close_events.perf_submit(ctx, &close_event, sizeof(struct socket_close_event_t));

    // Remove the connection from the mapping.
    conn_info_map.delete(&tgid_fd);
}

static __inline int32_t read_big_endian_int32(const char* buf) {
  int32_t length;
  bpf_probe_read(&length, 4, buf);
  return bpf_ntohl(length);
}

static __inline int16_t read_big_endian_int16(const char* buf) {
  int16_t val;
  bpf_probe_read(&val, 2, buf);
  return bpf_ntohs(val);
}						

static inline __attribute__((__always_inline__)) bool infer_kafka_request(const char* buf, struct kafka_headers_t* kafka_headers) {
  // API is Kafka's terminology for opcode.
  static const int kNumAPIs = 62;
  static const int kMaxAPIVersion = 12;

  const int16_t request_API_key = read_big_endian_int16(buf);
  if (request_API_key < 0 || request_API_key > kNumAPIs) {
  // if (request_API_key < 0 || request_API_key > 1) {
    return false;
  }

  const int16_t request_API_version = read_big_endian_int16(buf + 2);
  if (request_API_version < 1 || request_API_version > kMaxAPIVersion) {
    return false;
  }

  const int32_t correlation_id = read_big_endian_int32(buf + 4);
  if (correlation_id < 0) {
    return false;
  }
  kafka_headers->api_id = request_API_key;
  kafka_headers->api_version = request_API_version;
  kafka_headers->correlation_id = correlation_id;
  // bpf_trace_printk("%d %d %d", request_API_key, request_API_version, correlation_id);
  return true;
}

static inline __attribute__((__always_inline__)) bool infer_kafka_message(struct conn_info_t* conn_info, const char* buf, size_t count, struct kafka_headers_t* kafka_headers) {
  // Second statement checks whether suspected header matches the length of current packet.
  // This shouldn't confuse with MySQL because MySQL uses little endian, and Kafka uses big endian.
  // bpf_trace_printk("kafka request parser invoked!");
  if (conn_info->is_kafka) {
      return true;
  }

  // bpf_trace_printk("%s", conn_info->prev_buf);
  bool use_prev_buf =
      (conn_info->prev_count == 4) && (conn_info->message_length);

  if (use_prev_buf) {
    // bpf_trace_printk("uuuse prrrrev buf");
    count += 4;
  }
  // bpf_trace_printk("break1");
  // length(4 bytes) + api_key(2 bytes) + api_version(2 bytes) + correlation_id(4 bytes)
  static const int kMinRequestLength = 12;
  if (count < kMinRequestLength) {
    return false;
  }

  // const int32_t message_size = use_prev_buf ? count : read_big_endian_int32(buf) + 4;
  const int32_t message_size = count;
  // bpf_trace_printk("break2");

  // Enforcing count to be exactly message_size + 4 to mitigate misclassification.
  // However, this will miss long messages broken into multiple reads.
  if (message_size < 0 || count != (size_t)message_size) {
    // bpf_trace_printk(buf, message_size);
    // bpf_trace_printk("kafka returned");
    return false;
  }
  const char* request_buf = use_prev_buf ? buf : buf + 4;
  // bpf_trace_printk("Before func call");
  bool result = infer_kafka_request(request_buf, kafka_headers);

  // Kafka servers read in a 4-byte packet length header first. The first packet in the
  // stream is used to infer protocol, but the header has already been read. One solution is to
  // add another perf_submit of the 4-byte header, but this would impact the instruction limit.
  // Not handling this case causes potential confusion in the parsers. Instead, we set a
  // prepend_length_header field if and only if Kafka has just been inferred for the first time
  // under the scenario described above. Length header is appended to user the buffer in user space.
  if (use_prev_buf && result == true && conn_info->is_http == false && conn_info->is_kafka == false) {
    conn_info->prepend_length_header = true;
  }

  if (result) {
    conn_info->is_kafka == true;
    // bpf_trace_printk("kafka");
  }

  return result;
}

static inline __attribute__((__always_inline__)) bool is_http_connection(struct conn_info_t* conn_info, const char* buf, size_t count) {
    // If the connection was already identified as HTTP connection, no need to re-check it.
    if (conn_info->is_http) {
        return true;
    }

    // The minimum length of http request or response.
    if (count < 16) {
        return false;
    }

    bool res = false;
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        res = true;
    }
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
        res = true;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
        res = true;
    }

    if (res) {
        conn_info->is_http = true;
        // bpf_trace_printk("http");
    }

    return res;
}

static __inline void perf_submit_buf(struct pt_regs* ctx, const enum traffic_direction_t direction,
                                     const char* buf, size_t buf_size, size_t offset,
                                     struct conn_info_t* conn_info,
                                     struct socket_data_event_t* event) {
    switch (direction) {
        case kEgress:
            event->attr.pos = conn_info->wr_bytes + offset;
            break;
        case kIngress:
            event->attr.pos = conn_info->rd_bytes + offset;
            break;
    }

    // Note that buf_size_minus_1 will be positive due to the if-statement above.
    size_t buf_size_minus_1 = buf_size - 1;

    // Clang is too smart for us, and tries to remove some of the obvious hints we are leaving for the
    // BPF verifier. So we add this NOP volatile statement, so clang can't optimize away some of our
    // if-statements below.
    // By telling clang that buf_size_minus_1 is both an input and output to some black box assembly
    // code, clang has to discard any assumptions on what values this variable can take.
    asm volatile("" : "+r"(buf_size_minus_1) :);

    buf_size = buf_size_minus_1 + 1;

    // 4.14 kernels reject bpf_probe_read with size that they may think is zero.
    // Without the if statement, it somehow can't reason that the bpf_probe_read is non-zero.
    size_t amount_copied = 0;
    if (buf_size_minus_1 < MAX_MSG_SIZE) {
        bpf_probe_read(&event->msg, buf_size, buf);
        amount_copied = buf_size;
    } else {
        bpf_probe_read(&event->msg, MAX_MSG_SIZE, buf);
        amount_copied = MAX_MSG_SIZE;
    }

    // If-statement is redundant, but is required to keep the 4.14 verifier happy.
    if (amount_copied > 0) {
        event->attr.msg_size = amount_copied;
        socket_data_events.perf_submit(ctx, event, sizeof(event->attr) + amount_copied);
    }
}

static __inline void perf_submit_wrapper(struct pt_regs* ctx,
                                         const enum traffic_direction_t direction, const char* buf,
                                         const size_t buf_size, struct conn_info_t* conn_info,
                                         struct socket_data_event_t* event) {
    int bytes_sent = 0;
    unsigned int i;
#pragma unroll
    for (i = 0; i < CHUNK_LIMIT; ++i) {
        const int bytes_remaining = buf_size - bytes_sent;
        const size_t current_size = (bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1)) ? MAX_MSG_SIZE : bytes_remaining;
        perf_submit_buf(ctx, direction, buf + bytes_sent, current_size, bytes_sent, conn_info, event);
        bytes_sent += current_size;
        if (buf_size == bytes_sent) {
            return;
        }
    }
}

static inline __attribute__((__always_inline__)) void process_data(const bool vecs, struct pt_regs* ctx, uint64_t id,
                                                                   enum traffic_direction_t direction,
                                                                   const struct data_args_t* args, ssize_t bytes_count) {
    // // Always check access to pointer before accessing them.
    // if (args->buf == NULL) {
    //     return;
    // }

    // // For read and write syscall, the return code is the number of bytes written or read, so zero means nothing
    // // was written or read, and negative means that the syscall failed. Anyhow, we have nothing to do with that syscall.
    // if (bytes_count <= 0) {
    //     return;
    // }
    // bpf_trace_printk("process data test");
    if (!vecs && args->buf == NULL) {
	    return;
	  }

	  if (vecs && (args->iov == NULL || args->iovlen <= 0)) {
	    return;
	  }

	  if (args->fd < 0) {
	    return;
	  }

	  if (bytes_count <= 0) {
	    // This read()/write() call failed, or processed nothing.
	    return;
	  }

    uint32_t pid = id >> 32;
    uint64_t pid_fd = ((uint64_t)pid << 32) | (uint32_t)args->fd;
    struct conn_info_t* conn_info = conn_info_map.lookup(&pid_fd);

    if (conn_info == NULL) {
        // The FD being read/written does not represent an IPv4 socket FD.
        return;
    }
    // bpf_trace_printk("%u", id);
    conn_info->prepend_length_header = false;
    uint32_t protocol = 0;
    struct kafka_headers_t kafka_headers = {};
    if (is_http_connection(conn_info, args->buf, bytes_count)){
      protocol = 1;
    }
    else if (infer_kafka_message(conn_info, args->buf, bytes_count, &kafka_headers)){
      protocol = 2;
    }

    // Check if the connection is already HTTP, or check if that's a new connection, check protocol and return true if that's HTTP.
    if (protocol > 0) {
        // allocate new event.
        // bpf_trace_printk("interesting protocol");
        uint32_t kZero = 0;
        struct socket_data_event_t* event = socket_data_event_buffer_heap.lookup(&kZero);
        if (event == NULL) {
            return;
        }

        // Fill the metadata of the data event.
        event->attr.timestamp_ns = bpf_ktime_get_ns();
        event->attr.direction = direction;
        event->attr.conn_id = conn_info->conn_id;
        event->attr.prepend_length_header = conn_info->prepend_length_header;
        event->attr.protocol = protocol;
        bpf_get_current_comm(&event->attr.comm, sizeof(event->attr.comm));
        // bpf_trace_printk("%d %d %d", kafka_headers.api_id, kafka_headers.api_version, kafka_headers.correlation_id);
        event->attr.kafka_headers = kafka_headers;
        // bpf_trace_printk("%d %d %d", event->attr.kafka_headers.api_id, event->attr.kafka_headers.api_version, event->attr.kafka_headers.correlation_id);
        bpf_probe_read(&event->attr.length_header, 4, conn_info->prev_buf);

        perf_submit_wrapper(ctx, direction, args->buf, bytes_count, conn_info, event);
    }

    conn_info->prev_count = bytes_count;
  if (bytes_count == 4) {
    conn_info->prev_buf[0] = args->buf[0];
    conn_info->prev_buf[1] = args->buf[1];
    conn_info->prev_buf[2] = args->buf[2];
    conn_info->prev_buf[3] = args->buf[3];
    conn_info->message_length = (size_t)read_big_endian_int32(args->buf);
    // bpf_trace_printk("Curr count is 4 ");
    // bpf_trace_printk("%d %d", args->buf[0], args->buf[1]);
    // bpf_trace_printk("%d %d", args->buf[2], args->buf[3]);
    // bpf_trace_printk("%u", (size_t)read_big_endian_int32(args->buf));
  }

	// Update the conn_info total written/read bytes.
	switch (direction) {
        case kEgress:
            conn_info->wr_bytes += bytes_count;
            break;
        case kIngress:
            conn_info->rd_bytes += bytes_count;
            break;
    }
}

// Hooks
int syscall__probe_entry_connect(struct pt_regs* ctx, int sockfd, const struct sockaddr* addr,
                                 socklen_t addrlen) {
  // bpf_trace_printk("Entry connect");
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct connect_args_t connect_args = {};
  connect_args.fd = sockfd;
  connect_args.addr = (struct sockaddr_in *)addr;
  active_connect_args_map.update(&id, &connect_args);

  return 0;
}

int syscall__probe_ret_connect(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();

  // Unstash arguments, and process syscall.
  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL) {
    process_syscall_connect(ctx, id, connect_args);
  }

  active_connect_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_accept(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    // cccccc("Entry accept");
    uint64_t id = bpf_get_current_pid_tgid();

    // Keep the addr in a map to use during the exit method.
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)addr;
    active_accept_args_map.update(&id, &accept_args);

    return 0;
}

int syscall__probe_ret_accept(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Pulling the addr from the map.
    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
    if (accept_args != NULL) {
        process_syscall_accept(ctx, id, accept_args);
    }

    active_accept_args_map.delete(&id);
    return 0;
}


// Hooking the entry of accept4
// the signature of the syscall is int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int syscall__probe_entry_accept4(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    // Getting a unique ID for the relevant thread in the relevant pid.
    // That way we can link different calls from the same thread.
    // bpf_trace_printk("Entry accept4");
    uint64_t id = bpf_get_current_pid_tgid();

    // Keep the addr in a map to use during the accpet4 exit hook.
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)addr;
    active_accept_args_map.update(&id, &accept_args);

    return 0;
}

// Hooking the exit of accept4
int syscall__probe_ret_accept4(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Pulling the addr from the map.
    struct accept_args_t* accept_args = active_accept_args_map.lookup(&id);
    // If the id exist in the map, we will get a non empty pointer that holds
    // the input address argument from the entry of the syscall.
    if (accept_args != NULL) {
        process_syscall_accept(ctx, id, accept_args);
    }

    // Anyway, in the end clean the map.
    active_accept_args_map.delete(&id);
    return 0;
}

// original signature: ssize_t write(int fd, const void *buf, size_t count);
int syscall__probe_entry_write(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    // bpf_trace_printk("Entry write");
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args_t write_args = {};
    write_args.fd = fd;
    write_args.buf = buf;
    active_write_args_map.update(&id, &write_args);

    return 0;
}

int syscall__probe_ret_write(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx); // Also stands for return code.

    // Unstash arguments, and process syscall.
    struct data_args_t* write_args = active_write_args_map.lookup(&id);
    if (write_args != NULL) {
        process_data(false, ctx, id, kEgress, write_args, bytes_count);
    }

    active_write_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_send(struct pt_regs* ctx, int sockfd, char* buf, size_t len) {
  // bpf_trace_printk("Entry send");
  uint64_t id = bpf_get_current_pid_tgid();

  struct data_args_t write_args = {};
  write_args.fd = sockfd;
  write_args.buf = buf;
  active_write_args_map.update(&id, &write_args);

  return 0;
}

int syscall__probe_ret_send(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx); // Also stands for return code.

    // Unstash arguments, and process syscall.
    struct data_args_t* write_args = active_write_args_map.lookup(&id);
    if (write_args != NULL) {
        process_data(false, ctx, id, kEgress, write_args, bytes_count);
    }

    active_write_args_map.delete(&id);
    return 0;
}

int syscall__probe_entry_sendto(struct pt_regs* ctx, int sockfd, char* buf, size_t len, int flags,
                                const struct sockaddr* dest_addr, socklen_t addrlen) {
  // bpf_trace_printk("Entry sendto");

  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  if (dest_addr != NULL) {
    struct connect_args_t connect_args = {};
    connect_args.fd = sockfd;
    connect_args.addr = (struct sockaddr_in *)dest_addr;
    active_connect_args_map.update(&id, &connect_args);
  }

  // Stash arguments.
  struct data_args_t write_args = {};
  write_args.fd = sockfd;
  write_args.buf = buf;
  active_write_args_map.update(&id, &write_args);

  return 0;
}

int syscall__probe_ret_sendto(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  ssize_t bytes_count = PT_REGS_RC(ctx);

  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL && bytes_count > 0) {
    process_implicit_conn(ctx, id, connect_args);
  }
  active_connect_args_map.delete(&id);

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_data(false, ctx, id, kEgress, write_args, bytes_count);
  }

  active_write_args_map.delete(&id);

  return 0;
}
                      
int syscall__probe_entry_sendmsg(struct pt_regs* ctx, int sockfd,
                                 const struct user_msghdr* msghdr) {
  uint64_t id = bpf_get_current_pid_tgid();
  // bpf_trace_printk("Entry sendmsg");

  if (msghdr != NULL) {
    // Stash arguments.
    if (msghdr->msg_name != NULL) {
      struct connect_args_t connect_args = {};
      connect_args.fd = sockfd;
      connect_args.addr = msghdr->msg_name;
      active_connect_args_map.update(&id, &connect_args);
    }

    // Stash arguments.
    struct data_args_t write_args = {};
    // write_args.source_fn = kSyscallSendMsg;
    write_args.fd = sockfd;
    write_args.iov = msghdr->msg_iov;
    write_args.iovlen = msghdr->msg_iovlen;
    active_write_args_map.update(&id, &write_args);
  }

  return 0;
}

int syscall__probe_ret_sendmsg(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  ssize_t bytes_count = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL && bytes_count > 0) {
    process_implicit_conn(ctx, id, connect_args);
  }
  active_connect_args_map.delete(&id);

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_data(true, ctx, id, kEgress, write_args, bytes_count);
  }

  active_write_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_sendmmsg(struct pt_regs* ctx, int sockfd, struct mmsghdr* msgvec,
                                  unsigned int vlen) {
  // bpf_trace_printk("Entry sendmmsg");
  uint64_t id = bpf_get_current_pid_tgid();

  // TODO(oazizi): Right now, we only trace the first message in a sendmmsg() call.
  if (msgvec != NULL && vlen >= 1) {
    // Stash arguments.
    if (msgvec[0].msg_hdr.msg_name != NULL) {
      struct connect_args_t connect_args = {};
      connect_args.fd = sockfd;
      connect_args.addr = msgvec[0].msg_hdr.msg_name;
      active_connect_args_map.update(&id, &connect_args);
    }

    // Stash arguments.
    struct data_args_t write_args = {};
    // write_args.source_fn = kSyscallSendMMsg;
    write_args.fd = sockfd;
    write_args.iov = msgvec[0].msg_hdr.msg_iov;
    write_args.iovlen = msgvec[0].msg_hdr.msg_iovlen;
    write_args.msg_len = &msgvec[0].msg_len;
    active_write_args_map.update(&id, &write_args);
  }

  return 0;
}

int syscall__probe_ret_sendmmsg(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  int num_msgs = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL && num_msgs > 0) {
    process_implicit_conn(ctx, id, connect_args);
  }
  active_connect_args_map.delete(&id);

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL && num_msgs > 0) {
    // msg_len is defined as unsigned int, so we have to use the same here.
    // This is different than most other syscalls that use ssize_t.
    unsigned int bytes_count = 0;
    bpf_probe_read(&bytes_count, sizeof(unsigned int), write_args->msg_len);
    process_data(true, ctx, id, kEgress, write_args, bytes_count);
  }
  active_write_args_map.delete(&id);

  return 0;
}

int syscall__probe_entry_writev(struct pt_regs* ctx, int fd, const struct iovec* iov, int iovlen) {
  // bpf_trace_printk("Entry writev");
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t write_args = {};
  write_args.fd = fd;
  write_args.iov = iov;
  write_args.iovlen = iovlen;
  active_write_args_map.update(&id, &write_args);

  return 0;
}

int syscall__probe_ret_writev(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  ssize_t bytes_count = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  struct data_args_t* write_args = active_write_args_map.lookup(&id);
  if (write_args != NULL) {
    process_data(true, ctx, id, kEgress, write_args, bytes_count);
  }

  active_write_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_readv(struct pt_regs* ctx, int fd, struct iovec* iov, int iovlen) {
  // bpf_trace_printk("Entry readv");
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t read_args = {};
  read_args.fd = fd;
  read_args.iov = iov;
  read_args.iovlen = iovlen;
  active_read_args_map.update(&id, &read_args);

  return 0;
}

int syscall__probe_ret_readv(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  ssize_t bytes_count = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_data(true, ctx, id, kIngress, read_args, bytes_count);
  }

  active_read_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_recv(struct pt_regs* ctx, int sockfd, char* buf, size_t len) {
  // bpf_trace_printk("Entry recv");

  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  struct data_args_t read_args = {};
  read_args.fd = sockfd;
  read_args.buf = buf;
  active_read_args_map.update(&id, &read_args);

  return 0;
}

int syscall__probe_ret_recv(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  ssize_t bytes_count = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_data(false, ctx, id, kIngress, read_args, bytes_count);
  }

  active_read_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_recvmsg(struct pt_regs* ctx, int sockfd, struct user_msghdr* msghdr) {
  // bpf_trace_printk("Entry recvmsg");
  uint64_t id = bpf_get_current_pid_tgid();

  if (msghdr != NULL) {
    // Stash arguments.
    if (msghdr->msg_name != NULL) {
      struct connect_args_t connect_args = {};
      connect_args.fd = sockfd;
      connect_args.addr = msghdr->msg_name;
      active_connect_args_map.update(&id, &connect_args);
    }

    // Stash arguments.
    struct data_args_t read_args = {};
    read_args.fd = sockfd;
    read_args.iov = msghdr->msg_iov;
    read_args.iovlen = msghdr->msg_iovlen;
    active_read_args_map.update(&id, &read_args);
  }

  return 0;
}

int syscall__probe_ret_recvmsg(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  ssize_t bytes_count = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL && bytes_count > 0) {
    process_implicit_conn(ctx, id, connect_args);
  }
  active_connect_args_map.delete(&id);

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_data(true, ctx, id, kIngress, read_args, bytes_count);
  }

  active_read_args_map.delete(&id);
  return 0;
}

int syscall__probe_entry_recvmmsg(struct pt_regs* ctx, int sockfd, struct mmsghdr* msgvec,
                                  unsigned int vlen) {
  // bpf_trace_printk("Entry recvmmsg");
  uint64_t id = bpf_get_current_pid_tgid();

  // TODO(oazizi): Right now, we only trace the first message in a recvmmsg() call.
  if (msgvec != NULL && vlen >= 1) {
    // Stash arguments.
    if (msgvec[0].msg_hdr.msg_name != NULL) {
      struct connect_args_t connect_args = {};
      connect_args.fd = sockfd;
      connect_args.addr = msgvec[0].msg_hdr.msg_name;
      active_connect_args_map.update(&id, &connect_args);
    }

    // Stash arguments.
    struct data_args_t read_args = {};
    read_args.fd = sockfd;
    read_args.iov = msgvec[0].msg_hdr.msg_iov;
    read_args.iovlen = msgvec[0].msg_hdr.msg_iovlen;
    read_args.msg_len = &msgvec[0].msg_len;
    active_read_args_map.update(&id, &read_args);
  }

  return 0;
}

int syscall__probe_ret_recvmmsg(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  int num_msgs = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL && num_msgs > 0) {
    process_implicit_conn(ctx, id, connect_args);
  }
  active_connect_args_map.delete(&id);

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL && num_msgs > 0) {
    // msg_len is defined as unsigned int, so we have to use the same here.
    // This is different than most other syscalls that use ssize_t.
    unsigned int bytes_count = 0;
    bpf_probe_read(&bytes_count, sizeof(unsigned int), read_args->msg_len);
    process_data(true, ctx, id, kIngress, read_args, bytes_count);
  }
  active_read_args_map.delete(&id);

  return 0;
}

int syscall__probe_entry_recvfrom(struct pt_regs* ctx, int sockfd, char* buf, size_t len, int flags,
                                  struct sockaddr* src_addr, socklen_t* addrlen) {
  // bpf_trace_printk("Entry recvfrom");
  uint64_t id = bpf_get_current_pid_tgid();

  // Stash arguments.
  if (src_addr != NULL) {
    struct connect_args_t connect_args = {};
    connect_args.fd = sockfd;
    connect_args.addr = (struct sockaddr_in *)src_addr;
    active_connect_args_map.update(&id, &connect_args);
  }

  // Stash arguments.
  struct data_args_t read_args = {};
  read_args.fd = sockfd;
  read_args.buf = buf;
  active_read_args_map.update(&id, &read_args);

  return 0;
}

int syscall__probe_ret_recvfrom(struct pt_regs* ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  ssize_t bytes_count = PT_REGS_RC(ctx);

  // Unstash arguments, and process syscall.
  const struct connect_args_t* connect_args = active_connect_args_map.lookup(&id);
  if (connect_args != NULL && bytes_count > 0) {
    process_implicit_conn(ctx, id, connect_args);
  }
  active_connect_args_map.delete(&id);

  // Unstash arguments, and process syscall.
  struct data_args_t* read_args = active_read_args_map.lookup(&id);
  if (read_args != NULL) {
    process_data(false, ctx, id, kIngress, read_args, bytes_count);
  }
  active_read_args_map.delete(&id);

  return 0;
}

// original signature: ssize_t read(int fd, void *buf, size_t count);
int syscall__probe_entry_read(struct pt_regs* ctx, int fd, char* buf, size_t count) {
  // bpf_trace_printk("Entry read");
    uint64_t id = bpf_get_current_pid_tgid();

    // Stash arguments.
    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.buf = buf;
    active_read_args_map.update(&id, &read_args);

    return 0;
}

int syscall__probe_ret_read(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // The return code the syscall is the number of bytes read as well.
    ssize_t bytes_count = PT_REGS_RC(ctx);
    struct data_args_t* read_args = active_read_args_map.lookup(&id);
    if (read_args != NULL) {
        // kIngress is an enum value that let's the process_data function
        // to know whether the input buffer is incoming or outgoing.
        process_data(false, ctx, id, kIngress, read_args, bytes_count);
    }

    active_read_args_map.delete(&id);
    return 0;
}
// original signature: int close(int fd)
int syscall__probe_entry_close(struct pt_regs* ctx, int fd) {
  // bpf_trace_printk("Entry close");
    uint64_t id = bpf_get_current_pid_tgid();
    struct close_args_t close_args;
    close_args.fd = fd;
    active_close_args_map.update(&id, &close_args);

    return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    const struct close_args_t* close_args = active_close_args_map.lookup(&id);
    if (close_args != NULL) {
        process_syscall_close(ctx, id, close_args);
    }

    active_close_args_map.delete(&id);
    return 0;
}
