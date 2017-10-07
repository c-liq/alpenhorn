#ifndef ALPENHORN_bb_H
#define ALPENHORN_bb_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct byte_buffer byte_buffer;
struct byte_buffer
{
    uint8_t *data;
    uint8_t *read_pos;
    uint64_t read_limit;
    uint64_t read;
    uint8_t *write_pos;
    uint64_t write_limit;
    uint64_t written;
    uint64_t capacity;
    bool resizable;
    bool alloced;
};

typedef byte_buffer byte_buffer_t[1];

int bb_init(byte_buffer *buf, uint64_t size, bool resizable);

byte_buffer *bb_alloc(uint64_t capacity, bool resizable);

int bb_check_size(byte_buffer *buf, uint64_t count);

void bb_clear(byte_buffer *buf);

void bb_free(byte_buffer *buf);

int bb_write(byte_buffer *buf, uint8_t *data, uint64_t count);

uint8_t *bb_write_virtual(byte_buffer *buf, uint64_t count);

uint8_t *bb_read_virtual(byte_buffer *buf, uint64_t count);

int bb_write_u64(byte_buffer *buf, uint64_t num);

ssize_t bb_write_from_fd(byte_buffer *buf, int fd);

int bb_read(uint8_t *out, byte_buffer *buf, uint64_t count);

int bb_read_u64(uint64_t *out, byte_buffer *buf);

ssize_t bb_read_to_fd(byte_buffer *buf, int fd);

int bb_to_bb(byte_buffer *out, byte_buffer *in, uint64_t count);

int bb_compact(byte_buffer *buf);

void bb_reset(byte_buffer *buf);

byte_buffer *bb_clone(byte_buffer *in);

int bb_copy_init(byte_buffer *new_bb, byte_buffer *in);

byte_buffer *bb_copy_alloc(byte_buffer *in);

void bb_reset_zero(byte_buffer *buf);

int bb_slice(byte_buffer_t out, byte_buffer_t in, uint64_t count);

static void _bb_init_static(byte_buffer *buf, uint8_t *data, uint64_t capacity);

void bb_print(byte_buffer *);

#define bb_init_static(buf, capacity) \
            uint8_t bb_tmp_buffer_##buf[capacity]; \
            _bb_init_static(buf, bb_tmp_buffer_##buf, capacity)



#endif //ALPENHORN_bb_H
