#include <stdint.h>
#include <stdio.h>
#include "alpenhorn/byte_buffer.h"

int byte_buffer_resize(byte_buffer_s *buf, uint64_t new_capacity)
{
    if (new_capacity <= buf->capacity) {
        fprintf(stderr, "cannot shrink buffer\n");
        return -1;
    }

    uint8_t *new_buf = realloc(buf->data, new_capacity);
    if (!new_buf) {
        fprintf(stderr, "failed to resize byte buffer, realloc failure\n");
        return -1;
    }
    buf->data = new_buf;
    buf->pos = buf->data + buf->used;
    buf->capacity = new_capacity;
    return 0;
}

int bb_write_u64(byte_buffer_s *buf, uint64_t num) {

}

int byte_buffer_put(byte_buffer_s *buf, uint8_t *data, size_t size)
{
    if (size > buf->capacity - buf->used) {
        uint64_t new_capacity = buf->capacity + (2 * size);
        int res = byte_buffer_resize(buf, new_capacity);
        if (res)
            return -1;
    }

    memcpy(buf->pos, data, size);
    buf->pos += size;
    buf->used += size;
    return 0;
}

int byte_buffer_put_virtual(byte_buffer_s *buf, size_t size)
{
    if (size > buf->capacity - buf->used) {
        int res = byte_buffer_resize(buf, buf->capacity + (2 * size));
        if (res)
            return -1;
    }
    buf->pos += size;
    buf->used += size;
    return 0;
}

byte_buffer_s *byte_buffer_alloc(uint64_t capacity)
{
    byte_buffer_s *buffer = calloc(1, sizeof *buffer);
    if (!buffer) {
        return NULL;
    }

    int res = byte_buffer_init(buffer, capacity, NULL);
    if (res) {
        free(buffer);
        return NULL;
    }
    return buffer;
}

int byte_buffer_init(byte_buffer_s *buf, uint64_t capacity, bool resizable)
{
    if (!buf) return -1;

    buf->capacity = capacity;
    buf->data = calloc(1, buf->capacity);
    buf->pos = buf->data;

    if (!buf->data) {
        fprintf(stderr, "calloc error in mix_buf_init\n");
        return -1;
    }

    buf->used = 0;
    return 0;
}

void byte_buffer_clear(byte_buffer_s *buf)
{
    if (!buf) return;

    memset(buf->data, 0, buf->capacity);
    buf->pos = buf->data;
    buf->used = 0;
}