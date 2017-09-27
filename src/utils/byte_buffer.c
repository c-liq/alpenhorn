
#include "byte_buffer.h"


static inline void _bb_upd_read(byte_buffer_s *buf, uint64_t count)
{
    buf->read_pos += count;
    buf->read += count;
    buf->read_limit = count;
}

static inline void _bb_upd_write(byte_buffer_s *buf, uint64_t count)
{
    buf->write_pos += count;
    buf->write_limit -= count;
    buf->written += count;
    buf->read_limit += count;
}

int bb_check_size(byte_buffer_s *buf, uint64_t count)
{
    if (count <= buf->write_limit) {
        return 0;
    }

    if (!buf->resizable) {
        return -1;
    }

    uint64_t new_capacity = buf->capacity * 2 + count;
    uint8_t *new_buf = realloc(buf->data, new_capacity);
    if (!new_buf) {
        fprintf(stderr, "failed to resize byte buffer, realloc failure\n");
        return -1;
    }

    buf->data = new_buf;
    buf->read_pos = buf->data + buf->read;
    buf->write_pos = buf->data + buf->written;
    buf->capacity = new_capacity;
    buf->write_limit = new_capacity - buf->written;
    return 0;
}

int bb_compact(byte_buffer_s *buf)
{
    if (buf->read == 0) {
        return 0;
    }

    memcpy(buf->data, buf->read_pos, buf->read_limit);
    buf->write_pos = buf->data + buf->read_limit;
    buf->read = 0;
    buf->read_pos = buf->data;
    buf->write_limit = buf->capacity - buf->read_limit;
}

int bb_read(uint8_t *out, byte_buffer_s *buf, uint64_t count)
{
    if (buf->read_limit < count) {
        return -1;
    }

    memcpy(out, buf->read_pos, count);
    _bb_upd_read(buf, count);
    return 0;
}

int bb_write_u64(byte_buffer_s *buf, uint64_t num)
{
    if (bb_check_size(buf, sizeof num)) {
        return -1;
    }

    uint8_t *out = buf->write_pos;
    out[0] = (uint8_t) (num >> 56);
    out[1] = (uint8_t) (num >> 48);
    out[2] = (uint8_t) (num >> 40);
    out[3] = (uint8_t) (num >> 32);
    out[4] = (uint8_t) (num >> 24);
    out[5] = (uint8_t) (num >> 16);
    out[6] = (uint8_t) (num >> 8);
    out[7] = (uint8_t) (num >> 0);
    _bb_upd_write(buf, sizeof num);

    return 0;
}

int bb_read_u64(uint64_t *out, byte_buffer_s *buf)
{
    if (buf->read_limit < sizeof out) {
        return -1;
    }

    *out = be64toh(*buf->read_pos);
    _bb_upd_read(buf, sizeof out);
    return 0;
}

int bb_write(byte_buffer_s *buf, uint8_t *data, size_t count)
{
    if (bb_check_size(buf, count)) {
        return -1;
    }

    memcpy(buf->write_pos, data, count);
    _bb_upd_write(buf, count);
    return 0;
}

uint8_t *bb_write_virtual(byte_buffer_s *buf, uint64_t count)
{
    if (bb_check_size(buf, count)) {
        return NULL;
    }

    uint8_t *ptr = buf->write_pos;
    _bb_upd_write(buf, count);
    return ptr;
}

uint8_t *bb_read_virtual(byte_buffer_s *buf, uint64_t count)
{
    if (buf->read_limit < count) {
        return NULL;
    }

    uint8_t *ptr = buf->read_pos;
    _bb_upd_read(buf, count);
    return ptr;
}

byte_buffer_s *bb_alloc(uint64_t capacity, bool resizable)
{
    byte_buffer_s *buffer = calloc(1, sizeof *buffer);
    if (!buffer) {
        return NULL;
    }

    if (bb_init(buffer, capacity, resizable)) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

int bb_init(byte_buffer_s *buf, uint64_t capacity, bool resizable)
{
    if (!buf) return -1;

    buf->capacity = capacity;
    buf->data = calloc(1, buf->capacity);

    if (!buf->data) {
        fprintf(stderr, "calloc error in mix_buf_init\n");
        return -1;
    }

    buf->read_pos = buf->data;
    buf->write_pos = buf->data;
    buf->read = 0;
    buf->written = 0;
    buf->read_limit = 0;
    buf->write_limit = buf->capacity;
    buf->alloced = true;
    buf->resizable = resizable;

    return 0;
}

int bb_to_bb(byte_buffer_s *out, byte_buffer_s *in, uint64_t count) {
    if (bb_check_size(out, count) || in->read_limit < count) {
        return -1;
    }

    memcpy(out->write_pos, in->read_pos, count);
    bb_write_virtual(out, count);
    bb_read_virtual(in, count);
    return 0;
}

ssize_t bb_write_from_fd(byte_buffer_s *buf, int socket_fd)
{
    if (bb_check_size(buf, 4096)) {
        return -1;
    }

    ssize_t res = read(socket_fd, buf->write_pos, buf->write_limit);
    if (res > 0) {
        _bb_upd_write(buf, (uint64_t) res);
    }

    return res;
}

ssize_t bb_read_to_fd(byte_buffer_s *buf, int socket_fd)
{

    ssize_t res = write(socket_fd, buf->read_pos, buf->read_limit);
    if (res > 0) {
        _bb_upd_read(buf, (uint64_t) res);
    }

    return res;
}

void bb_reset(byte_buffer_s *buf)
{
    buf->read_pos = buf->data;
    buf->write_pos = buf->data;
    buf->read = 0;
    buf->written = 0;
    buf->read_limit = 0;
    buf->write_limit = buf->capacity;
}

void bb_clear(byte_buffer_s *buf)
{
    if (buf->alloced) {
        free(buf->data);
    }

    buf->data = NULL;
    buf->read_pos = NULL;
    buf->write_pos = NULL;

    buf->read_limit = 0;
    buf->write_limit = 0;
    buf->read = 0;
    buf->written = 0;
}

void bb_free(byte_buffer_s *buf)
{
    bb_clear(buf);
    free(buf);
}