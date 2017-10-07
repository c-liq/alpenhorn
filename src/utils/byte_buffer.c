#include "byte_buffer.h"

static inline void _bb_upd_read(byte_buffer *buf, uint64_t count)
{
    buf->read_pos += count;
    buf->read += count;
    buf->read_limit -= count;
}

static inline void _bb_upd_write(byte_buffer *buf, uint64_t count)
{
    buf->write_pos += count;
    buf->write_limit -= count;
    buf->written += count;
    buf->read_limit += count;
}

int bb_check_size(byte_buffer *buf, uint64_t count) {
    if (!buf) {
        return -1;
    }

    if (count <= buf->write_limit) {
        return 0;
    }

    if (!buf->resizable) {
        return -1;
    }

    uint64_t new_capacity = buf->capacity * 2 + count;
    uint8_t *new_buf = realloc(buf->data, new_capacity);
    if (!new_buf) {
        return -1;
    }

    buf->data = new_buf;
    buf->read_pos = buf->data + buf->read;
    buf->write_pos = buf->data + buf->written;
    buf->capacity = new_capacity;
    buf->write_limit = new_capacity - buf->written;

    return 0;
}

int bb_compact(byte_buffer *buf)
{
    if (buf->read == 0) {
        return 0;
    }

    memcpy(buf->data, buf->read_pos, buf->read_limit);
    buf->write_pos = buf->data + buf->read_limit;
    buf->read = 0;
    buf->read_pos = buf->data;
    buf->write_limit = buf->capacity - buf->read_limit;

    return 0;
}

int bb_read(uint8_t *out, byte_buffer *buf, uint64_t count)
{
    if (buf->read_limit < count) {
        return -1;
    }

    memcpy(out, buf->read_pos, count);
    _bb_upd_read(buf, count);
    return 0;
}

int bb_write_u64(byte_buffer *buf, uint64_t num)
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

int bb_read_u64(uint64_t *out, byte_buffer *buf)
{
    if (buf->read_limit < sizeof out) {

        return -1;
    }

    uint8_t *ptr = buf->read_pos;

    *out += (uint64_t) ptr[7] << 0;
    *out += (uint64_t) ptr[6] << 8;
    *out += (uint64_t) ptr[5] << 16;
    *out += (uint64_t) ptr[5] << 24;
    *out += (uint64_t) ptr[3] << 32;
    *out += (uint64_t) ptr[2] << 40;
    *out += (uint64_t) ptr[1] << 48;
    *out += (uint64_t) ptr[0] << 56;

    _bb_upd_read(buf, sizeof out);
    return 0;
}

int bb_write(byte_buffer *buf, uint8_t *data, size_t count)
{
    if (bb_check_size(buf, count)) {
        return -1;
    }

    memcpy(buf->write_pos, data, count);
    _bb_upd_write(buf, count);
    return 0;
}

uint8_t *bb_write_virtual(byte_buffer *buf, uint64_t count)
{
    if (bb_check_size(buf, count)) {
        return NULL;
    }

    uint8_t *ptr = buf->write_pos;
    _bb_upd_write(buf, count);
    return ptr;
}

uint8_t *bb_read_virtual(byte_buffer *buf, uint64_t count)
{
    if (buf->read_limit < count) {
        return NULL;
    }

    uint8_t *ptr = buf->read_pos;
    _bb_upd_read(buf, count);
    return ptr;
}

byte_buffer *bb_alloc(uint64_t capacity, bool resizable) {
    byte_buffer *buffer = calloc(1, sizeof *buffer);
    if (!buffer) {
        return NULL;
    }

    if (bb_init(buffer, capacity, resizable)) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

int bb_slice(byte_buffer_t out, byte_buffer_t in, uint64_t count) {
    uint8_t *slice_ptr = bb_read_virtual(in, count);
    if (!slice_ptr) {
        return -1;
    }

    out->data = slice_ptr;
    out->read_pos = slice_ptr;
    out->write_pos = slice_ptr + count;
    out->read_limit = count;
    out->write_limit = 0;
    out->read = 0;
    out->written = count;
    out->resizable = false;
    out->alloced = false;
    out->capacity = count;

    return 0;
}

int bb_init(byte_buffer *buf, uint64_t capacity, bool resizable)
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

int bb_to_bb(byte_buffer *out, byte_buffer *in, uint64_t count) {
    if (bb_check_size(out, count) || in->read_limit < count) {
        return -1;
    }

    memcpy(out->write_pos, in->read_pos, count);
    _bb_upd_write(out, count);
    _bb_upd_read(in, count);
    return 0;
}

ssize_t bb_write_from_fd(byte_buffer *buf, int socket_fd)
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

ssize_t bb_read_to_fd(byte_buffer *buf, int socket_fd)
{
    ssize_t res = write(socket_fd, buf->read_pos, buf->read_limit);
    if (res > 0) {
        _bb_upd_read(buf, (uint64_t) res);
    }

    return res;
}

byte_buffer *bb_clone(byte_buffer *in) {
    byte_buffer *new_bb = bb_alloc(in->capacity, in->resizable);
    if (!new_bb) {
        return NULL;
    }

    memcpy(new_bb->data, in->data, in->written);
    new_bb->read = in->read;
    new_bb->written = in->written;
    new_bb->read_limit = in->read_limit;
    new_bb->write_limit = in->write_limit;

    new_bb->read_pos = new_bb->data + new_bb->read;
    new_bb->write_pos = new_bb->data + new_bb->written;

    new_bb->resizable = in->resizable;
    new_bb->alloced = true;

    return new_bb;
}

int bb_copy_init(byte_buffer *new_bb, byte_buffer *in) {
    if (!new_bb || !in) {
        return -1;
    }

    new_bb->data = in->data;
    new_bb->read = in->read;
    new_bb->written = in->written;
    new_bb->read_limit = in->read_limit;
    new_bb->write_limit = in->write_limit;
    new_bb->read_pos = in->read_pos;
    new_bb->write_pos = in->write_pos;
    new_bb->resizable = in->resizable;
    new_bb->alloced = in->alloced;
    return 0;
}

static void _bb_init_static(byte_buffer *buf, uint8_t *data, uint64_t capacity) {
    buf->data = data;
    buf->capacity = capacity;
    buf->read_pos = buf->data;
    buf->write_pos = buf->data;
    buf->read = 0;
    buf->written = 0;
    buf->read_limit = 0;
    buf->write_limit = buf->capacity;
    buf->alloced = false;
    buf->resizable = false;
}

byte_buffer *bb_copy_alloc(byte_buffer *in) {
    byte_buffer *new_bb = calloc(1, sizeof *new_bb);

    if (bb_copy_init(new_bb, in)) {
        free(new_bb);
        new_bb = NULL;
    }

    return new_bb;
}

void bb_print(byte_buffer *buf) {
    printf("ByteBuffer stats: buf ptr: %p | capacity: %ld | read: %ld | written | %ld | rlim: %ld | wlim: %ld \n",
           (void *) buf->data,
           buf->capacity,
           buf->read,
           buf->written,
           buf->read_limit,
           buf->write_limit);
}
void bb_reset(byte_buffer *buf) {

    buf->read_pos = buf->data;
    buf->write_pos = buf->data;
    buf->read = 0;
    buf->written = 0;
    buf->read_limit = 0;
    buf->write_limit = buf->capacity;
}

void bb_reset_zero(byte_buffer *buf) {
    bb_reset(buf);
    memset(buf->data, 0, buf->capacity);
}

void bb_clear(byte_buffer *buf)
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

void bb_free(byte_buffer *buf)
{
    bb_clear(buf);
    free(buf);
}