#ifndef ALPENHORN_bb_H
#define ALPENHORN_bb_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

typedef struct byte_buffer byte_buffer_s;
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

typedef byte_buffer_s byte_buffer_t[1];

int bb_init(byte_buffer_s *buf, uint64_t size, bool resizable);

byte_buffer_s *bb_alloc(uint64_t capacity, bool resizable);

int bb_check_size(byte_buffer_s *buf, uint64_t count);

void bb_clear(byte_buffer_s *buf);

void bb_free(byte_buffer_s *buf);

int bb_write(byte_buffer_s *buf, uint8_t *data, uint64_t count);

uint8_t * bb_write_virtual(byte_buffer_s *buf, uint64_t count);

uint8_t* bb_read_virtual(byte_buffer_s *buf, uint64_t count);

int bb_write_u64(byte_buffer_s *buf, uint64_t num);

ssize_t bb_write_from_fd(byte_buffer_s *buf, int fd);

int bb_read(uint8_t *out, byte_buffer_s *buf, uint64_t count);

int bb_read_u64(uint64_t *out, byte_buffer_s *buf);

ssize_t bb_read_to_fd(byte_buffer_s *buf, int fd);

int bb_to_bb(byte_buffer_s *out, byte_buffer_s *in, uint64_t count);

int bb_compact(byte_buffer_s *buf);

void bb_reset(byte_buffer_s *buf);

void bb_free(byte_buffer_s *buf);


#endif //ALPENHORN_bb_H
