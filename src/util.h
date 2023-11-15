/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "block_meta.h"
#include "printf.h"

#define THRESHOLD 128 * 1024
#define ALIGNMENT_8_BYTE 8
#define ALIGNED_BYTE 8

size_t align_block(size_t size);
void add_block_in_list (struct block_meta **memoryHead, struct block_meta *newBlock);
void set_block_meta (struct block_meta *newBlock, int status, size_t size);
struct block_meta *split_chunk(struct block_meta *newBlock, size_t neededSize, size_t alignedBlockMeta);
struct block_meta *find_block_with_size(struct block_meta **memoryHead, size_t size);
struct block_meta *find_the_block_ptr(void *ptr, size_t alignedBlockMeta);
void remove_block_from_list(struct block_meta **memoryHead, struct block_meta *block);
void *malloc_calloc_implementation(size_t size, size_t threshold);


void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
