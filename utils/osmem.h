/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_meta.h"
#include "printf.h"

#define THRESHOLD 128000
#define ALIGNMENT_8_BYTE 8

//  Global list of allocated memory
struct block_meta *memoryHead = NULL;

//  Heap preallocation happens only once, so we set a global index
int heap_preallocation = 0;

size_t align_block(size_t size);
void add_block_in_list (struct block_meta **memoryHead, struct block_meta *newBlock);
void set_block_meta (struct block_meta *newBlock, int status, int size);

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
