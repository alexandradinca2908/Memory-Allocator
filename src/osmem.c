// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"

//  Making the given size a multiple of 8 bytes
size_t align_block(size_t size) {
	if (size % 8 == 0) {
		return size;
	}
    return size + (ALIGNMENT_8_BYTE - size % ALIGNMENT_8_BYTE);
}

//  Add a new meta block in memory list
void add_block_in_list(struct block_meta **memoryHead, struct block_meta *newBlock) {

	//  Check to see if it's the first alloc
	if (*memoryHead == NULL) {
		*memoryHead = newBlock;
	} else {
		struct block_meta *iter = *memoryHead;

		//  Adding mapped memory before alloc'd memory in list
		//  Three cases: only mapped, only alloc'd or both types in list

		if (newBlock->status == STATUS_MAPPED) {
			//  Add mapped element
			if (iter->status == STATUS_MAPPED) {
				//  Only mapped & both types
				while (iter->next != NULL && iter->next->status != STATUS_ALLOC) {
					iter = iter->next;
				}
				newBlock->next = iter->next;
				newBlock->prev = iter;
				iter->next = newBlock;
				newBlock->next->prev = newBlock;

			} else if (iter->status == STATUS_ALLOC) {
				//  Only alloc'd, so we add newBlock first in list
				newBlock->next = iter;
				newBlock->prev = NULL;
				iter->prev = newBlock;

				*memoryHead = newBlock;
			}
		} else if (newBlock->status == STATUS_ALLOC) {
			//  Add alloc'd element at the end of the list
			while (iter->next != NULL) {
				iter = iter->next;
			}

			iter->next = newBlock;
			newBlock->prev = iter;
			newBlock->next = NULL;
		}		
	}
}

void set_block_meta(struct block_meta *newBlock, int status, int size) {
	newBlock->status = status;
	newBlock->size = size;
	newBlock->next = newBlock->prev = NULL;
}

void split_chunk(struct block_meta *newBlock, size_t neededSize, size_t alignedBlockMeta) {
	size_t remaining_size = newBlock->size - neededSize - alignedBlockMeta;

	if (newBlock->size > neededSize + alignedBlockMeta) {
		if (remaining_size >= alignedBlockMeta + 1) {
			//  Add a new meta block after the needed payload
			struct block_meta *newSplitBlock;
			newSplitBlock = (struct block_meta *)((char *)(newBlock) + alignedBlockMeta + neededSize);

			//  Connect the two new blocks in list and update new block
			newBlock->next = newSplitBlock;
			newBlock->size = neededSize;
			newBlock->status = STATUS_ALLOC;

			//  Declare the remaining space as unused and update info
			newSplitBlock->next = NULL;
			newSplitBlock->prev = newBlock;
			newSplitBlock->size = remaining_size;
			newSplitBlock->status = STATUS_FREE;
		}
	} else if (newBlock->size == neededSize + alignedBlockMeta) {
		//  We just set the block
		newBlock->size = neededSize;
		newBlock->status = STATUS_ALLOC;
	}
	return;
}

void expandBlocks(struct block_meta **memoryHead) {
	if (*memoryHead == NULL) {
		return;
	}

	struct block_meta *iter = *memoryHead;
	size_t alignedBlockMeta = align_block(sizeof(struct block_meta));

	//  Coalesce all free adjacent blocks
	while (iter != NULL && iter->next != NULL) {
		if (iter->status == STATUS_FREE && iter->next->status == STATUS_FREE) {
			iter->size += (alignedBlockMeta + iter->next->size);
			iter = iter->next->next;
		} else {
			iter = iter->next;
		}
	}
}

struct block_meta *find_block_with_size(struct block_meta *memoryHead, size_t size) {
	struct block_meta *iter = memoryHead;
	struct block_meta *best_block = NULL;
	size_t min = __SIZE_MAX__;

	//  Return the free block with the least memory
	while (iter != NULL && iter->next != NULL) {
		if (iter->status == STATUS_FREE && iter->size >= size) {
			if (iter->size < min) {
				min = iter->size;
				best_block = iter;
			}
		}
		iter = iter->next;
	}
	return best_block;
}

struct block_meta *find_the_block_ptr(void *ptr, size_t alignedBlockMeta) {
	return (struct block_meta *)(((char *)ptr) - alignedBlockMeta);
}

void remove_block_from_list(struct block_meta **memoryHead, struct block_meta *block) {
	if ((*memoryHead) == block) {
		//  If the block is first in list, we just move the head
		(*memoryHead) = (*memoryHead)->next;
		return;

	} else {
		struct block_meta *iter = *memoryHead;

		while (iter != block && iter != NULL) {
			iter = iter->next;
		}

		//  Not found
		if (iter == NULL) {
			return;
		}

		// Found
		iter->prev->next = iter->next;
	}
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size == 0) {
		return NULL;
	}

	//  Alloc'd block is alligned to 8 bytes
	size_t alignedBlockMeta = align_block(sizeof(struct block_meta));
	size_t alignedPayload = align_block(size);
	size_t alignedAll = alignedPayload + alignedBlockMeta;

	if (alignedAll >= THRESHOLD) {
		//  Alloc memory, check alloc, create meta data
		void *area = mmap(NULL, alignedAll, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(area == MAP_FAILED, "ERROR IN MAPPING\n");
		struct block_meta *newBlock = (struct block_meta *)area;

		//  Setting the metadata
		set_block_meta(newBlock, STATUS_MAPPED, alignedPayload);

		//  Adding the alloc'd memory in our memory list
		add_block_in_list(&memoryHead, newBlock);

		//  Returning only the needed area
		return (void *)(((char *)area) + alignedBlockMeta);

	} else if (alignedAll < THRESHOLD && heap_preallocation == 0) {
		//  First and only prealloc
		heap_preallocation = 1;

		//  Alloc memory, check alloc, create meta data
		void *area = sbrk(THRESHOLD);
		DIE(area == MAP_FAILED, "ERROR IN PREALLOCATION\n");
		struct block_meta *newBlock = (struct block_meta *)area;

		//  Setting the metadata
		set_block_meta(newBlock, STATUS_FREE, THRESHOLD - alignedBlockMeta);

		//  Splitting our new block to only use the needed amount
		split_chunk(newBlock, alignedPayload, alignedBlockMeta);

		//  Adding the alloc'd memory in our memory list
		add_block_in_list(&memoryHead, newBlock);

		//  Returning only the needed area
		return (void*)(((char*)area) + alignedBlockMeta);

	} else if (alignedAll < THRESHOLD && heap_preallocation == 1) {
		//  First we expand all available blocks
		expandBlocks(&memoryHead);

		//  Then we look for already free space
		struct block_meta *newBlock = find_block_with_size(memoryHead, alignedPayload);

		if (newBlock == NULL) {
			//  Didn't find any, so we just alloc a new chunk
			void *area = sbrk(alignedAll);
			DIE(area == MAP_FAILED, "ERROR IN ALLOCATION\n");
			newBlock = (struct block_meta *)area;

			//  Setting the metadata
			set_block_meta(newBlock, STATUS_ALLOC, alignedPayload);

			//  Adding the alloc'd memory in our memory list
			add_block_in_list(&memoryHead, newBlock);

			//  Returning only the needed area
			return (void*)((char*)area + alignedBlockMeta);
		} else {
			//  Found some free space
			//  Splitting our new block to only use the needed amount
			split_chunk(newBlock, alignedPayload, alignedBlockMeta);

			//  Block already in list

			//  Returning only the needed area
			return (void*)((char*)newBlock + alignedBlockMeta);
		}
	}

	//  If an error occurs and no ifs are checked, return NULL
	return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */

	//  If pointer is NULL, we exit
	if (ptr == NULL) {
		return;
	}
	
	size_t alignedBlockMeta = align_block(sizeof(struct block_meta));
	struct block_meta *blockPointer = find_the_block_ptr(ptr, alignedBlockMeta);

	//  Check if the pointer is valid
	struct block_meta *iter = memoryHead;

	while (iter != blockPointer && iter != NULL) {
		iter = iter->next;
	}

	//  If the pointer is invalid, we exit the function
	if (iter == NULL) {
		return;
	}

	//  Pointer is valid
	if (blockPointer->status == STATUS_MAPPED) {
		//  If the memory is mapped, we just free it
		remove_block_from_list(&memoryHead, blockPointer);
		int ret = munmap((void *)blockPointer, blockPointer->size + alignedBlockMeta);
		DIE(ret == -1, "ERROR IN MUNMAP\n");

	} else if (blockPointer->size == STATUS_ALLOC) {
		//  If the memory is alloc'd, we keep the block for future allocs
		blockPointer->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
