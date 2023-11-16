// SPDX-License-Identifier: BSD-3-Clause

#include "util.h"

//  Global list of allocated memory
struct block_meta *memoryHead;

//  Heap preallocation happens only once, so we set a global index
int heap_preallocation;

//  Making the given size a multiple of 8 bytes
size_t align_block(size_t size)
{
	if (size % 8 == 0)
		return size;

	return size + (ALIGNMENT_8_BYTE - size % ALIGNMENT_8_BYTE);
}

//  Add a new meta block in memory list
void add_block_in_list(struct block_meta **memoryHead, struct block_meta *newBlock)
{
	//  Check to see if it's the first alloc
	if (*memoryHead == NULL) {
		*memoryHead = newBlock;
		return;
	}
	struct block_meta *iter = *memoryHead;

	//  Adding mapped memory before alloc'd memory in list

	//  Add mapped element
	if (newBlock->status == STATUS_MAPPED) {
		//  First element is mapped
		if (iter->status == STATUS_MAPPED) {
			//  We add newBlock after last mapped element
			while (iter->next != NULL && iter->next->status == STATUS_MAPPED)
				iter = iter->next;

			newBlock->next = iter->next;
			newBlock->next->prev = newBlock;
			iter->next = newBlock;
			newBlock->prev = iter;
		//  First element is alloc'd
		} else {
			//  We add newBlock at the beginning of the list
			newBlock->prev = NULL;
			newBlock->next = iter;
			*memoryHead = newBlock;
		}
	//  Add alloc'd element
	} else {
		//  Add element at the end of the list
		while (iter->next != NULL)
			iter = iter->next;

		iter->next = newBlock;
		newBlock->prev = iter;
		newBlock->next = NULL;
	}
}

void set_block_meta(struct block_meta *newBlock, int status, size_t size)
{
	newBlock->status = status;
	newBlock->size = size;
	newBlock->next = NULL;
}

struct block_meta *split_chunk(struct block_meta *newBlock, size_t neededSize, size_t alignedBlockMeta)
{
	if (newBlock->size >= neededSize + alignedBlockMeta + ALIGNED_BYTE) {
		//  Add a new meta block after the needed payload
		struct block_meta *newSplitBlock;

		newSplitBlock = (struct block_meta *)((char *)newBlock + alignedBlockMeta + neededSize);

		//  Declare the remaining space as unused and update info
		newSplitBlock->next = newBlock->next;
		newSplitBlock->prev = newBlock;
		newSplitBlock->size = newBlock->size - neededSize - alignedBlockMeta;
		newSplitBlock->status = STATUS_FREE;

		//  Connect the two new blocks in list and update new block
		newBlock->next = newSplitBlock;
		newBlock->size = neededSize;
		newBlock->status = STATUS_ALLOC;
	}

	return newBlock;
}

struct block_meta *find_block_with_size(struct block_meta **memoryHead, size_t size)
{
	if (*memoryHead == NULL)
		return NULL;

	struct block_meta *iter = *memoryHead;
	struct block_meta *iterNext = iter->next;
	size_t alignedBlockMeta = align_block(sizeof(struct block_meta));

	//  Coalesce all free adjacent blocks
	//  We use iterNext to traverse the list and iter->next to remove pointers
	while (iter != NULL && iterNext != NULL) {
		if (iter->status == STATUS_FREE && iterNext->status == STATUS_FREE) {
			iter->size += (alignedBlockMeta + iterNext->size);
			iter->next = iter->next->next;
			iterNext = iter->next;
		} else {
			iter = iterNext;
			iterNext = iterNext->next;
		}
	}

	struct block_meta *best_block = NULL;

	//  Return the free block with the least memory
	iter = *memoryHead;
	while (iter != NULL) {
		if (iter->status == STATUS_FREE && iter->size >= size) {
			if (best_block == NULL)
				best_block = iter;
			else if (best_block->size > iter->size)
				best_block = iter;
		}
		iter = iter->next;
	}

	//  If no block was found, we can try expanding last brk block
	if (best_block == NULL) {
		iter = *memoryHead;
		while (iter->next != NULL)
			iter = iter->next;

		if (iter->status == STATUS_FREE) {
			void *area = sbrk(align_block(size - iter->size));

			DIE(area == MAP_FAILED, "Error in expanding the last block");

			set_block_meta(iter, STATUS_ALLOC, size);

			return iter;
		}
	} else {
		best_block->status = STATUS_ALLOC;
	}

	//  Return the block or NULL
	return best_block;
}

struct block_meta *find_the_block_ptr(void *ptr, size_t alignedBlockMeta)
{
	return (struct block_meta *)(((char *)ptr) - alignedBlockMeta);
}

void remove_block_from_list(struct block_meta **memoryHead, struct block_meta *block)
{
	if ((*memoryHead) == block) {
		//  If the block is first in list, we just move the head
		(*memoryHead) = (*memoryHead)->next;
		return;

	} else {
		struct block_meta *iter = *memoryHead;

		while (iter->next != block && iter->next != NULL)
			iter = iter->next;

		//  Not found
		if (iter->next == NULL)
			return;

		// Found
		iter->next = block->next;
		block->next->prev = iter->next;
	}
}

void *malloc_calloc_implementation(size_t size, size_t threshold)
{
	if (size == 0)
		return NULL;

	//  Alloc'd block is alligned to 8 bytes
	size_t alignedBlockMeta = align_block(sizeof(struct block_meta));
	size_t alignedPayload = align_block(size);
	size_t alignedAll = alignedPayload + alignedBlockMeta;

	if (alignedAll < threshold && heap_preallocation == 0) {
		//  First and only prealloc
		heap_preallocation = 1;

		//  Alloc memory, check alloc, create meta data
		void *area = sbrk(THRESHOLD);

		DIE(area == MAP_FAILED, "ERROR IN PREALLOCATION\n");

		struct block_meta *newBlock = (struct block_meta *)area;

		//  Setting the metadata
		set_block_meta(newBlock, STATUS_ALLOC, THRESHOLD - alignedBlockMeta);

		//  Adding the alloc'd memory in our memory list
		add_block_in_list(&memoryHead, newBlock);

		//  Returning only the needed area
		return (void *)(((char *)newBlock) + alignedBlockMeta);

	} else if (alignedAll < threshold && heap_preallocation == 1) {
		//  First we look for already free space
		struct block_meta *newBlock = find_block_with_size(&memoryHead, alignedPayload);

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
			return (void *)((char *)newBlock + alignedBlockMeta);
		}

		//  Found some free space
		//  Splitting our new block to only use the needed amount
		struct block_meta *ret = split_chunk(newBlock, alignedPayload, alignedBlockMeta);

		//  Block already in list

		//  Returning only the needed area
		return (void *)((char *)ret + alignedBlockMeta);

	} else if (alignedAll >= threshold) {
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
	}

	//  If an error occurs and no ifs are checked, return NULL
	return NULL;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	return malloc_calloc_implementation(size, THRESHOLD);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */

	//  If pointer is NULL, we exit
	if (ptr == NULL)
		return;

	size_t alignedBlockMeta = align_block(sizeof(struct block_meta));
	struct block_meta *blockPointer = find_the_block_ptr(ptr, alignedBlockMeta);

	if (blockPointer->status == STATUS_MAPPED) {
		//  If the memory is mapped, we just free it
		remove_block_from_list(&memoryHead, blockPointer);
		int ret = munmap((void *)blockPointer, blockPointer->size + alignedBlockMeta);

		DIE(ret == -1, "ERROR IN MUNMAP\n");

	} else if (blockPointer->status == STATUS_ALLOC) {
		//  If the memory is alloc'd, we keep the block for future allocs
		blockPointer->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	size_t alignedSize = align_block(nmemb * size);
	void *pointer = malloc_calloc_implementation(alignedSize, getpagesize());

	memset(pointer, 0, align_block(nmemb * size));

	return pointer;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */

	//  There are 2 cases
	//  Case 1: mapped memory expansion/reduction
	//  Case 2: brk memory expansion/reduction

	//  NULL pointer needs completely new allocation
	if (ptr == NULL)
		return os_malloc(size);

	//  Size 0 means free
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	size_t alignedBlockMeta = align_block(sizeof(struct block_meta));
	size_t alignedPayload = align_block(size);
	size_t alignedAll = alignedBlockMeta + alignedPayload;
	struct block_meta *oldBlock = find_the_block_ptr(ptr, alignedBlockMeta);

	//  Same size doesn't require realloc
	if (oldBlock->size == alignedPayload)
		return ptr;

	//  Case 1
	//  Mapped memory or memory exceeding threshold gets (re)mapped
	if (oldBlock->status == STATUS_MAPPED || alignedAll >= THRESHOLD) {
		//  Map new area
		void *area = os_malloc(alignedPayload);

		//  Copy the data
		if (oldBlock->size < alignedPayload) {
			//  Expansion
			memcpy(area, ptr, oldBlock->size);
		} else {
			//  Reduction
			memcpy(area, ptr, alignedPayload);
		}

		//  Free the old block
		os_free(ptr);

		return area;
	}

	//  Case 2
	if (oldBlock->status == STATUS_ALLOC) {
		struct block_meta *adjBlock = oldBlock->next;
		struct block_meta *newBlock = NULL;

		if (oldBlock->size < alignedPayload) {
			//  We check to see if we can merge blocks
			//  Merge as many blocks as needed
			while (adjBlock != NULL && adjBlock->status == STATUS_FREE) {
				oldBlock->size += adjBlock->size + alignedBlockMeta;
				adjBlock = adjBlock->next;
				oldBlock->next = adjBlock;

				if (oldBlock->size >= alignedPayload) {
					newBlock = split_chunk(oldBlock, alignedPayload, alignedBlockMeta);
					return (void *)(((char *)newBlock) + alignedBlockMeta);
				}
			}

			//  If we can't merge, we try to expand the block (only if it's the last)
			if (oldBlock->next == NULL) {
				void *area = sbrk(alignedPayload - oldBlock->size);

				DIE(area == MAP_FAILED, "Error in expanding the last block");

				//  Update the meta block
				set_block_meta(oldBlock, STATUS_ALLOC, alignedPayload);

				return (void *)(((char *)oldBlock) + alignedBlockMeta);
			}

			//  We can't do anything so we just alloc a new chunk
			void *area = os_malloc(size);

			memcpy(area, ptr, oldBlock->size);

			//  Free the old block
			os_free(ptr);

			return area;

		//  Memory reduction
		} else {
			struct block_meta *newBlock = split_chunk(oldBlock, alignedPayload, alignedBlockMeta);

			return (void *)(((char *)newBlock) + alignedBlockMeta);
		}
	}

	return NULL;
}
