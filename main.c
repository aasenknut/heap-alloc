#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define HEAP_CAP 55600
#define CHUNK_ARR_CAP 1024


typedef struct {
    uintptr_t *start; //points to location on heap
    size_t size; //size of chunk allocated on heap
} chunk;

// chunk_arr is used for storing allocated chunks, and free chunks.
typedef struct {
    size_t count;
    chunk chunks[CHUNK_ARR_CAP];
} chunk_arr;

uintptr_t heap[HEAP_CAP] = {0};

chunk_arr alloced_chunks = {0};
chunk_arr free_chunks = {
    .count = 1,
    .chunks = {
        [0] = {.start = heap, .size = sizeof(heap)}
    },
};
chunk_arr tmp_chunks = {0};

void dump_chunks(const chunk_arr *arr) {
    printf("\n\nallocated chunks (%zu)", (*arr).count);
    for (size_t j = 0; j < (*arr).count; j++) {
        printf("\nstart: %p - size: %zu",
                (*arr).chunks[j].start, 
                (*arr).chunks[j].size);
    }
}

int find_chunk(const chunk_arr *arr, uintptr_t *ptr) {
    for (size_t j = 0; j < (*arr).count; j++) {
        if ((*arr).chunks[j].start == ptr) {
            return (int) j;
        }
    }
    return -1;
}

void remove_chunk(chunk_arr *arr, size_t idx) {
    assert(idx < (*arr).count);
    for (size_t j = idx; j < (*arr).count; j++) {
        (*arr).chunks[j] = (*arr).chunks[j+1];
    }
    (*arr).count -= 1;
}

// Inserts a chunk into an array of chunks, and sorts the array by pointer value.
void insert_chunk(chunk_arr *arr, void *ptr, size_t chunk_size)
{
    assert((*arr).count < CHUNK_ARR_CAP);
    (*arr).chunks[(*arr).count].start = ptr;
    (*arr).chunks[(*arr).count].size = chunk_size;

    // Make sure the pointer values are sorted, so it's faster to search.
    for (size_t j = (*arr).count; 
            j > 0 && (*arr).chunks[j].start < (*arr).chunks[j-1].start;
            j--) {
        const chunk c = (*arr).chunks[j];
        (*arr).chunks[j] = (*arr).chunks[j-1];
        (*arr).chunks[j] = c;
    }
    (*arr).count++;
}

// If the pointer of a chunk + the size of the chunk is equal to the next
// pointer, then these two chunks can be merged.
// Instead of filling in holes we just append to an auxiliary array and replace
// the original array.
void merge_chunks(chunk_arr *src, chunk_arr *dst) {
    (*dst).count = 0;
    for (size_t j = 0; j < (*src).count; j++) {
        const chunk src_chunk = (*src).chunks[j];

        if ((*dst).count > 0) {
            chunk *last_chunk = &(*dst).chunks[(*dst).count-1];
            if ((*last_chunk).start + (*last_chunk).size  == src_chunk.start) {
                (*last_chunk).size += src_chunk.size;
            } else {
                insert_chunk(dst, src_chunk.start, src_chunk.size);
            }
        } else {
            insert_chunk(dst, src_chunk.start, src_chunk.size);
        }
    }
}

void free_chunk(void *ptr) 
{
    int idx = find_chunk(&alloced_chunks, ptr);
    assert(idx >= 0);
    insert_chunk(&free_chunks,
            alloced_chunks.chunks[idx].start,
            alloced_chunks.chunks[idx].size);
    remove_chunk(&alloced_chunks, (size_t) idx);
}

void *heap_alloc(size_t num_bytes)
{
    // Round up to the nearest number of words needed to allocate the requestd
    // number of bytes. 
    const size_t num_words = (num_bytes + sizeof(uintptr_t)-1) / sizeof(uintptr_t);

    if (num_words > 0) {
        merge_chunks(&free_chunks, &tmp_chunks);
        free_chunks = tmp_chunks;

        for (size_t j = 0; j < free_chunks.count; j++) {
            const chunk chunk = free_chunks.chunks[j];
            if (chunk.size >= num_words) {
                remove_chunk(&free_chunks, j);
                insert_chunk(&alloced_chunks, chunk.start, num_words);

                const size_t excess = chunk.size - num_words;
                if (excess > 0) {
                    insert_chunk(&free_chunks, chunk.start + num_words, excess);
                }
                return chunk.start;
            }
        }
    }
    return NULL;
}

int main()
{
    printf("\nFree chunks count: %zu", free_chunks.count);
    printf("\nHeap size: %zu", sizeof(heap));
    char *a = heap_alloc(16);
    printf("\nalloced bytes: %p", a);
    for (int j=0; j < 16; j++) {
        a[j] = j + 'A';
        printf("\nchar: %c", a[j]);
    }
    //heap_free(a);
    dump_chunks(&alloced_chunks);
    return 0;
}
