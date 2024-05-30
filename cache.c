#include "cache.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

/* Create a cache simulator according to the config */
struct cache *cache_create(struct cache_config config, struct cache *lower_level)
{
    /*YOUR CODE HERE*/
    struct cache *cache_create = (struct cache *)malloc(config.size);

    uint32_t size_of_index;
    uint32_t set_num = config.lines / config.ways;
    while (set_num > 1)
    {
        size_of_index++;
        set_num = set_num / 2;
    }

    uint32_t size_of_offset;
    uint32_t block_size = config.line_size;
    while (block_size > 1)
    {
        size_of_offset++;
        block_size = block_size / 2;
    }

    uint32_t size_of_tag = config.address_bits - size_of_index - size_of_offset;

    cache_create->config = config;
    cache_create->tag_bits = size_of_tag;
    cache_create->tag_mask = ((1 << size_of_tag) - 1) << (size_of_offset + size_of_index);
    cache_create->index_bits = size_of_index;
    cache_create->index_mask = ((1 << size_of_index) - 1) << (size_of_offset);
    cache_create->offset_bits = size_of_offset;
    cache_create->offset_mask = ((1 << size_of_offset) - 1);

    for (uint32_t i = 0; i < config.lines; i++)
    {
        (cache_create->lines)[i].valid = 0;
    }
    for (uint32_t i = 0; i < config.lines; i++)
    {
        (cache_create->lines)[i].dirty = 0;
    }
    for (uint32_t i = 0; i < config.lines; i++)
    {
        (cache_create->lines)[i].tag = 0;
    }
    for (uint32_t i = 0; i < config.lines; i++)
    {
        (cache_create->lines)[i].last_access = 0;
    }
    for (uint32_t i = 0; i < config.lines; i++)
    {
        (cache_create->lines)[i].data = NULL;
    }

    cache_create->lower_cache = lower_level;

    return cache_create;
}

/*
Release the resources allocated for the cache simulator.
Also writeback dirty lines

The order in which lines are evicted is:
set0-slot0, set1-slot0, set2-slot0, (the 0th way)
set0-slot1, set1-slot1, set2-slot1, (the 1st way)
set0-slot2, set1-slot2, set2-slot2, (the 2nd way)
and so on.
*/
void cache_destroy(struct cache *cache)
{
    /*YOUR CODE HERE*/
    free(cache->lines);
    free(cache->lower_cache);
    free(cache);
}

/* Read one byte at a specific address. return hit=true/miss=false */
bool cache_read_byte(struct cache *cache, uint32_t addr, uint8_t *byte)
{
    /*YOUR CODE HERE*/
    uint32_t tag = cache->tag_mask & addr;
    uint32_t index = cache->index_mask & addr;

    for (uint32_t i = (cache->config.ways) * index; i < (cache->config.ways) * (index + 1); i++)
    {
        if ((cache->lines)[i].tag == tag)
        {
            (cache->lines)[i].last_access = get_timestamp();
            *byte = *(cache->lines)[i].data;
            return 1;
        }
    }

    uint32_t v = (cache->config.ways) * index;
    for (uint32_t i = (cache->config.ways) * index; i < (cache->config.ways) * (index + 1); i++)
    {
        if ((cache->lines[i].tag == 0))
        {
            v = i;
            break;
        }
        if ((cache->lines[i].last_access) < (cache->lines[v].last_access))
        {
            v = i;
        }
    }
    struct cache_line *victim = cache->lines + v * (cache->config.line_size);
    uint32_t victim_addr = ((victim->tag) << ((cache->index_bits) + (cache->offset_bits))) + (index << (cache->offset_bits));

    if (cache->lines[v].dirty == 1)
    {
        mem_store(victim->data, victim_addr, cache->config.line_size);
    }

    mem_load(victim->data, addr, cache->config.line_size);

    (cache->lines)[v].last_access = get_timestamp();
    (cache->lines)[v].valid = 1;
    (cache->lines)[v].dirty = 0;

    *byte = *(cache->lines)[v].data;

    return 0;
}

/* Write one byte into a specific address. return hit=true/miss=false*/
bool cache_write_byte(struct cache *cache, uint32_t addr, uint8_t byte)
{
    /*YOUR CODE HERE*/
    uint32_t tag = cache->tag_mask & addr;
    uint32_t index = cache->index_mask & addr;

    for (uint32_t i = (cache->config.ways) * index; i < (cache->config.ways) * (index + 1); i++)
    {

        if ((cache->lines)[i].tag == tag && ((cache->lines)[i].valid == 1))
        {
            (cache->lines)[i].last_access = get_timestamp();
            return 1;
        }
    }

    uint32_t v = cache->config.ways * index;
    for (uint32_t i = (cache->config.ways) * index; i < (cache->config.ways) * (index + 1); i++)
    {
        if ((cache->lines[i].tag == 0))
        {
            v = i;
            break;
        }
        if ((cache->lines[i].last_access) < (cache->lines[v].last_access))
        {
            v = i;
        }
    }
    struct cache_line *victim = cache->lines + v * cache->config.line_size;
    uint32_t victim_addr = ((victim->tag) << ((cache->index_bits) + (cache->offset_bits))) + (index << (cache->offset_bits));

    if (cache->lines[v].dirty == 1)
    {
        mem_store(victim->data, victim_addr, cache->config.line_size);
    }

    mem_load(victim->data, addr, cache->config.line_size);

    cache->lines[v].last_access = get_timestamp();
    (cache->lines)[v].valid = 1;
    if (cache->config.write_back == 1)
    {
        cache->lines[v].dirty = 1;
    }

    *(cache->lines[v]).data = byte;

    return 0;
}
