// Copyright (c) 2014, Cloudera, inc.
// Confidential Cloudera Information: Covered by NDA.

#include "kudu/util/cache_metrics.h"

#include "kudu/util/metrics.h"

METRIC_DEFINE_counter(server, block_cache_inserts,
                      "Block Cache Inserts", kudu::MetricUnit::kBlocks,
                      "Number of blocks inserted in the cache");
METRIC_DEFINE_counter(server, block_cache_lookups,
                      "Block Cache Lookups", kudu::MetricUnit::kBlocks,
                      "Number of blocks looked up from the cache");
METRIC_DEFINE_counter(server, block_cache_evictions,
                      "Block Cache Evictions", kudu::MetricUnit::kBlocks,
                      "Number of blocks evicted from the cache");
METRIC_DEFINE_counter(server, block_cache_misses,
                      "Block Cache Misses", kudu::MetricUnit::kBlocks,
                      "Number of lookups that didn't yield a block");
METRIC_DEFINE_counter(server, block_cache_misses_caching,
                      "Block Cache Misses (Caching)", kudu::MetricUnit::kBlocks,
                      "Number of lookups that were expecting a block that didn't yield one."
                      "Use this number instead of cache_misses when trying to determine how "
                      "efficient the cache is");
METRIC_DEFINE_counter(server, block_cache_hits,
                      "Block Cache Hits", kudu::MetricUnit::kBlocks,
                      "Number of lookups that found a block");
METRIC_DEFINE_counter(server, block_cache_hits_caching,
                      "Block Cache Hits (Caching)", kudu::MetricUnit::kBlocks,
                      "Number of lookups that were expecting a block that found one."
                      "Use this number instead of cache_hits when trying to determine how "
                      "efficient the cache is");

METRIC_DEFINE_gauge_uint64(server, block_cache_usage, "Block Cache Memory Usage",
                           kudu::MetricUnit::kBytes,
                           "Memory consumed by the block cache");

namespace kudu {

#define MINIT(member, x) member(METRIC_##x.Instantiate(entity))
#define GINIT(member, x) member(METRIC_##x.Instantiate(entity, 0))
CacheMetrics::CacheMetrics(const scoped_refptr<MetricEntity>& entity)
  : MINIT(inserts, block_cache_inserts),
    MINIT(lookups, block_cache_lookups),
    MINIT(evictions, block_cache_evictions),
    MINIT(cache_hits, block_cache_hits),
    MINIT(cache_hits_caching, block_cache_hits_caching),
    MINIT(cache_misses, block_cache_misses),
    MINIT(cache_misses_caching, block_cache_misses_caching),
    GINIT(cache_usage, block_cache_usage) {
}
#undef MINIT
#undef GINIT

} // namespace kudu
