## Root Cause: Cache Poisoning Bug

The issue was in cache.rs, where the cache plugin computes the cache key once at the beginning of execution but doesn't recompute it before storing responses in Phase 2.

### The Attack Chain:

1. Query arrives for release-assets.githubusercontent.com
2. Cache plugin computes key: release-assets.githubusercontent.com:1:1 (Phase 1)
3. Cache miss → continues downstream
4. Redirect plugin modifies the question to ping.archlinux.org
5. Forward plugin resolves modified domain, gets CNAME response
6. BUG: Cache plugin stores the ping.archlinux.org response under the OLD key release-assets.githubusercontent.com:1:1
7. Poisoned!: Next query for release-assets.githubusercontent.com returns the wrong ping.archlinux.org CNAME

### The Fix

I modified cache.rs to recompute the cache key in Phase 2 based on the current (potentially modified) request:

Then use phase2_key instead of the original key when storing both negative and positive responses.

#### Changes made:

Line 1176-1190: Added Phase 2 cache key recomputation
Line 1207: Use phase2_key for negative caching
Line 1243: Use phase2_key for positive caching
Line 1236: Updated debug log to show phase2_key
