//! Executable cache wrappers
//!
//! Thin executable wrappers around the core `CachePlugin` and `CacheStorePlugin` so
//! they can be used in executable plugin chains (quick-setup style).

use crate::plugin::{Context, Plugin};
use crate::Result;
use async_trait::async_trait;
use std::fmt;

/// Wrapper that delegates to `crate::plugins::CachePlugin` for checking cache.
pub struct ExecCache {
    inner: crate::plugins::CachePlugin,
}

impl ExecCache {
    /// Create with a maximum size
    pub fn new(size: usize) -> Self {
        Self {
            inner: crate::plugins::CachePlugin::new(size),
        }
    }

    /// Quick setup from string like the upstream: `[size]`
    pub fn quick_setup(s: &str) -> Result<Self> {
        let size = if s.is_empty() {
            1024
        } else {
            s.parse::<usize>().unwrap_or(1024)
        };
        Ok(Self::new(size))
    }
}

impl fmt::Debug for ExecCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecCache").finish()
    }
}

#[async_trait]
impl Plugin for ExecCache {
    fn name(&self) -> &str {
        "cache"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        // Delegate to inner cache plugin
        self.inner.execute(ctx).await
    }
}

/// Wrapper that delegates to `crate::plugins::CacheStorePlugin` to store responses.
pub struct ExecCacheStore {
    inner: crate::plugins::CacheStorePlugin,
}

impl ExecCacheStore {
    /// Create a new store wrapper that shares storage with provided cache plugin
    pub fn new_from_cache(cache: &crate::plugins::CachePlugin) -> Self {
        Self {
            inner: crate::plugins::CacheStorePlugin::new(cache),
        }
    }

    /// Quick setup: create a cache and corresponding store plugin
    pub fn quick_setup(s: &str) -> Result<Self> {
        let size = if s.is_empty() {
            1024
        } else {
            s.parse::<usize>().unwrap_or(1024)
        };
        let cache = crate::plugins::CachePlugin::new(size);
        Ok(Self::new_from_cache(&cache))
    }
}

impl fmt::Debug for ExecCacheStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecCacheStore").finish()
    }
}

#[async_trait]
impl Plugin for ExecCacheStore {
    fn name(&self) -> &str {
        "cache_store"
    }

    async fn execute(&self, ctx: &mut Context) -> Result<()> {
        self.inner.execute(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Message;

    #[tokio::test]
    async fn test_exec_cache_quick_setup() {
        let exec = ExecCache::quick_setup("").unwrap();
        let mut ctx = Context::new(Message::new());
        // executing should not panic; cache will be a miss
        let _ = exec.execute(&mut ctx).await;
    }

    #[tokio::test]
    async fn test_exec_cache_store_quick_setup() {
        let store = ExecCacheStore::quick_setup("").unwrap();
        let mut ctx = Context::new(Message::new());
        // nothing to store, but should not panic
        let _ = store.execute(&mut ctx).await;
    }
}
