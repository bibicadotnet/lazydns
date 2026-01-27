//! Top-N tracking algorithm
//!
//! Efficiently tracks the top N items by count using a min-heap.

use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::hash::Hash;

/// Top-N tracker using count-min sketch approximation with exact top tracking
#[derive(Debug)]
pub struct TopN<K: Hash + Eq + Clone> {
    /// Maximum number of items to track
    n: usize,
    /// Item counts
    counts: RwLock<HashMap<K, u64>>,
    /// Maximum items to keep before pruning
    max_items: usize,
}

impl<K: Hash + Eq + Clone> TopN<K> {
    /// Create a new TopN tracker
    pub fn new(n: usize) -> Self {
        Self {
            n,
            counts: RwLock::new(HashMap::new()),
            // Keep 10x items before pruning to avoid frequent pruning
            max_items: n * 10,
        }
    }

    /// Create with custom max items before pruning
    pub fn with_max_items(n: usize, max_items: usize) -> Self {
        Self {
            n,
            counts: RwLock::new(HashMap::new()),
            max_items,
        }
    }

    /// Increment the count for a key
    pub fn increment(&self, key: K) {
        self.add(key, 1);
    }

    /// Add a count for a key
    pub fn add(&self, key: K, count: u64) {
        let mut counts = self.counts.write();
        *counts.entry(key).or_insert(0) += count;

        // Prune if too many items
        if counts.len() > self.max_items {
            self.prune_locked(&mut counts);
        }
    }

    /// Prune to keep only top items (requires write lock already held)
    fn prune_locked(&self, counts: &mut HashMap<K, u64>) {
        if counts.len() <= self.n * 2 {
            return;
        }

        // Find threshold (n-th largest count)
        let mut count_values: Vec<u64> = counts.values().copied().collect();
        count_values.sort_unstable_by(|a, b| b.cmp(a));

        if let Some(&threshold) = count_values.get(self.n * 2) {
            counts.retain(|_, &mut v| v > threshold);
        }
    }

    /// Get the top N items with their counts
    pub fn top(&self) -> Vec<(K, u64)> {
        let counts = self.counts.read();
        let mut items: Vec<(K, u64)> = counts.iter().map(|(k, &v)| (k.clone(), v)).collect();

        // Sort by count descending
        items.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        // Take top N
        items.truncate(self.n);
        items
    }

    /// Get the count for a specific key
    pub fn get(&self, key: &K) -> u64 {
        self.counts.read().get(key).copied().unwrap_or(0)
    }

    /// Get total count of all items
    pub fn total(&self) -> u64 {
        self.counts.read().values().sum()
    }

    /// Get number of unique items tracked
    pub fn len(&self) -> usize {
        self.counts.read().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.counts.read().is_empty()
    }

    /// Clear all counts
    pub fn clear(&self) {
        self.counts.write().clear();
    }

    /// Merge another TopN into this one
    pub fn merge(&self, other: &TopN<K>) {
        let other_counts = other.counts.read();
        let mut self_counts = self.counts.write();

        for (key, count) in other_counts.iter() {
            *self_counts.entry(key.clone()).or_insert(0) += count;
        }

        if self_counts.len() > self.max_items {
            self.prune_locked(&mut self_counts);
        }
    }
}

impl<K: Hash + Eq + Clone + Serialize> TopN<K> {
    /// Get top N as serializable entries
    pub fn top_entries(&self) -> Vec<TopNEntry<K>> {
        self.top()
            .into_iter()
            .enumerate()
            .map(|(rank, (key, count))| TopNEntry {
                rank: rank + 1,
                key,
                count,
            })
            .collect()
    }
}

/// A single entry in the top-N list
#[derive(Debug, Clone, Serialize)]
pub struct TopNEntry<K> {
    pub rank: usize,
    pub key: K,
    pub count: u64,
}

/// Specialized TopN for domain tracking
pub type TopDomains = TopN<String>;

/// Specialized TopN for client IP tracking
pub type TopClients = TopN<String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_increment() {
        let top = TopN::new(3);
        top.increment("a".to_string());
        top.increment("a".to_string());
        top.increment("b".to_string());

        assert_eq!(top.get(&"a".to_string()), 2);
        assert_eq!(top.get(&"b".to_string()), 1);
        assert_eq!(top.get(&"c".to_string()), 0);
    }

    #[test]
    fn test_top_n() {
        let top = TopN::new(2);
        top.add("a".to_string(), 100);
        top.add("b".to_string(), 50);
        top.add("c".to_string(), 200);
        top.add("d".to_string(), 10);

        let result = top.top();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "c");
        assert_eq!(result[0].1, 200);
        assert_eq!(result[1].0, "a");
        assert_eq!(result[1].1, 100);
    }

    #[test]
    fn test_total() {
        let top = TopN::new(10);
        top.add("a".to_string(), 10);
        top.add("b".to_string(), 20);
        top.add("c".to_string(), 30);

        assert_eq!(top.total(), 60);
    }

    #[test]
    fn test_prune() {
        let top = TopN::with_max_items(2, 5);

        for i in 0..20 {
            top.add(format!("item{}", i), i as u64);
        }

        // Should have pruned to keep only high-count items
        assert!(top.len() <= 10); // Should be around 2*n after pruning
    }

    #[test]
    fn test_merge() {
        let top1 = TopN::new(5);
        top1.add("a".to_string(), 10);
        top1.add("b".to_string(), 20);

        let top2 = TopN::new(5);
        top2.add("a".to_string(), 5);
        top2.add("c".to_string(), 30);

        top1.merge(&top2);

        assert_eq!(top1.get(&"a".to_string()), 15);
        assert_eq!(top1.get(&"b".to_string()), 20);
        assert_eq!(top1.get(&"c".to_string()), 30);
    }
}
