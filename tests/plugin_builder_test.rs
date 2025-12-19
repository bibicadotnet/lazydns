//! Integration tests for the plugin builder system

use lazydns::config::types::PluginConfig;
use lazydns::plugin::factory;
use lazydns::plugin::factory::init;
use std::collections::HashMap;

#[test]
fn test_create_cache_plugin_from_builder() {
    init();

    let mut config_map = HashMap::new();
    config_map.insert("size".to_string(), serde_yaml::Value::Number(2048.into()));

    let config = PluginConfig {
        tag: Some("test_cache".to_string()),
        plugin_type: "cache".to_string(),
        args: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        name: Some("test_cache".to_string()),
        priority: 100,
        config: config_map,
    };

    let builder_obj =
        factory::get_plugin_factory("cache").expect("cache builder should be registered");
    let plugin = builder_obj
        .create(&config)
        .expect("plugin creation should succeed");

    assert_eq!(plugin.name(), "cache");
}

#[test]
fn test_create_forward_plugin_from_builder() {
    init();

    let mut config_map = HashMap::new();
    let upstreams = vec![
        serde_yaml::Value::String("8.8.8.8:53".to_string()),
        serde_yaml::Value::String("8.8.4.4:53".to_string()),
    ];
    config_map.insert(
        "upstreams".to_string(),
        serde_yaml::Value::Sequence(upstreams),
    );

    let config = PluginConfig {
        tag: Some("test_forward".to_string()),
        plugin_type: "forward".to_string(),
        args: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        name: Some("test_forward".to_string()),
        priority: 100,
        config: config_map,
    };

    let builder_obj =
        factory::get_plugin_factory("forward").expect("forward builder should be registered");
    let plugin = builder_obj
        .create(&config)
        .expect("plugin creation should succeed");

    assert_eq!(plugin.name(), "forward");
}

#[test]
fn test_builder_not_found() {
    init();

    let result = factory::get_plugin_factory("nonexistent_plugin");
    assert!(result.is_none());
}

#[test]
fn test_builder_thread_safety() {
    use std::thread;

    init();

    let handles: Vec<_> = (0..10)
        .map(|_| {
            thread::spawn(|| {
                let types = factory::get_all_plugin_types();
                assert!(!types.is_empty());
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}
