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

#[test]
fn test_exec_mark_plugin() {
    init();

    let exec_factory =
        factory::get_exec_plugin_factory("mark").expect("mark exec factory should be registered");

    // Test boolean mark
    let plugin = exec_factory
        .create("mark", "vip_customer")
        .expect("exec plugin creation should succeed");
    assert_eq!(plugin.name(), "mark");

    // Test mark with value
    let plugin = exec_factory
        .create("mark", "priority high")
        .expect("exec plugin creation should succeed");
    assert_eq!(plugin.name(), "mark");

    // Test mark with multi-word value
    let plugin = exec_factory
        .create("mark", "status very important")
        .expect("exec plugin creation should succeed");
    assert_eq!(plugin.name(), "mark");
}

#[test]
fn test_exec_return_plugin() {
    init();

    let exec_factory = factory::get_exec_plugin_factory("return")
        .expect("return exec factory should be registered");

    // Test return plugin (no arguments)
    let plugin = exec_factory
        .create("return", "")
        .expect("exec plugin creation should succeed");
    assert_eq!(plugin.name(), "return");
}

#[test]
fn test_acl_plugin_from_builder() {
    init();

    let mut config_map = HashMap::new();
    config_map.insert(
        "default".to_string(),
        serde_yaml::Value::String("deny".to_string()),
    );

    let rules = vec![
        serde_yaml::Value::Mapping({
            let mut rule = serde_yaml::Mapping::new();
            rule.insert(
                serde_yaml::Value::String("network".to_string()),
                serde_yaml::Value::String("192.168.0.0/16".to_string()),
            );
            rule.insert(
                serde_yaml::Value::String("action".to_string()),
                serde_yaml::Value::String("allow".to_string()),
            );
            rule
        }),
        serde_yaml::Value::Mapping({
            let mut rule = serde_yaml::Mapping::new();
            rule.insert(
                serde_yaml::Value::String("network".to_string()),
                serde_yaml::Value::String("10.0.0.0/8".to_string()),
            );
            rule.insert(
                serde_yaml::Value::String("action".to_string()),
                serde_yaml::Value::String("allow".to_string()),
            );
            rule
        }),
    ];
    config_map.insert("rules".to_string(), serde_yaml::Value::Sequence(rules));

    let config = PluginConfig {
        tag: Some("test_acl".to_string()),
        plugin_type: "query_acl".to_string(),
        args: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        priority: 100,
        config: config_map,
    };

    let builder_obj =
        factory::get_plugin_factory("query_acl").expect("query_acl builder should be registered");
    let plugin = builder_obj
        .create(&config)
        .expect("plugin creation should succeed");

    assert_eq!(plugin.name(), "query_acl");
}
