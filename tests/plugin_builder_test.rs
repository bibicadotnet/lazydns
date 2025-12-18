//! Integration tests for the plugin builder system

use lazydns::config::types::PluginConfig;
use lazydns::plugin::factory;
use lazydns::plugin::factory::initialize_all_factories;
use std::collections::HashMap;

#[test]
fn test_builder_initialization() {
    // Initialize builders
    initialize_all_factories();

    // Verify that builders are registered
    let types = factory::get_all_plugin_types();

    println!("Registered plugin types: {:?}", types);

    // Should have at least cache, forward, accept, reject, return, jump
    assert!(types.contains(&"cache".to_string()));
    assert!(types.contains(&"forward".to_string()));
    assert!(types.contains(&"accept".to_string()));
    assert!(types.contains(&"reject".to_string()));
    assert!(types.contains(&"return".to_string()));
    assert!(types.contains(&"jump".to_string()));
}

#[test]
fn test_create_cache_plugin_from_builder() {
    initialize_all_factories();

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
    initialize_all_factories();

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
fn test_create_reject_plugin_from_builder() {
    initialize_all_factories();

    let mut config_map = HashMap::new();
    config_map.insert("rcode".to_string(), serde_yaml::Value::Number(3.into()));

    let config = PluginConfig {
        tag: Some("test_reject".to_string()),
        plugin_type: "reject".to_string(),
        args: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        name: Some("test_reject".to_string()),
        priority: 100,
        config: config_map,
    };

    let builder_obj =
        factory::get_plugin_factory("reject").expect("reject builder should be registered");
    let plugin = builder_obj
        .create(&config)
        .expect("plugin creation should succeed");

    assert_eq!(plugin.name(), "reject");
}

#[test]
fn test_control_flow_plugins_from_builder() {
    initialize_all_factories();

    // Test accept
    let accept_config = PluginConfig::new("accept".to_string());
    let accept_builder = factory::get_plugin_factory("accept").expect("accept builder");
    let accept_plugin = accept_builder.create(&accept_config).unwrap();
    assert_eq!(accept_plugin.name(), "accept");

    // Test return
    let return_config = PluginConfig::new("return".to_string());
    let return_builder = factory::get_plugin_factory("return").expect("return builder");
    let return_plugin = return_builder.create(&return_config).unwrap();
    assert_eq!(return_plugin.name(), "return");

    // Test drop_resp
    let drop_config = PluginConfig::new("drop_resp".to_string());
    let drop_builder = factory::get_plugin_factory("drop_resp").expect("drop_resp builder");
    let drop_plugin = drop_builder.create(&drop_config).unwrap();
    assert_eq!(drop_plugin.name(), "drop_resp");
}

#[test]
fn test_jump_plugin_from_builder() {
    initialize_all_factories();

    let mut config_map = HashMap::new();
    config_map.insert(
        "target".to_string(),
        serde_yaml::Value::String("some_sequence".to_string()),
    );

    let config = PluginConfig {
        tag: Some("test_jump".to_string()),
        plugin_type: "jump".to_string(),
        args: serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        name: Some("test_jump".to_string()),
        priority: 100,
        config: config_map,
    };

    let builder_obj =
        factory::get_plugin_factory("jump").expect("jump builder should be registered");
    let plugin = builder_obj
        .create(&config)
        .expect("plugin creation should succeed");

    assert_eq!(plugin.name(), "jump");
}

#[tokio::test]
async fn test_plugin_from_builder_executes() {
    use lazydns::dns::Message;
    use lazydns::plugin::Context;

    initialize_all_factories();

    let config = PluginConfig::new("accept".to_string());
    let builder_obj = factory::get_plugin_factory("accept").expect("accept builder");
    let plugin = builder_obj.create(&config).unwrap();

    let mut ctx = Context::new(Message::new());
    plugin.execute(&mut ctx).await.unwrap();
}

#[test]
fn test_builder_not_found() {
    initialize_all_factories();

    let result = factory::get_plugin_factory("nonexistent_plugin");
    assert!(result.is_none());
}

#[test]
fn test_builder_thread_safety() {
    use std::thread;

    initialize_all_factories();

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
