use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, parse_macro_input};

/// Derive macro to auto-generate plugin factory registration code
///
/// This macro:
/// 1. Generates a factory wrapper struct
/// 2. Derives the canonical plugin name from the type name (PascalCase -> snake_case, strip "Plugin" suffix)
/// 3. Adds the factory to the distributed slice for automatic registration
///
/// # Example
///
/// ```ignore
/// #[derive(RegisterPlugin)]
/// struct MyPlugin;
///
/// impl Plugin for MyPlugin {
///     async fn execute(&self, ctx: &mut Context) -> Result<()> { Ok(()) }
///     fn name(&self) -> &str { "my_plugin" }
///     fn init(config: &PluginConfig) -> Result<Arc<dyn Plugin>> { Ok(Arc::new(Self)) }
///     fn aliases(&self) -> &'static [&'static str] { &[] }
/// }
/// ```
#[proc_macro_derive(RegisterPlugin)]
pub fn derive_register_plugin(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let plugin_type = &input.ident;
    let plugin_type_string = plugin_type.to_string();

    // Generate identifiers
    let factory_wrapper = format_ident!("{}FactoryWrapper", plugin_type);
    let register_fn = format_ident!("__register_plugin_factory_{}", plugin_type_string);

    // Generate the factory wrapper and distributed slice submission
    let expanded = quote! {
        // Factory wrapper struct
        #[derive(Default)]
        struct #factory_wrapper;

        impl crate::plugin::factory::PluginFactory for #factory_wrapper {
            fn create(
                &self,
                config: &crate::config::types::PluginConfig,
            ) -> crate::Result<std::sync::Arc<dyn crate::plugin::Plugin>> {
                <#plugin_type as crate::plugin::Plugin>::init(config)
            }

            fn plugin_type(&self) -> &'static str {
                // Cache the derived name
                static DERIVED_NAME: once_cell::sync::Lazy<&'static str> =
                    once_cell::sync::Lazy::new(|| {
                        let t = std::any::type_name::<#plugin_type>();
                        let last = t.rsplit("::").next().unwrap_or(t);
                        let base = last.strip_suffix("Plugin").unwrap_or(last);
                        // PascalCase/CamelCase -> snake_case
                        let mut s = String::new();
                        for (i, ch) in base.chars().enumerate() {
                            if ch.is_uppercase() {
                                if i != 0 {
                                    s.push('_');
                                }
                                for lc in ch.to_lowercase() {
                                    s.push(lc);
                                }
                            } else {
                                s.push(ch);
                            }
                        }
                        Box::leak(s.into_boxed_str())
                    });

                DERIVED_NAME.clone()
            }

            fn aliases(&self) -> &'static [&'static str] {
                <#plugin_type as crate::plugin::Plugin>::aliases()
            }
        }

        // Submit factory constructor to distributed slice
        #[linkme::distributed_slice(crate::plugin::factory::PLUGIN_FACTORIES_SLICE)]
        fn #register_fn() -> std::sync::Arc<dyn crate::plugin::factory::PluginFactory> {
            std::sync::Arc::new(#factory_wrapper::default())
        }
    };

    TokenStream::from(expanded)
}

/// Derive macro to auto-generate exec plugin factory registration code
///
/// Similar to RegisterPlugin but for exec plugins.
///
/// # Example
///
/// ```ignore
/// #[derive(RegisterExecPlugin)]
/// struct MyExecPlugin;
///
/// impl Plugin for MyExecPlugin {
///     async fn execute(&self, ctx: &mut Context) -> Result<()> { Ok(()) }
///     fn name(&self) -> &str { "my_exec_plugin" }
/// }
///
/// impl ExecPlugin for MyExecPlugin {
///     fn quick_setup(prefix: &str, exec_str: &str) -> Result<Arc<dyn Plugin>> { Ok(Arc::new(Self)) }
/// }
/// ```
#[proc_macro_derive(RegisterExecPlugin)]
pub fn derive_register_exec_plugin(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let plugin_type = &input.ident;
    let plugin_type_string = plugin_type.to_string();

    // Generate identifiers
    let factory_wrapper = format_ident!("{}ExecFactoryWrapper", plugin_type);
    let register_fn = format_ident!("__register_exec_plugin_factory_{}", plugin_type_string);

    // Generate the exec factory wrapper and distributed slice submission
    let expanded = quote! {
        // Exec factory wrapper struct
        #[derive(Default)]
        struct #factory_wrapper;

        impl crate::plugin::factory::ExecPluginFactory for #factory_wrapper {
            fn create(
                &self,
                prefix: &str,
                exec_str: &str,
            ) -> crate::Result<std::sync::Arc<dyn crate::plugin::Plugin>> {
                <#plugin_type as crate::plugin::ExecPlugin>::quick_setup(prefix, exec_str)
            }

            fn plugin_type(&self) -> &'static str {
                // Cache the derived name (same logic as RegisterPlugin)
                static DERIVED_NAME: once_cell::sync::Lazy<&'static str> =
                    once_cell::sync::Lazy::new(|| {
                        let t = std::any::type_name::<#plugin_type>();
                        let last = t.rsplit("::").next().unwrap_or(t);
                        let base = last.strip_suffix("Plugin").unwrap_or(last);
                        // PascalCase/CamelCase -> snake_case
                        let mut s = String::new();
                        for (i, ch) in base.chars().enumerate() {
                            if ch.is_uppercase() {
                                if i != 0 {
                                    s.push('_');
                                }
                                for lc in ch.to_lowercase() {
                                    s.push(lc);
                                }
                            } else {
                                s.push(ch);
                            }
                        }
                        Box::leak(s.into_boxed_str())
                    });

                DERIVED_NAME.clone()
            }

            fn aliases(&self) -> &'static [&'static str] {
                // Get aliases from the Plugin trait implementation
                <#plugin_type as crate::plugin::Plugin>::aliases()
            }
        }

        // Submit exec factory constructor to distributed slice
        #[linkme::distributed_slice(crate::plugin::factory::EXEC_PLUGIN_FACTORIES_SLICE)]
        fn #register_fn() -> std::sync::Arc<dyn crate::plugin::factory::ExecPluginFactory> {
            std::sync::Arc::new(#factory_wrapper::default())
        }
    };

    TokenStream::from(expanded)
}

/// Derive macro to auto-generate `as_shutdown` method for plugins
///
/// This macro implements the `as_shutdown(&self) -> Option<&dyn Shutdown>` method,
/// returning `Some(self)` to indicate that the plugin implements the Shutdown trait.
///
/// Use this on any Plugin type that also implements the `Shutdown` trait.
///
/// # Example
///
/// ```ignore
/// use lazydns::plugin::{Plugin, traits::Shutdown};
/// use async_trait::async_trait;
///
/// #[derive(ShutdownPlugin)]
/// struct MyPlugin;
///
/// #[async_trait]
/// impl Plugin for MyPlugin {
///     fn name(&self) -> &str { "my_plugin" }
///     async fn execute(&self, ctx: &mut Context) -> Result<()> { Ok(()) }
/// }
///
/// #[async_trait]
/// impl Shutdown for MyPlugin {
///     async fn shutdown(&self) -> Result<()> {
///         // cleanup code
///         Ok(())
///     }
/// }
/// ```
#[proc_macro_derive(ShutdownPlugin)]
pub fn derive_shutdown_plugin(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let plugin_type = &input.ident;

    let expanded = quote! {
        impl #plugin_type {
            /// Auto-generated bridge to Shutdown trait
            pub fn as_shutdown(&self) -> Option<&dyn crate::plugin::traits::Shutdown> {
                Some(self)
            }
        }
    };

    TokenStream::from(expanded)
}
