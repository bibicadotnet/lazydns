use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, parse_macro_input};

/// Derive macro to auto-generate plugin factory registration code
///
/// This macro:
/// 1. Generates a factory wrapper struct
/// 2. Derives the canonical plugin name from the type name (PascalCase -> snake_case, strip "Plugin" suffix)
/// 3. Creates a lazy static factory registration
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

    // Convert PluginName to PLUGIN_NAME format
    let mut upper_name = String::new();
    for (i, ch) in plugin_type_string.chars().enumerate() {
        if ch.is_uppercase() && i != 0 {
            upper_name.push('_');
        }
        upper_name.push(ch.to_ascii_uppercase());
    }
    let factory_static = format_ident!("{}_FACTORY", upper_name);

    // Generate the factory wrapper and registration code
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

        // Auto-register using lazy static
        pub(crate) static #factory_static: once_cell::sync::Lazy<()> =
            once_cell::sync::Lazy::new(|| {
                crate::plugin::factory::register_plugin_factory(
                    std::sync::Arc::new(#factory_wrapper::default()),
                );
            });
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

    // Convert PluginName to PLUGIN_NAME format
    let mut upper_name = String::new();
    for (i, ch) in plugin_type_string.chars().enumerate() {
        if ch.is_uppercase() && i != 0 {
            upper_name.push('_');
        }
        upper_name.push(ch.to_ascii_uppercase());
    }
    let exec_factory_static = format_ident!("{}_EXEC_FACTORY", upper_name);

    // Generate the exec factory wrapper and registration code
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

        // Auto-register using lazy static
        pub static #exec_factory_static: once_cell::sync::Lazy<()> =
            once_cell::sync::Lazy::new(|| {
                crate::plugin::factory::register_exec_plugin_factory(
                    std::sync::Arc::new(#factory_wrapper::default()),
                );
            });
    };

    TokenStream::from(expanded)
}
