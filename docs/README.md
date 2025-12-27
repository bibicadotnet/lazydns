# lazydns Documentation

Welcome to the lazydns documentation. This `docs/` folder contains guides, references, and examples to help you use, operate, and develop for lazydns.

Start with the Quickstart to run lazydns locally, or browse the sidebar/SUMMARY to explore the docs.

---

If you maintain released documentation elsewhere (e.g., a hosted site), keep this folder as the canonical repository of source docs (markdown) used to publish that site.

## Quick Navigation

Use the site sidebar (`en/SUMMARY.md`) or the quick links below to jump to common pages:

- [Introduction](en/01_INTRODUCTION.md)
- [Quickstart](en/02_QUICKSTART.md)
- [Installation & Updates](en/03_INSTALLATION.md)
- [Configuration (Core)](en/04_CONFIGURATION.md)
- Plugins
  - [Plugins Guide (User)](en/05_PLUGINS_USERGUIDE.md)
    - [Hosts](en/05_01_PLUGIN_HOSTS.md)
    - [Forward](en/05_02_PLUGIN_FORWARD.md)
    - [Cache](en/05_03_PLUGIN_CACHE.MD)
    - [ACL](en/05_04_PLUGIN_ACL.md)
    - [GeoIP & GeoSite](en/05_05_PLUGIN_GEOIP_GEOSITE.md)
- [Writing Plugins (Developer)](en/06_WRITING_PLUGINS.md)
- [Datasets & Formats](en/07_DATASETS.md)
- [Examples & Recipes](en/09_EXAMPLES_AND_RECIPES.md)
- [Admin API & Management](en/10_ADMIN_API.md)
- [Testing & CI](en/11_TESTING_AND_CI.md)

## Notes for developers / maintainers

These files live at the `docs/` root (non-recursive) and cover targeted topics useful for maintainers and operators:

- [ADMIN_USAGE](ADMIN_USAGE.md) — Administrative HTTP API and management examples.
- [CACHE_CONFIG_GUIDE](CACHE_CONFIG_GUIDE.md) — Deep-dive guide for cache tuning and options.
- [ENV_OVERRIDE](ENV_OVERRIDE.md) — How to override configuration via environment variables.
- [IMPLEMENTATION](IMPLEMENTATION.md) — Design notes and implementation details.
- [IP_MATCHING_RULES](IP_MATCHING_RULES.md) — IP/CIDR matching rules and examples.
- [DOMAIN_MATCHING_RULES](DOMAIN_MATCHING_RULES.md) — Domain matching and suffix rules.
- [PLUGINS_AUDIT_PLUGINS](PLUGINS_AUDIT_PLUGINS.md) — Guidance for auditing and reviewing plugins.
- [PLUGIN_DOWNLOADER](PLUGIN_DOWNLOADER.md) — How the plugin downloader works and how to use it.
- [UPSTREAM_FEATURES](UPSTREAM_FEATURES.md) — List of upstream (`mosdns`) features and differences.
- [BREAKING_CHANGE_REQUESTCONTEXT](BREAKING_CHANGE_REQUESTCONTEXT.md) — Migration notes for RequestContext breaking changes.

If you publish docs elsewhere, keep this repository as the canonical source and update the hosted site from these files.