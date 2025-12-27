# lazydns Documentation

Welcome to the lazydns documentation. This `docs/` folder contains guides, references, and examples to help you use, operate, and develop for lazydns.

Start with the Quickstart to run lazydns locally, or browse the sidebar/SUMMARY to explore the docs.

---

If you maintain released documentation elsewhere (e.g., a hosted site), keep this folder as the canonical repository of source docs (markdown) used to publish that site.

## Quick Navigation

Use the site sidebar (`en/SUMMARY.md`) or the quick links below to jump to common pages:

* [Introduction](en/01_INTRODUCTION.md)
* [Quickstart](en/02_QUICKSTART.md)
* [Installation & Updates](en/03_INSTALLATION.md)
* [Configuration (Core)](en/04_CONFIGURATION.md)
* [Plugins Guide (User)](en/05_PLUGINS_USERGUIDE.md)
  * [Forward](en/05_02_PLUGIN_FORWARD.md)
  * [Cache](en/05_03_PLUGIN_CACHE.md)
  * [ACL](en/05_04_PLUGIN_ACL.md)
  * [Cron](en/05_06_PLUGIN_CRON.md)
  * DataSet Plugins
    - [Hosts](en/05_01_PLUGIN_HOSTS.md)
    - [Domain Set](en/05_07_01_PLUGIN_DOMAIN_SET.md)
    - [Ip Set](en/05_07_02_PLUGIN_IP_SET.md)
    - [GeoIP & GeoSite](en/05_05_PLUGIN_GEOIP_GEOSITE.md)
  * Executable Plugins
    - [`Sequence`](en/05_00_PLUGIN_SEQUENCE.md)
    - [Arbitrary](en/05_08_01_PLUGIN_ARBITRARY.md)
    - [Black Hole](en/05_08_02_PLUGIN_BLACK_HOLE.md)
    - [Collector](en/05_08_03_PLUGIN_COLLECTOR.md)
    - [Debug Print](en/05_08_04_PLUGIN_DEBUG_PRINT.md)
    - [Downloader](en/05_08_05_PLUGIN_DOWNLOADER.md)
    - [Drop Resp](en/05_08_06_PLUGIN_DROP_RESP.md)
    - [Dual Selector](en/05_08_07_PLUGIN_DUAL_SELECTOR.md)
    - [ECS](en/05_08_08_PLUGIN_ECS.md)
    - [EDNS0 Options](en/05_08_09_PLUGIN_EDNS0OPT.md)
    - [Fallback](en/05_08_10_PLUGIN_FALLBACK.md)
    - [IpSet (exec)](en/05_08_11_PLUGIN_IPSET_EXEC.md)
    - [Mark](en/05_08_12_PLUGIN_MARK.md)
    - [NftSet](en/05_08_13_PLUGIN_NFTSET.md)
    - [Query Summary](en/05_08_14_PLUGIN_QUERY_SUMMARY.md)
    - [Rate Limit](en/05_08_15_PLUGIN_RATE_LIMIT.md)
    - [Redirect](en/05_08_16_PLUGIN_REDIRECT.md)
    - [Reverse Lookup](en/05_08_17_PLUGIN_REVERSE_LOOKUP.md)
    - [RouterOS AddrList](en/05_08_18_PLUGIN_ROS_ADDRLIST.md)
    - [Sleep](en/05_08_19_PLUGIN_SLEEP.md)
    - [TTL](en/05_08_20_PLUGIN_TTL.md)
* [Writing Plugins (Developer)](en/06_WRITING_PLUGINS.md)
* [Datasets & Formats](en/07_DATASETS.md)
* [Changelog](en/16_CHANGELOG.md)
* [Appendix](en/17_APPENDIX.md)

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