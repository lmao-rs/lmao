# Changelog

## [0.8.1] - 2021-12-24

### Fixes

Rework `started_at` header storage so that requests do not start too early
([#1348] - [@zeylahellyer]).

[#1348]: https://github.com/twilight-rs/twilight/pull/1348

## [0.8.0] - 2021-12-03

Initial release ([#1191] - [@Gelbpunkt]). `http` now internally depends
on this crate to ratelimit requests. This crate exposes a trait and
provides a reference implementation using an in-memory backend.

### Fixes

As this is mostly code taken from `http`, it also contains some
bugfixes.

Fixes the template paths to match the Discord API ([#1205] -
[@Gelbpunkt]).

For webhooks, the token is now a major parameter ([#1263] -
[@Gelbpunkt]).

[#1191]: https://github.com/twilight-rs/twilight/pull/1191
[#1205]: https://github.com/twilight-rs/twilight/pull/1205
[#1263]: https://github.com/twilight-rs/twilight/pull/1263

[@Gelbpunkt]: https://github.com/Gelbpunkt
[@zeylahellyer]: https://github.com/zeylahellyer

[0.8.1]: https://github.com/twilight-rs/twilight/releases/tag/http-ratelimiting-0.8.1
[0.8.0]: https://github.com/twilight-rs/twilight/releases/tag/http-ratelimiting-0.8.0
