- Source builds now require Rust 1.97.1, which includes the upstream fix for an LLVM miscompilation.
- Remote HTTP fetches now reject redirects outside the configured URL's origin,
  preventing providers from redirecting sync requests to unrelated internal services.
