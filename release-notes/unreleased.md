### Changed

- Preserve tracked established and related replies to server-initiated traffic
  before applying bans. Exempt replies remain subject to other host firewall rules;
  incoming traffic on connections initiated by banned clients remains blocked,
  including existing sessions. Run `sudo kidobo sync` after upgrading to install this policy;
  live inspection reports older wiring without the reply-direction exemption as
  unknown until sync succeeds.
