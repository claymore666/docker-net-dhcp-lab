# docker-net-dhcp-lab

Runs [docker-net-dhcp](https://github.com/claymore666/docker-net-dhcp) against
real DHCP servers and routers, each installed the way its users install it,
and publishes what passed.

Work in progress. The repository becomes public once the first results page
exists.

## Bring up the reference cell

```
scripts/bootstrap-host.sh          # once per lab host
scripts/demo-ref-cell.sh ref-only  # one command, issue #1
```

`lab.yaml` declares the cells; `verify.sh` is the arbiter (CI runs it on
every push and PR). See `docs/` in the plugin repo's track file for the
full design.
