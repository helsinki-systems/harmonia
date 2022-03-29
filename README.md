# bc

## Build

### Whole application

```
nix-shell --run cargo b
```

### C Library Wrapper around libnixstore

```
nix-shell --run make
```

Note: The makefile is only to provide a way to build the c Library so it can be
used outside of rust as well.

## Configuration

Default values

```
bind = "127.0.0.1:8080"
workers = 4
max_connection_rate = 256
priority = 30
loglevel = "info"
```
