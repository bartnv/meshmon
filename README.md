# Meshmon

Meshmon is a distributed full-mesh network monitor, capable of monitoring all available network paths between a set of nodes running the tool.

## Features

 * No single point of failure
 * Configuration and network status propagated automatically
 * Separate IPv4 and IPv6 monitoring and reporting
 * Stateful firewall hole-punching
 * Web and terminal user interfaces

## Building

Meshmon is a regular Rust application managed by Cargo. To build from source, clone the git repository and run:

    cargo build --release --all-features

If you want a smaller build that excludes the web server and terminal user interface, run:

    cargo build --release

This generates a binary in the `target/release` directory. This binary is entirely self-contained, requiring only a compatible libc.

## Configuration

You can have meshmon generate a configuration template by running:

    meshmon init

This creates a `config.toml` file with the basic configuration entries. The only mandatory thing to change is the `name` parameter. Change it to a name for the current node, which needs to be unique in the network. Changes can also be passed directly as parameters to `meshmon init`. See `meshmon init --help` for the options.

Meshmon will rewrite the configuration file periodically with updated network information, so make sure it continues to have the permissions to do so.

## Running

Starting meshmon with the previous network configuration can be done by simply running:

    meshmon run

To bootstrap a new monitoring network, some additional parameters will be necessary, but only once. The easiest way to do this is to start one node (which is accessible on the default TCP port 7531) with `meshmon run --accept`. This will make it auto-accept any new node that connects to it. Then start the other nodes with `meshmon run --connect <hostname>:7531` with the hostname of the accept node. After a minute, all nodes will write this configuration to disk and will be able to find each other the next time without any commandline parameters.

See all available options with the `meshmon run --help` command.

## Output

By default, `meshmon run` will output basic results from the monitoring on stdout. Use the `--tui` option to activate the ncurses-like terminal interface.

As an alternative, a web interface is available using the build-in webserver. Use the `--http` or `--https` parameters to enable this on specific nodes, then connect your web browser to the configured port. This currently has no access control, so keep this in mind if you enable it on a globally accessible port. Putting it on a local network or behind a secured proxy is recommended.
