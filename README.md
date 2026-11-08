# iroh-mdns-sd
[![Crates.io](https://img.shields.io/crates/v/iroh-mdns-sd.svg)](https://crates.io/crates/iroh-mdns-sd)
[![Documentation](https://docs.rs/iroh-mdns-sd/badge.svg)](https://docs.rs/iroh-mdns-sd)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Discord](https://img.shields.io/discord/1403836127458099381?logo=discord&label=Discord)](https://discord.gg/c22SPMYAwZ)


mDNS-based address lookup for [iroh](https://github.com/n0-computer/iroh).


This crate wraps the `mdns-sd` crate to find address information about endpoints 
on your local network — no relay or outside internet needed. 
See the [`mdns-sd`](https://crates.io/crates/mdns-sd) crate for more details.

*Note*: this is a drop-in replacement for the `iroh-address-lookups` crate 
just faster in startup but less scalable 
(similar tradeoff as described [here](https://docs.iroh.computer/connecting/local-address-lookup#choose-an-mdns-lookup))

When `MdnsAddressLookup` is enabled, you can get a stream of locally
discovered endpoints by calling `MdnsAddressLookup::subscribe`.

```rust,no_run
use std::time::Duration;

use iroh::endpoint::{Endpoint, presets};
use iroh_mdns_sd::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;

#[tokio::main]
async fn main() {
    let endpoint = Endpoint::bind(presets::Minimal).await.unwrap();

    // Register the address lookup with the endpoint.
    let mdns = MdnsAddressLookup::builder().build(endpoint.id()).unwrap();
    endpoint.address_lookup().unwrap().add(mdns.clone());

    // Subscribe to the mdns discovery events.
    let mut events = mdns.subscribe().await;
    while let Some(event) = events.next().await {
        match event {
            DiscoveryEvent::Discovered { endpoint_info, .. } => {
                println!("MDNS discovered: {:?}", endpoint_info);
            }
            DiscoveryEvent::Expired { endpoint_id } => {
                println!("MDNS expired: {endpoint_id}");
            }
            _ => {}
        }
    }
}
```

## Filtering

By default, `MdnsAddressLookup` publishes all addresses it receives:
direct IP addresses and up to one `RelayUrl`. The following constraints
apply regardless of any user-supplied filter:

- Only the first `RelayUrl` in the address set is published.
- A `RelayUrl` longer than 249 bytes is silently dropped.

You can supply an `iroh::address_lookup::AddrFilter` via
`MdnsAddressLookupBuilder::addr_filter` to control which addresses are
published and in what order.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.