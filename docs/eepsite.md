---
outline: deep
---

# Browing and Hosting Eepsites

## Configuring your browser

To browse eepsites, your browser must be configured to use `emissary-cli` as an HTTP proxy. The default port for the HTTP proxy is 4444.

### Firefox

Under `Edit > Settings > Network Settings`, specify `emissary-cli` as the HTTP proxy:

![Proxy](img/proxy.png)

Alternatively, you can use the [I2P in Private Browsing extension](https://github.com/eyedeekay/I2P-in-Private-Browsing-Mode-Firefox).

 ### Chromium

Start Chromium and specify `emissary-cli` as the HTTP proxy:

```bash
chromium --proxy-server="http://127.0.0.1:4444"
```

###

## Hosting an eepsite

To host an eepsite, add a server tunnel to `router.toml`:

```toml
[[server-tunnels]]
name = "my-website"
port = 8080
destination_path = "my-website.b64"
```

Here:
 * `destination_path` is the file path of the destination's private key
 * `port` is the port that a web server on your local machine is listening on

If the destination's private key does not exist, `emissary-cli` automatically generates and stores it on your disk. You can also manually create the private key using any SAMv3 library that supports `DEST GENERATE`. The private key must be a base64-encoded string.

You can find the `.b32.i2p` address of the destination in the router UI under `Destinations`.

### Encrypted lease sets

A destination can publish its lease set encrypted (an "encrypted lease set", store type 5) so that floodfills and other routers learn nothing about it. Such a destination is reached through its *blinded* address: a 56-character `.b32.i2p` address derived from the destination's signing key instead of the usual 52-character hash. The lease set is encrypted with a key that changes every UTC day, and only routers that know the blinded address can decrypt it.

SAMv3 clients enable this by passing `i2cp.leaseSetType=5` to `SESSION CREATE`. The router logs the blinded address when the session starts and shows it in the UI under `Destinations`. Connecting to a blinded address works everywhere a `.b32.i2p` address does: the HTTP and SOCKS proxies, and `STREAM CONNECT` in SAMv3.

Limitations:
 * server tunnels configured in `router.toml` cannot enable encrypted lease sets yet since the SAMv3 client library used by `emissary-cli` doesn't pass the option through
 * lease sets that require per-client authorization (DH or PSK) and I2CP sessions with encrypted lease sets are not supported
 * `NAMING LOOKUP` of a blinded address is not supported, the address must be connected to directly

### Offline keys

The signing key of a destination can be kept offline. The router is instead given a *transient* signing key together with an *offline signature*: the transient key and its expiration, signed by the destination's own key. Lease sets, streaming handshakes and Datagram2 datagrams are signed with the transient key and remote routers verify them through the offline signature, so a compromised router leaks only a key with a limited lifetime and the destination keeps its address.

Create offline keys from an existing private key file with `emissary-cli`:

```sh
emissary-cli offline-keys --file my-website.b64 --output my-website-offline.b64 --days 30
```

Use the output file as `destination_path` of the server tunnel and keep the original file offline. Repeat the command before the transient key expires. The private key file format is the one described in the SAMv3 specification: an all-zero signing private key followed by the offline signature section and the transient private key, so files created by other routers' tools work as well, and SAMv3 clients can pass such a file in `DESTINATION=` directly.

Limitations:
 * offline keys cannot be combined with encrypted lease sets or with `STYLE=DATAGRAM` sessions (repliable Datagram1 datagrams have no room for the offline signature); `STREAM`, `RAW`, `DATAGRAM2` and `PRIMARY` sessions are supported
 * I2CP clients with offline keys are accepted (session configuration and lease sets signed with the transient key) but there is no tooling for them in `emissary-cli`
 * only Ed25519 transient keys can be created and used locally; remote destinations may also use ECDSA-P256 transient keys
