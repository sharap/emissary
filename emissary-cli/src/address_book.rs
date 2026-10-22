// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::config::AddressBookConfig;

use emissary_core::{
    crypto::{base32_encode, base64_decode, base64_encode},
    primitives::Destination,
    runtime::AddressBook,
};
use futures::channel::oneshot;
use parking_lot::RwLock;
use reqwest::{
    header::{
        HeaderMap, HeaderValue, CONNECTION, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
    },
    Client, Proxy, StatusCode,
};

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

/// Logging target for the file
const LOG_TARGET: &str = "emissary::address-book";

/// Backoff if downloading the hosts file fails.
const RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// How many times each subscription is tried before giving up.
const SUBSCRIPTION_NUM_RETRIES: usize = 5usize;

/// How often the subscriptions are downloaded again unless configured otherwise.
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

/// Subscriptions used when the configuration doesn't list any.
///
/// The bootstrap `hosts.txt` of the I2P project only has a few dozen names. These services
/// publish the full lists. `reg.i2p` is given as a `.b32.i2p` address because it's missing from
/// the bootstrap file, the others are resolved through it.
pub const DEFAULT_SUBSCRIPTIONS: &[&str] = &[
    "http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt",
    "http://notbob.i2p/hosts.txt",
    "http://identiguy.i2p/hosts.txt",
    "http://stats.i2p/cgi-bin/newhosts.txt",
];

/// Write `addresses` to the base32 address file at `path`, one `hostname=base32` per line.
///
/// The in-memory map is the only source of truth: every change is written from it, so entries
/// downloaded by the manager and entries added through the UI never overwrite each other.
fn write_addresses(path: &Path, addresses: &HashMap<String, String>) -> std::io::Result<()> {
    let serialized = addresses.iter().collect::<BTreeMap<_, _>>().into_iter().fold(
        String::new(),
        |mut acc, (hostname, address)| {
            acc.push_str(hostname);
            acc.push('=');
            acc.push_str(address);
            acc.push('\n');
            acc
        },
    );

    std::fs::write(path, serialized)
}

/// Used when requesting address books from servers. This should reduce load to servers whose
/// address books haven't changed since our last lookup.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct Modified {
    etag: String,
    last_modified: String,
}

/// The on-disk representation of our hosts modified times.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct HostModified {
    host_modified_times: Vec<(String, Modified)>,
}

impl From<HashMap<String, Modified>> for HostModified {
    fn from(value: HashMap<String, Modified>) -> Self {
        Self {
            host_modified_times: value.into_iter().collect::<Vec<(String, Modified)>>(),
        }
    }
}

impl From<HostModified> for HashMap<String, Modified> {
    fn from(value: HostModified) -> HashMap<String, Modified> {
        HashMap::from_iter(value.host_modified_times)
    }
}

/// Only modified responses are passed on.
enum Response {
    /// etags/last-modified saved the server from doing work.
    NotModified,
    /// The response body and the etag/last-modified info to save for subsequent requests.
    Modified { modified: Modified, body: String },
}

/// When a request fails, we remove the cache entry and sleep for `RETRY_BACKOFF`.
enum Error {
    /// There's an error _sending_ an HTTP request.
    Client,
    /// The HTTP request was a failure (4xx, 5xx).
    Server,
    /// We couldn't decode the response.
    Encoding,
    /// We couldn't get a response.
    Response,
}

/// Address book.
pub struct AddressBookManager {
    /// Path to address book.
    address_book_path: PathBuf,

    /// Hostname -> Base32 address mappings
    addresses: Arc<RwLock<HashMap<String, String>>>,

    /// URL from which the primary `hosts.txt` is downloaded.
    hosts_url: Option<String>,

    /// How often the subscriptions are downloaded again, `None` means only once at startup.
    refresh_interval: Option<Duration>,

    /// Additional subscriptions.
    subscriptions: Vec<String>,

    /// Incremented on every change of `addresses`, lets the UI notice updates cheaply.
    version: Arc<AtomicU64>,
}

impl AddressBookManager {
    /// Create new [`AddressBookManager`].
    pub async fn new(base_path: PathBuf, config: AddressBookConfig) -> Self {
        let path = base_path.join("addressbook");

        // load (hostname, base32 address) mappings from disk
        let addresses = match tokio::fs::read_to_string(path.join("addresses")).await {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    path = %path.join("addresses").display(),
                    error = ?error.kind(),
                    "failed to load base32 addresses from disk",
                );

                HashMap::new()
            }
            Ok(content) => content
                .lines()
                .filter_map(|line| {
                    line.split_once('=').map(|(key, value)| (key.to_owned(), value.to_owned()))
                })
                .collect(),
        };

        Self {
            address_book_path: path,
            addresses: Arc::new(RwLock::new(addresses)),
            hosts_url: config.default,
            refresh_interval: match config.refresh_hours {
                None => Some(DEFAULT_REFRESH_INTERVAL),
                Some(0) => None,
                Some(hours) => Some(Duration::from_secs(hours.saturating_mul(60 * 60))),
            },
            subscriptions: config.subscriptions.unwrap_or_else(|| {
                DEFAULT_SUBSCRIPTIONS.iter().map(|url| url.to_string()).collect()
            }),
            version: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Override the refresh interval, `None` disables periodic refreshes.
    #[cfg(test)]
    fn with_refresh_interval(mut self, refresh_interval: Option<Duration>) -> Self {
        self.refresh_interval = refresh_interval;
        self
    }

    /// Get handle to [`AddressBook`].
    pub fn handle(&self) -> Arc<AddressBookHandle> {
        Arc::new(AddressBookHandle {
            address_book_path: Arc::from(self.address_book_path.to_str().expect("to succeed")),
            addresses: Arc::clone(&self.addresses),
            version: Arc::clone(&self.version),
        })
    }

    /// Attempt to download `hosts.txt` from `url`.
    async fn download(
        client: &Client,
        url: &str,
        modified: Option<&Modified>,
    ) -> Result<Response, Error> {
        let mut headers = HeaderMap::from_iter([(CONNECTION, HeaderValue::from_static("close"))]);
        // Consider refactoring some of this. if-let chaings may make this nicer.
        if let Some(modified) = modified {
            if !modified.etag.is_empty() {
                if let Ok(etag) = HeaderValue::from_str(&modified.etag) {
                    headers.insert(IF_NONE_MATCH, etag);
                }
            }

            if !modified.last_modified.is_empty() {
                if let Ok(last_modified) = HeaderValue::from_str(&modified.last_modified) {
                    headers.insert(IF_MODIFIED_SINCE, last_modified);
                }
            }
        }
        let response = match client.get(url.to_string()).headers(headers).send().await {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?url,
                    ?error,
                    "failed to fetch hosts.txt"
                );
                return Err(Error::Client);
            }
            Ok(response) => response,
        };
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(Response::NotModified);
        }
        if !response.status().is_success() {
            tracing::warn!(
                target: LOG_TARGET,
                ?url,
                status = ?response.status(),
                "request to address book server failed",
            );
            return Err(Error::Server);
        }
        let modified = Modified {
            etag: response
                .headers()
                .get(ETAG)
                .and_then(|e| e.to_str().ok())
                .map(String::from)
                .unwrap_or_default(),
            last_modified: response
                .headers()
                .get(LAST_MODIFIED)
                .and_then(|l| l.to_str().ok())
                .map(String::from)
                .unwrap_or_default(),
        };
        match response.bytes().await {
            Ok(response) => match std::str::from_utf8(&response) {
                Ok(response) => Ok(Response::Modified {
                    modified,
                    body: response.to_owned(),
                }),
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?url,
                        ?error,
                        "failed to convert `hosts.txt` to utf-8",
                    );
                    Err(Error::Encoding)
                }
            },
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?url,
                    ?error,
                    "failed to get response from address book server"
                );
                Err(Error::Response)
            }
        }
    }

    /// Parse `hosts` into base64 destinations and base32 addresses and merge the results into
    /// `addresses`.
    ///
    /// Addresses already present in `addresses` will be ignored.
    async fn parse_and_merge(
        &self,
        addresses: &mut HashMap<String, (String, String)>,
        hosts: String,
    ) {
        for line in hosts.lines() {
            let Some((hostname, base64_destination)) = line.split_once('=') else {
                tracing::warn!(
                    target: LOG_TARGET,
                    %line,
                    "ignoring invalid address",
                );
                continue;
            };
            let hostname = hostname.trim().to_string();

            if addresses.contains_key(&hostname) {
                tracing::trace!(
                    target: LOG_TARGET,
                    %hostname,
                    "skipping an already-existing address",
                );
                continue;
            }

            let base64_destination = match base64_destination.find("#!") {
                Some(index) => base64_destination[..index].trim().to_string(),
                None => base64_destination.trim().to_string(),
            };

            let Some(decoded) = base64_decode(&base64_destination) else {
                tracing::warn!(
                    target: LOG_TARGET,
                    %hostname,
                    "ignoring invalid base64-encoded destination",
                );
                continue;
            };

            match Destination::parse(&decoded) {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %hostname,
                        ?error,
                        "ignoring invalid destination",
                    );
                    continue;
                }
                Ok(destination) => {
                    let base32_address = base32_encode(destination.id().to_vec());
                    addresses.insert(hostname, (base32_address, base64_destination));
                }
            }
        }
    }

    /// Loads the modified info for each endpoint we request. In case we can't load it, we return an
    /// empty `HashMap` so the whole process doesn't fail.
    ///
    /// If we can't load it for `std::io::Error` reasons, then we probably won't be able to save
    /// either.
    async fn load_host_modified_times(&self) -> HashMap<String, Modified> {
        let path = self.address_book_path.join("host_modified_times");
        let raw = match tokio::fs::read_to_string(path).await {
            Ok(r) => r,
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "could not read host_modified_times",
                );
                return HashMap::new();
            }
        };

        match toml::from_str::<HostModified>(&raw) {
            Ok(h) => h.into(),
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "could not deserialize host_modified_times",
                );
                HashMap::new()
            }
        }
    }

    /// Serializes the host modified times as a `Vec<(String, Modified)>`. Warns on error instead of
    /// failing.
    async fn save_host_modified_times(&self, host_modified_times: HashMap<String, Modified>) {
        let path = self.address_book_path.join("host_modified_times");
        let modified = HostModified::from(host_modified_times);
        let raw = match toml::to_string(&modified) {
            Ok(r) => r,
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "could not serialize host_modified_times",
                );
                return;
            }
        };

        if let Err(error) = tokio::fs::write(path, raw).await {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "could not write host_modified_times",
            );
        }
    }

    /// Start event loop for [`AddressBookManager`].
    ///
    /// Before the address book subscription download starts, [`AddressBook`] waits on
    /// `http_proxy_ready_rx` which the HTTP proxy sends a signal to once it's ready.
    ///
    /// The subscriptions are downloaded again every `refresh_interval`, so names registered after
    /// the router was started show up without a restart.
    pub async fn run(
        self,
        http_port: u16,
        http_host: String,
        http_proxy_ready_rx: oneshot::Receiver<()>,
    ) {
        if let Err(error) = http_proxy_ready_rx.await {
            tracing::error!(
                target: LOG_TARGET,
                ?error,
                "http proxy failed to start, cannot start address book",
            );
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            ?http_port,
            ?http_host,
            subscriptions = ?self.subscriptions,
            "create address book",
        );

        let client = Client::builder()
            .proxy(Proxy::http(format!("http://{http_host}:{http_port}")).expect("to succeed"))
            .http1_title_case_headers()
            .build()
            .expect("to succeed");

        loop {
            self.download_all(&client).await;

            let Some(refresh_interval) = self.refresh_interval else {
                return;
            };

            tracing::info!(
                target: LOG_TARGET,
                ?refresh_interval,
                "address book downloaded, waiting for the next refresh",
            );
            tokio::time::sleep(refresh_interval).await;
        }
    }

    /// Download the default `hosts.txt` and all subscriptions once and store the results on disk.
    async fn download_all(&self, client: &Client) {
        let mut addresses = HashMap::<String, (String, String)>::new();
        let mut host_modified_times = self.load_host_modified_times().await;

        if let Some(url) = &self.hosts_url {
            self.download_with_retries(url, client, &mut addresses, &mut host_modified_times)
                .await;

            // save hosts to disk at this point as subscriptions might contain .i2p addresses
            // which the http proxy must be able to resolve to .b32.i2p addresses
            self.save_to_disk(addresses.clone()).await;
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                "default address book download skipped",
            );
        };

        for subscription in &self.subscriptions {
            self.download_with_retries(
                subscription,
                client,
                &mut addresses,
                &mut host_modified_times,
            )
            .await;
        }

        self.save_to_disk(addresses).await;
        self.save_host_modified_times(host_modified_times).await;
    }

    /// A wrapper around `Self::download` which deals with retries, logging, etc.
    async fn download_with_retries(
        &self,
        url: &String,
        client: &Client,
        addresses: &mut HashMap<String, (String, String)>,
        host_modified_times: &mut HashMap<String, Modified>,
    ) {
        for _ in 0..SUBSCRIPTION_NUM_RETRIES {
            match Self::download(client, url, host_modified_times.get(url)).await {
                Ok(Response::NotModified) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        %url,
                        "hosts.txt not changed since last download",
                    );
                    break;
                }
                Ok(Response::Modified { modified, body }) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        %url,
                        "hosts.txt downloaded",
                    );
                    self.parse_and_merge(addresses, body).await;
                    host_modified_times.insert(url.to_string(), modified);
                    break;
                }
                // These errors would have been logged by `Self::download` already.
                Err(_) => {
                    tokio::time::sleep(RETRY_BACKOFF).await;
                }
            }
        }
    }

    /// Save `addresses` to disk.
    ///
    /// Parses each destination in `addresses` into its .b32.i2p address, stores all .b32.i2p
    /// addresses along with their hostnames into a file and stores all .Base64-encoded destinations
    /// into a separate directory where each destination is indexed by their hostname.
    async fn save_to_disk(&self, addresses: HashMap<String, (String, String)>) {
        let (addresses, destinations): (HashMap<_, _>, HashMap<_, _>) = addresses
            .into_iter()
            .map(|(hostname, (base32, base64))| ((hostname.clone(), base32), (hostname, base64)))
            .unzip();

        // store base32-encoded addresses on disk and update `addresses`
        {
            let mut inner = self.addresses.write();

            for (hostname, address) in addresses {
                inner.insert(hostname, address);
            }
            self.version.fetch_add(1, Ordering::Release);

            if let Err(error) = write_addresses(&self.address_book_path.join("addresses"), &inner) {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to write base32 addresses to disk",
                );
            }
        }

        // store base64-encoded destinations on disk
        match tokio::fs::create_dir_all(self.address_book_path.join("destinations")).await {
            Err(error) => tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "failed to create directory for destinations",
            ),
            Ok(_) =>
                for (hostname, destination) in destinations {
                    if let Err(error) = tokio::fs::write(
                        self.address_book_path.join("destinations").join(format!("{hostname}.txt")),
                        destination,
                    )
                    .await
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %hostname,
                            ?error,
                            "failed to store destination to disk",
                        );
                    }
                },
        }
    }
}

/// Address book handle.
#[derive(Clone)]
pub struct AddressBookHandle {
    /// Path to address book.
    address_book_path: Arc<str>,

    /// Hostname -> Base32 address mappings
    addresses: Arc<RwLock<HashMap<String, String>>>,

    /// Incremented on every change of `addresses`.
    version: Arc<AtomicU64>,
}

impl AddressBookHandle {
    /// Version of the address book, changes whenever an entry is added, removed or downloaded.
    #[allow(dead_code)]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Copy of all `hostname -> base32 address` entries, sorted by hostname.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> BTreeMap<Arc<str>, Arc<str>> {
        self.addresses
            .read()
            .iter()
            .map(|(hostname, address)| (Arc::from(hostname.as_str()), Arc::from(address.as_str())))
            .collect()
    }

    /// Store `addresses` on disk after a modification.
    fn store(&self, addresses: &HashMap<String, String>, host: &str) {
        self.version.fetch_add(1, Ordering::Release);

        if let Err(error) = write_addresses(
            Path::new(&*self.address_book_path).join("addresses").as_path(),
            addresses,
        ) {
            tracing::warn!(
                target: LOG_TARGET,
                %host,
                error = ?error.kind(),
                "failed to update on-disk base32 address list",
            );
        }
    }

    /// Add new host to address book.
    ///
    /// Only the base32 address of the host is stored on disk.
    #[allow(dead_code)]
    pub fn add_base32(&self, host: String, address: String) {
        let mut inner = self.addresses.write();
        inner.insert(host.clone(), address);
        self.store(&inner, &host);
    }

    /// Add new host to address book.
    ///
    /// Both the destination and the base32 address of the destination are stored on disk.
    #[allow(dead_code)]
    pub fn add_base64(&self, host: String, destination: Destination) {
        let base32_address = base32_encode(destination.id().to_vec());

        {
            let mut inner = self.addresses.write();
            inner.insert(host.clone(), base32_address);
            self.store(&inner, &host);
        }

        if let Err(error) = std::fs::write(
            format!("{}/destinations/{host}.txt", self.address_book_path),
            base64_encode(destination.serialize()),
        ) {
            tracing::warn!(
                target: LOG_TARGET,
                %host,
                error = ?error.kind(),
                "failed to write base64-encoded destination on disk",
            );
        }
    }

    /// Remove `host` from address book.
    #[allow(dead_code)]
    pub fn remove(&self, host: &str) {
        {
            let mut inner = self.addresses.write();
            inner.remove(host);
            self.store(&inner, host);
        }

        // remove destination file for the host
        if let Err(error) = std::fs::remove_file(format!(
            "{}/destinations/{host}.txt",
            self.address_book_path
        )) {
            tracing::warn!(
                target: LOG_TARGET,
                %host,
                error = ?error.kind(),
                "failed to remove destination for host",
            );
        }
    }
}

impl AddressBook for AddressBookHandle {
    fn resolve_base64(&self, host: String) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> {
        let path = Arc::clone(&self.address_book_path);

        Box::pin(async move {
            tokio::fs::read_to_string(format!("{path}/destinations/{host}.txt")).await.ok()
        })
    }

    fn resolve_base32(&self, host: &str) -> Option<String> {
        self.addresses.read().get(host).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emissary_core::crypto::SigningPrivateKey;
    use emissary_util::runtime::tokio::Runtime as TokioRuntime;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// Create a `hostname=base64` line for a destination derived from `seed`.
    fn hosts_line(hostname: &str, seed: u8) -> String {
        let signing_key = SigningPrivateKey::from_bytes(&[seed; 32]).unwrap();
        let destination = Destination::new::<TokioRuntime>(signing_key.public());

        format!("{hostname}={}", base64_encode(destination.serialize()))
    }

    /// Minimal HTTP server standing in for the HTTP proxy.
    ///
    /// Answers every request with the next body of `bodies` (the last one is repeated) and counts
    /// the requests.
    async fn fake_proxy(bodies: Vec<String>) -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&requests);

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let index = counter.fetch_add(1, Ordering::SeqCst).min(bodies.len() - 1);
                let body = bodies[index].clone();

                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];

                    while !request.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        request.push(byte[0]);
                    }

                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        (port, requests)
    }

    #[tokio::test]
    async fn built_in_subscriptions_used_when_unset() {
        let dir = tempdir().unwrap().keep();

        let manager = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;
        assert_eq!(manager.subscriptions, DEFAULT_SUBSCRIPTIONS);
        assert_eq!(manager.refresh_interval, Some(DEFAULT_REFRESH_INTERVAL));

        let manager = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: Some(Vec::new()),
                refresh_hours: Some(0),
            },
        )
        .await;
        assert!(manager.subscriptions.is_empty());
        assert_eq!(manager.refresh_interval, None);

        let manager = AddressBookManager::new(
            dir,
            AddressBookConfig {
                default: None,
                subscriptions: Some(vec![String::from("http://mine.i2p/hosts.txt")]),
                refresh_hours: Some(3),
            },
        )
        .await;
        assert_eq!(
            manager.subscriptions,
            vec![String::from("http://mine.i2p/hosts.txt")]
        );
        assert_eq!(
            manager.refresh_interval,
            Some(Duration::from_secs(3 * 60 * 60))
        );
    }

    #[tokio::test]
    async fn console_changes_and_downloads_share_one_file() {
        let dir = tempdir().unwrap().keep();
        tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

        let manager = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;
        let handle = manager.handle();
        assert_eq!(handle.version(), 0);

        // host added through the console before any download
        handle.add_base32(String::from("manual.i2p"), String::from("manual-base32"));
        assert_eq!(handle.version(), 1);

        // subscription download finishes
        let mut downloaded = HashMap::new();
        downloaded.insert(
            String::from("downloaded.i2p"),
            (
                String::from("downloaded-base32"),
                String::from("downloaded-base64"),
            ),
        );
        manager.save_to_disk(downloaded).await;
        assert_eq!(handle.version(), 2);

        // another host added through the console after the download
        handle.add_base32(String::from("later.i2p"), String::from("later-base32"));
        assert_eq!(handle.version(), 3);

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.keys().map(|key| key.as_ref()).collect::<Vec<_>>(),
            vec!["downloaded.i2p", "later.i2p", "manual.i2p"]
        );

        // everything is on disk, nothing overwrote anything
        let reloaded = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await
        .handle();
        for (host, address) in [
            ("manual.i2p", "manual-base32"),
            ("downloaded.i2p", "downloaded-base32"),
            ("later.i2p", "later-base32"),
        ] {
            assert_eq!(
                reloaded.resolve_base32(host).as_deref(),
                Some(address),
                "{host}"
            );
        }

        // removing one host keeps the others
        handle.remove("downloaded.i2p");
        assert_eq!(handle.version(), 4);
        assert!(handle.resolve_base32("downloaded.i2p").is_none());

        let reloaded = AddressBookManager::new(
            dir,
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await
        .handle();
        assert!(reloaded.resolve_base32("downloaded.i2p").is_none());
        assert!(reloaded.resolve_base32("manual.i2p").is_some());
        assert!(reloaded.resolve_base32("later.i2p").is_some());
    }

    #[tokio::test]
    async fn subscriptions_refreshed_periodically() {
        let dir = tempdir().unwrap().keep();
        tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

        // the first download lists one host, later downloads list two
        let (port, requests) = fake_proxy(vec![
            hosts_line("first.i2p", 1),
            format!(
                "{}\n{}",
                hosts_line("first.i2p", 1),
                hosts_line("second.i2p", 2)
            ),
        ])
        .await;

        let manager = AddressBookManager::new(
            dir,
            AddressBookConfig {
                default: Some(String::from("http://registry.i2p/hosts.txt")),
                subscriptions: Some(Vec::new()),
                refresh_hours: None,
            },
        )
        .await
        .with_refresh_interval(Some(Duration::from_millis(200)));
        let handle = manager.handle();

        let (ready_tx, ready_rx) = oneshot::channel();
        tokio::spawn(manager.run(port, String::from("127.0.0.1"), ready_rx));
        ready_tx.send(()).unwrap();

        // wait until the second download has been merged
        tokio::time::timeout(Duration::from_secs(10), async {
            while handle.resolve_base32("second.i2p").is_none() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("second download merged");

        assert!(requests.load(Ordering::SeqCst) >= 2);
        assert!(handle.resolve_base32("first.i2p").is_some());
        assert!(handle.resolve_base64(String::from("second.i2p")).await.is_some());
    }

    #[tokio::test]
    async fn no_refresh_without_interval() {
        let dir = tempdir().unwrap().keep();
        tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

        let (port, requests) = fake_proxy(vec![hosts_line("first.i2p", 1)]).await;
        let manager = AddressBookManager::new(
            dir,
            AddressBookConfig {
                default: Some(String::from("http://registry.i2p/hosts.txt")),
                subscriptions: Some(Vec::new()),
                refresh_hours: Some(0),
            },
        )
        .await;
        let handle = manager.handle();

        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(manager.run(port, String::from("127.0.0.1"), ready_rx));
        ready_tx.send(()).unwrap();

        // the event loop exits after the single download
        tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(handle.resolve_base32("first.i2p").is_some());
    }

    #[tokio::test]
    async fn save_only_destination() {
        let dir = tempdir().unwrap();
        let address_book = AddressBookManager::new(
            dir.keep(),
            AddressBookConfig {
                default: Some(String::from("url")),
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;

        let mut addresses = HashMap::<String, (String, String)>::new();
        let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
                J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
                E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
                umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
                KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
                O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
                gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
                n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
                PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
                1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
                Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
                p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
                PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
                Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
                bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
                S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
                DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
                WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
                bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
                JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
                AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
                Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
                pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
                Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
                e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

        address_book.parse_and_merge(&mut addresses, hosts).await;
        let addresses = addresses
            .into_iter()
            .map(|(hostname, (_, destination))| (hostname, destination))
            .collect::<HashMap<_, _>>();

        assert_eq!(
            addresses.get(&String::from("tracker2.postman.i2p")),
            Some(&String::from(
                    "lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDaJ50lUZg\
                    VPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaT\
                    Mn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQ\
                    US4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~\
                    sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfcKolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZ\
                    DU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA=="
                )
            )
        );

        assert_eq!(
            addresses.get(&String::from("psi.i2p")),
            Some(
                &String::from(
                    "a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH3\
                    3l4~mQjB8Hkt83l9qnNJPUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW\
                    9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpBZz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0Nt\
                    aOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPybmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MR\
                    VT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lzS9GWf2i-nk~~\
                    ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA"
                )
            )
        );

        assert_eq!(
            addresses.get(&String::from("zerobin.i2p")),
            Some(
                &String::from(
                    "Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVgDZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0Mj\
                    QDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8SWcxWdTbKU-O8IpE3O01Oc6j0fp1\
                    E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYhbfM7x56\
                    4PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZ\
                    nGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG\
                    0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA"
                )
            )
        );

        assert_eq!(
            addresses.get(&String::from("zzz.i2p")),
            Some(
                &String::from(
                    "GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~\
                    YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0\
                    d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsd\
                    jU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~\
                    DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFF\
                    T3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA=="
                )
            )
        );
    }

    #[tokio::test]
    async fn host_lookup() {
        // create address book
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
                J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
                E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
                umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
                KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
                O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
                gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
                n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
                PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
                1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
                Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
                p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
                PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
                Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
                bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
                S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
                DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
                WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
                bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
                JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
                AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
                Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
                pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
                Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
                e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            dir
        };

        // load address book from disk
        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;
        let handle = address_book.handle();

        // try to find base32 address and base64-encoded destination of a saved destination
        let host = handle.resolve_base32("zzz.i2p").expect("to find base32 address for zzz.i2p");
        assert_eq!(
            host,
            "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua".to_string()
        );

        let destination = handle
            .resolve_base64("zzz.i2p".to_string())
            .await
            .expect("expected to find destination for zzz.i2p");
        assert_eq!(destination, "GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==");

        // attempt to find base32 address for an unknown hostname
        assert!(handle.resolve_base32("test.i2p").is_none());
        assert!(handle.resolve_base64("test.i2p".to_string()).await.is_none());
    }

    #[tokio::test]
    async fn save_to_disk() {
        let dir = tempdir().unwrap().path().to_owned();
        tokio::fs::create_dir_all(dir.join("addressbook")).await.unwrap();

        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: Some(String::from("url")),
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;

        let mut addresses = HashMap::<String, (String, String)>::new();
        let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
                J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
                E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
                umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
                KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
                O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
                gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
                n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
                PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
                1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
                Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
                p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
                PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
                Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
                bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
                S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
                DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
                WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
                bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
                JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
                AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
                Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
                pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
                Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
                e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

        address_book.parse_and_merge(&mut addresses, hosts).await;
        address_book.save_to_disk(addresses.clone()).await;

        // verify all base64 destinations have been saved under correct keys
        for (key, (_, value)) in addresses {
            let key = key.strip_suffix(".i2p").unwrap();

            let path = dir.join("addressbook/destinations").join(format!("{key}.i2p.txt"));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), value);
        }

        // verify all base32 addresses have been saved and correspond to correct hostnames
        let content = std::fs::read_to_string(dir.join("addressbook/addresses")).unwrap();
        let mut expected = HashMap::<&str, &str>::from_iter([
            (
                "psi.i2p",
                "avviiexdngd32ccoy4kuckvc3mkf53ycvzbz6vz75vzhv4tbpk5a",
            ),
            (
                "zerobin.i2p",
                "3564erslxzaoucqasxsjerk4jz2xril7j2cbzd4p7flpb4ut67hq",
            ),
            (
                "tracker2.postman.i2p",
                "6a4kxkg5wp33p25qqhgwl6sj4yh4xuf5b3p3qldwgclebchm3eea",
            ),
            (
                "zzz.i2p",
                "lhbd7ojcaiofbfku7ixh47qj537g572zmhdc4oilvugzxdpdghua",
            ),
        ]);

        for line in content.lines() {
            let (key, value) = line.split_once('=').unwrap();
            let expected_value = expected.remove(&key).unwrap();

            assert_eq!(expected_value, value);
        }
    }

    #[tokio::test]
    async fn redownload_address_book() {
        // create address book
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
                J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
                E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
                umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
                KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
                O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
                gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
                n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
                PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
                1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
                Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
                p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
                PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
                Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
                bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
                S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
                DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
                WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
                bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
                JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
                AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
                Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
                pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
                Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
                e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            dir
        };

        // load address book from disk
        //
        // this simulates a startup from disk
        {
            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;
            let handle = address_book.handle();

            // verify all hosts are found
            for host in ["psi.i2p", "zerobin.i2p", "tracker2.postman.i2p", "zzz.i2p"] {
                assert!(handle.resolve_base32(host).is_some());
                assert!(handle.resolve_base64(host.to_string()).await.is_some());
            }

            // download more hosts from some other subscriptions
            //
            // verify that the new destinations are stored on disk, theb base32 address book is
            // updated and that `AddressBookHandle` has the new base32 addresses
            let new_hosts = "echo.idk.i2p=75Mgd8DeYkNAdk6mrF0rOt3WuM6bYi3k7n3BRIp-np5-5-py1YTmBJSRq9EXL1YrweU\
                pal~ZT~46~-lMW~zKHA46iTWsZzKFMEKFdfoM2fSgZDlEaoalW4QzkQjbOVO0atkEK15uXO2WiCRgfUab0Gyp-EcGkdQq\
                8FuF~sPLlm4xa90cmT6G~s1SeaNLII8DPli-XqZppSGOSArMSEYsxZPNfKs5UxvEeCrbUjBLCGhy2K3x926Af9bZk1ITI\
                W~K70xo-rSD0SbDXO9vT4e7fiq21Q2LicAofn~Y4MwPz6jr0CUZQAHxwCy1N3OR0XYFsTI4XS1LZ3zGwVpEjCfVD1mQhC\
                LzzIjRHgGB6Cr3xj3FntBhv0d9pBuogUjOkLEnmFHpj5ONE7l~3aUsR6vRYTUDfwnxXnIi9KF-PPyOAACXCz~T06QXVfa\
                qzTj8tyr40cUqKIZHquaMZrAkqqa26KM3l0fu755UVo43MfD3f9zo3erjo~UDI~oP1bYyEU3LBQAEAAcAAA==\n3chele\
                ctricboogaloo.i2p=W5br4iApDNRQ-IY0yZQqrv-BqIj5Rk1XytcDUHcTpGHiyeaEPlP3wRr~zMTKrlCh78IRI26m8Gw\
                jE2VKdoMMwl9j9GdikQX4p4J0912IcRZbFGVIkibe36KgqkKJ9-s1gv4yzDVjEG2ZE6CMn-NZJxyp3a7Ypa1UFDLATdep\
                KFhHZRK3EN9fcUfMy2EAMwgihnd4JVZTytSVOcKfUrhIXf1lKmgr9qN9uXv38q2mtYMzbnWNe6TlB9GWrAZnsREB1kEZM\
                ts28leSGB~kYJHSlxQQvgOA0Rt9s3xkvP~EThUmyIIDZ9SlBh8iek6E1wreHfRhsCA9qTdCcs5XivxG0CMJR4F-Q55AlS\
                FWthsgJrUrb9x4RB6fTANv5bvZH3yBMQvZZxgqu4sN6MbPVaW2X7x3ldq3~UwG~HXvdvA7wP-sBq3uEshPCuVhJD8ojUD\
                qm9prLIVuLWt2pIiVbz-l4P-jx769A0OoN8-Z6j5b7zLNdd~QX0NPfXVMp1V~Z4fFBQAEAAcAAA==\ngts.varikvalef\
                or.i2p=cqwoYXfztQTzDKaPMsElmgfflDLLRBBvQSTgHfhBKnGkT-lKzL659h480A9YQuZfmKSzaplidYTvMPIrS4lhh4\
                m7ybvkt3Dv9bLd8QR7k14gw~arshKakr6HgkpUXU8uwA6ns45bsLKe~PbASIGbPEIudRjtrvmRpXxqy~0mpjkXkhhm8RJ\
                x3CM7iO62ZyspCXTI2GV2rbvcxyD6kEcQd-YrU5tnimSUN8b1WqbkoQBvEn1JR~mn-KJzR4RUpKd~FgqPesMI2rM8dyl4\
                bQkHv3XrWU3YZ75bsXaht80Ii6rrcPrD3LCERIC43rII0Y1UQarpij2ZyC508ccveIbGroUWOsrPz8tLklnIuvZIor~2M\
                kWK9e2zymXMPU~8ZJDVhAFd2PSJs~TFBrwvzD2mvcG-ChvrS051Gv1ZPIOqDLGdTEBC7BV2OyDlzKu0VnHsiS3h2PwBJd\
                Xx9zk~HXAA1hwLCjuIwSYpNIQxrEaFEu2Eh6keqo-kKidL~Lcxk~hUBQAEAAcAAA==".to_string();

            let mut addresses = HashMap::<String, (String, String)>::new();
            address_book.parse_and_merge(&mut addresses, new_hosts).await;
            address_book.save_to_disk(addresses).await;

            // verify all old and new hosts are found
            for host in [
                "psi.i2p",
                "zerobin.i2p",
                "tracker2.postman.i2p",
                "zzz.i2p",
                "echo.idk.i2p",
                "3chelectricboogaloo.i2p",
                "gts.varikvalefor.i2p",
            ] {
                assert!(handle.resolve_base32(host).is_some());
                assert!(handle.resolve_base64(host.to_string()).await.is_some());
            }
        }

        // load address book from disk again and verify all hosts are still in the address book
        {
            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;
            let handle = address_book.handle();

            for host in [
                "psi.i2p",
                "zerobin.i2p",
                "tracker2.postman.i2p",
                "zzz.i2p",
                "echo.idk.i2p",
                "3chelectricboogaloo.i2p",
                "gts.varikvalefor.i2p",
            ] {
                assert!(handle.resolve_base32(host).is_some());
                assert!(handle.resolve_base64(host.to_string()).await.is_some());
            }
        }
    }

    #[tokio::test]
    async fn add_base32_address() {
        // create address book
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
                J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
                E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
                umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
                KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
                O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
                gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
                n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
                PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
                1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
                Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
                p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
                PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
                Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
                bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
                S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
                DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
                WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
                bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
                JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
                AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
                Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
                pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
                Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
                e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            dir
        };

        // simulate new boot and add new base32 address to address book
        {
            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;
            let handle = address_book.handle();

            handle.add_base32(
                "i2pd.i2p".to_string(),
                "4bpcp4fmvyr46vb4kqjvtxlst6puz4r3dld24umooiy5mesxzspa".to_string(),
            );

            // verify that base32 address for i2pd is found
            assert_eq!(
                handle.resolve_base32("i2pd.i2p"),
                Some(String::from(
                    "4bpcp4fmvyr46vb4kqjvtxlst6puz4r3dld24umooiy5mesxzspa"
                ))
            );
        }

        // simulate another boot and verify i2pd.i2p has been stored on disk
        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;

        assert_eq!(
            address_book.handle().resolve_base32("i2pd.i2p"),
            Some(String::from(
                "4bpcp4fmvyr46vb4kqjvtxlst6puz4r3dld24umooiy5mesxzspa"
            ))
        );
    }

    #[tokio::test]
    async fn add_base64_address() {
        // create address book
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
                J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
                E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
                umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
                KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
                O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
                gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
                n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
                PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
                1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
                Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
                p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
                PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
                Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
                bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
                S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
                DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
                WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
                bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
                JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
                AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
                Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
                pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
                Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
                e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            dir
        };

        // simulate new boot and add new base32 address to address book
        let base64_destination = {
            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: None,
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;
            let handle = address_book.handle();

            let base64_destination = "75Mgd8DeYkNAdk6mrF0rOt3WuM6bYi3k7n3BRIp-np5-5-py1YTmBJSRq9EXL1YrweU\
                pal~ZT~46~-lMW~zKHA46iTWsZzKFMEKFdfoM2fSgZDlEaoalW4QzkQjbOVO0atkEK15uXO2WiCRgfUab0Gyp-\
                EcGkdQq8FuF~sPLlm4xa90cmT6G~s1SeaNLII8DPli-XqZppSGOSArMSEYsxZPNfKs5UxvEeCrbUjBLCGhy2K3\
                x926Af9bZk1ITIW~K70xo-rSD0SbDXO9vT4e7fiq21Q2LicAofn~Y4MwPz6jr0CUZQAHxwCy1N3OR0XYFsTI4X\
                S1LZ3zGwVpEjCfVD1mQhCLzzIjRHgGB6Cr3xj3FntBhv0d9pBuogUjOkLEnmFHpj5ONE7l~3aUsR6vRYTUDfwn\
                xXnIi9KF-PPyOAACXCz~T06QXVfaqzTj8tyr40cUqKIZHquaMZrAkqqa26KM3l0fu755UVo43MfD3f9zo3erjo\
                ~UDI~oP1bYyEU3LBQAEAAcAAA==";
            let deserialized = base64_decode(base64_destination).unwrap();
            let destination = Destination::parse(&deserialized).unwrap();

            handle.add_base64("echo.idk.i2p".to_string(), destination);

            // verify that base32 address for echo.idk is found
            assert_eq!(
                handle.resolve_base32("echo.idk.i2p"),
                Some(String::from(
                    "63sgpiu6f33arldcxkbjsn3jgf6asyx3onjmz6j6gsk7hgbiehkq"
                ))
            );
            assert_eq!(
                handle.resolve_base64("echo.idk.i2p".to_string()).await,
                Some(base64_destination.to_string())
            );

            base64_destination
        };

        // simulate another boot and verify i2pd.i2p has been stored on disk
        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;
        let handle = address_book.handle();

        assert_eq!(
            handle.resolve_base32("echo.idk.i2p"),
            Some(String::from(
                "63sgpiu6f33arldcxkbjsn3jgf6asyx3onjmz6j6gsk7hgbiehkq"
            ))
        );
        assert_eq!(
            handle.resolve_base64("echo.idk.i2p".to_string()).await,
            Some(base64_destination.to_string())
        );
    }

    #[tokio::test]
    async fn remove_host() {
        // create address book and remove zzz.i2p from it
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
                J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
                E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
                umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
                KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
                O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
                gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
                n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
                PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
                1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
                Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
                p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
                PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
                Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
                bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
                S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
                DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
                WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
                bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
                JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
                AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
                Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
                pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
                Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
                e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            let handle = address_book.handle();
            assert!(handle.resolve_base32("zzz.i2p").is_some());
            assert!(handle.resolve_base64("zzz.i2p".to_string()).await.is_some());

            // remove host and verify it's no longer found
            handle.remove("zzz.i2p");

            assert!(handle.resolve_base32("zzz.i2p").is_none());
            assert!(handle.resolve_base64("zzz.i2p".to_string()).await.is_none());

            dir
        };

        // simulate another boot and verify zzz.i2p is not found in the address book
        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;
        let handle = address_book.handle();

        assert!(handle.resolve_base32("zzz.i2p").is_none());
        assert!(handle.resolve_base64("zzz.i2p".to_string()).await.is_none());
    }

    #[tokio::test]
    async fn duplicate_entries_ignored() {
        // create address book
        let dir = {
            let dir = tempdir().unwrap().keep();
            tokio::fs::create_dir_all(&dir.join("addressbook")).await.unwrap();

            let address_book = AddressBookManager::new(
                dir.clone(),
                AddressBookConfig {
                    default: Some(String::from("url")),
                    subscriptions: None,
                    refresh_hours: None,
                },
            )
            .await;

            let mut addresses = HashMap::<String, (String, String)>::new();
            let hosts = "zerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVgDZRuaToRlXIFW4k5J1ccTzGzMxR518Bk\
                CAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8SWcxWdTbKU-O8IpE3O\
                01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYhbf\
                M7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZ\
                nGKPEBD31hVLdJuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l\
                ~BvPl2OKQIBhXIxJLOOavGyqmmYmAAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-e\
                OD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dmXl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH\
                6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6\
                Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6Uri3usE3XWD7Pw6P8qVYF39jUIq4\
                OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpne8cuesn3NDXIp\
                NnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

            address_book.parse_and_merge(&mut addresses, hosts).await;
            address_book.save_to_disk(addresses).await;

            dir
        };

        // simulate another boot and verify zzz.i2p is not found in the address book
        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;

        // read original values from disk and verify only zerobin.i2p and zzz.i2p exist
        let original_values =
            tokio::fs::read_to_string(dir.join("addressbook/addresses")).await.unwrap();

        assert_eq!(original_values.matches("tracker2.postman.i2p").count(), 0);
        assert_eq!(original_values.matches("psi.i2p").count(), 0);
        assert_eq!(original_values.matches("zerobin.i2p").count(), 1);
        assert_eq!(original_values.matches("zzz.i2p").count(), 1);

        // add new hosts, tracker2.postman.i2p is new and zerobin.i2p and zzz.i2p already
        // exist in the address book
        let mut addresses = HashMap::<String, (String, String)>::new();
        let hosts = "tracker2.postman.i2p=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHhn853zjVXrJBgwlB9sO57KakBDa\
            J50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~PUJQxRwceaTMn96FcVenwdXqle\
            E16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG1kOIBeDD3XF8BWb6K3GOOoyjc1\
            umYKpur3G~FxBuqtHAsDRICrsRuil8qK~whOvj8uNTv~ohZnTZHxTLgi~sDyo98BwJ-4Y4NMSuF4GLzcgLypcR1D1WY2tDqMKRYFVyLE~MTPVjRRgXfc\
            KolykQ666~Go~A~~CNV4qc~zlO6F4bsUhVZDU7WJ7mxCAwqaMiJsL-NgIkb~SMHNxIzaE~oy0agHJMBQAEAAcAAA==#!oldsig=i02RMv3Hy86NGhVo2\
            O3byIf6xXqWrzrRibSabe5dmNfRRQPZO9L25A==#date=1598641102#action=adddest#sig=cB-mY~sp1uuEmcQJqremV1D6EDWCe3IwPv4lBiGAX\
            gKRYc5MLBBzYvJXtXmOawpfLKeNM~v5fWlXYsDfKf5nDA==#olddest=lnQ6yoBTxQuQU8EQ1FlF395ITIQF-HGJxUeFvzETLFnoczNjQvKDbtSB7aHh\
            n853zjVXrJBgwlB9sO57KakBDaJ50lUZgVPhjlI19TgJ-CxyHhHSCeKx5JzURdEW-ucdONMynr-b2zwhsx8VQCJwCEkARvt21YkOyQDaB9IdV8aTAmP~\
            PUJQxRwceaTMn96FcVenwdXqleE16fI8CVFOV18jbJKrhTOYpTtcZKV4l1wNYBDwKgwPx5c0kcrRzFyw5~bjuAKO~GJ5dR7BQsL7AwBoQUS4k1lwoYrG\
            1kOIBeDD3XF8BWb6K3GOOoyjc1umYKpur3G~FxBuqtHAsDRICkEbKUqJ9mPYQlTSujhNxiRIW-oLwMtvayCFci99oX8MvazPS7~97x0Gsm-onEK1Td9n\
            Bdmq30OqDxpRtXBimbzkLbR1IKObbg9HvrKs3L-kSyGwTUmHG9rSQSoZEvFMA-S0EXO~o4g21q1oikmxPMhkeVwQ22VHB0-LZJfmLr4SAAAA\npsi.i2\
            p=a11l91etedRW5Kl2GhdDI9qiRBbDRAQY6TWJb8KlSc0P9WUrEviABAAltqDU1DFJrRhMAZg5i6rWGszkJrF-pWLQK9JOH33l4~mQjB8Hkt83l9qnNJ\
            PUlGlh9yIfBY40CQ0Ermy8gzjHLayUpypDJFv2V6rHLwxAQeaXJu8YXbyvCucEu9i6HVO49akXW9YSxcZEqxK04wZnjBqhHGlVbehleMqTx9nkd0pUpB\
            Zz~vIaG9matUSHinopEo6Wegml9FEz~FEaQpPknKuMAGGSNFVJb0NtaOQSAocAOg1nLKh80v232Y8sJOHG63asSJoBa6bGwjIHftsqD~lEmVV4NkgNPy\
            bmvsD1SCbMQ2ExaCXFPVQV-yJhIAPN9MRVT9cSBT2GCq-vpMwdJ5Nf0iPR3M-Ak961JUwWXPYTL79toXCgxDX2~nZ5QFRV490YNnfB7LQu10G89wG8lz\
            S9GWf2i-nk~~ez0Lq0dH7qQokFXdUkPc7bvSrxqkytrbd-h8O8AAAA\nzerobin.i2p=Jf64hlpW8ILKZGDe61ljHU5wzmUYwN2klOyhM2iR-8VkUEVg\
            DZRuaToRlXIFW4k5J1ccTzGzMxR518BkCAE3jCFIyrbF0MjQDuXO5cwmqfBFWrIv72xgKDizu3HytE4vOF2M730rv8epSNPAJg6OpyXkf5UQW96kgL8S\
            WcxWdTbKU-O8IpE3O01Oc6j0fp1E4wVOci7qIL8UEloNN~mulgka69MkR0uEtXWOXd6wvBjLNrZgdZi7XtT4QlDjx13jr7RGpZBJAUkk~8gLqgJwoUYh\
            bfM7x564PIn3IlMXHK5AKRVxAbCQ5GkS8KdkvNL7FsQ~EiElGzZId4wenraHMHL0destUDmuwGdHKA7YdtovXD~OnaBvIbl36iuIduZnGKPEBD31hVLd\
            JuVId9RND7lQy5BZJHQss5HSxMWTszAnWJDwmxqzMHHCiL6BMpZnkz8znwPDSkUwEs3P6-ba7mDKKt8EPCG0nM6l~BvPl2OKQIBhXIxJLOOavGyqmmYm\
            AAAA\nzzz.i2p=GKapJ8koUcBj~jmQzHsTYxDg2tpfWj0xjQTzd8BhfC9c3OS5fwPBNajgF-eOD6eCjFTqTlorlh7Hnd8kXj1qblUGXT-tDoR9~YV8dm\
            Xl51cJn9MVTRrEqRWSJVXbUUz9t5Po6Xa247Vr0sJn27R4KoKP8QVj1GuH6dB3b6wTPbOamC3dkO18vkQkfZWUdRMDXk0d8AdjB0E0864nOT~J9Fpnd2\
            pQE5uoFT6P0DqtQR2jsFvf9ME61aqLvKPPWpkgdn4z6Zkm-NJOcDz2Nv8Si7hli94E9SghMYRsdjU-knObKvxiagn84FIwcOpepxuG~kFXdD5NfsH0v6\
            Uri3usE3XWD7Pw6P8qVYF39jUIq4OiNMwPnNYzy2N4mDMQdsdHO3LUVh~DEppOy9AAmEoHDjjJxt2BFBbGxfdpZCpENkwvmZeYUyNCCzASqTOOlNzdpn\
            e8cuesn3NDXIpNnqEE6Oe5Qm5YOJykrX~Vx~cFFT3QzDGkIjjxlFBsjUJyYkFjBQAEAAcAAA==".to_string();

        address_book.parse_and_merge(&mut addresses, hosts).await;
        address_book.save_to_disk(addresses).await;

        // read updated values from disk, verify all hosts exist and that there aren't duplicate
        let new_values =
            tokio::fs::read_to_string(dir.join("addressbook/addresses")).await.unwrap();

        assert_eq!(new_values.matches("tracker2.postman.i2p").count(), 1);
        assert_eq!(new_values.matches("psi.i2p").count(), 1);
        assert_eq!(new_values.matches("zerobin.i2p").count(), 1);
        assert_eq!(new_values.matches("zzz.i2p").count(), 1);

        // verify `addresses` have also been updated
        assert!(address_book.addresses.read().get("tracker2.postman.i2p").is_some());
        assert!(address_book.addresses.read().get("psi.i2p").is_some());
        assert!(address_book.addresses.read().get("zerobin.i2p").is_some());
        assert!(address_book.addresses.read().get("zzz.i2p").is_some());

        // create new address book with updated entries and verify all hosts are there
        let address_book_new = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: None,
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;

        assert!(address_book_new.addresses.read().get("tracker2.postman.i2p").is_some());
        assert!(address_book_new.addresses.read().get("psi.i2p").is_some());
        assert!(address_book_new.addresses.read().get("zerobin.i2p").is_some());
        assert!(address_book_new.addresses.read().get("zzz.i2p").is_some());
    }

    #[tokio::test]
    async fn simple_save_load_host_modified() {
        let dir = tempdir().unwrap().path().to_owned();
        let addressbook_dir = dir.join("addressbook");
        tokio::fs::create_dir_all(addressbook_dir).await.unwrap();
        let address_book = AddressBookManager::new(
            dir.clone(),
            AddressBookConfig {
                default: Some(String::from("url")),
                subscriptions: None,
                refresh_hours: None,
            },
        )
        .await;
        let loaded = HashMap::from_iter([(
            "foo".to_string(),
            Modified {
                etag: "bar".to_string(),
                last_modified: "baz".to_string(),
            },
        )]);
        address_book.save_host_modified_times(loaded.clone()).await;
        let saved = address_book.load_host_modified_times().await;
        assert_eq!(loaded, saved);
    }
}
