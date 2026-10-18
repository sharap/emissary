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

use crate::ui::dioxus::{util::load_router_config, App, AppOptions, LOG_TARGET};

use axum::{
    extract::{State, WebSocketUpgrade},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use dioxus::prelude::*;
use dioxus_liveview::{axum_socket, interpreter_glue, LiveViewPool};
use tokio::net::TcpListener;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

/// Application data.
struct AppData {
    pool: LiveViewPool,
    params: AppOptions,
}

/// Start the web UI.
pub async fn start(params: AppOptions) {
    let port = params.config.router_ui.as_ref().and_then(|config| config.port).unwrap_or(7657);
    let host = params
        .config
        .router_ui
        .as_ref()
        .and_then(|config| config.host)
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let router = Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(ws_handler))
        .with_state(Arc::new(AppData {
            pool: LiveViewPool::new(),
            params,
        }));

    // a failure to start the web ui must not take the router down with it
    let listener = match TcpListener::bind(SocketAddr::new(host, port)).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                target: LOG_TARGET,
                %host,
                %port,
                ?error,
                "failed to bind web ui listener, running without web ui",
            );
            return std::future::pending::<()>().await;
        }
    };

    tracing::info!(
        target: LOG_TARGET,
        %host,
        %port,
        "web ui listening",
    );

    if let Err(error) = axum::serve(listener, router.into_make_service()).await {
        tracing::error!(
            target: LOG_TARGET,
            ?error,
            "web ui server exited, running without web ui",
        );
        std::future::pending::<()>().await
    }
}

/// Check that the `Origin` of a WebSocket upgrade matches the `Host` the request was sent to.
///
/// Browsers always send `Origin` on WebSocket upgrades, so a mismatch means a page served from
/// another site is trying to open the console's socket. Requests without `Origin` are not from a
/// browser and are allowed.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok()) else {
        return true;
    };

    let allowed = || {
        let host = headers.get(header::HOST)?.to_str().ok()?;
        let origin = url::Url::parse(origin).ok()?;
        let origin_authority = match origin.port() {
            Some(port) => format!("{}:{port}", origin.host_str()?),
            None => origin.host_str()?.to_string(),
        };

        Some(origin_authority.eq_ignore_ascii_case(host))
    };

    allowed().unwrap_or(false)
}

async fn index_handler() -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Emissary Router Console</title>
</head>
<body>
  <div id="main"></div>
  {glue}
</body>
</html>"#,
        glue = interpreter_glue("/ws"),
    ))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(data): State<Arc<AppData>>,
) -> Response {
    if !origin_allowed(&headers) {
        tracing::warn!(
            target: LOG_TARGET,
            origin = ?headers.get(header::ORIGIN),
            host = ?headers.get(header::HOST),
            "rejecting web ui connection from another origin",
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    ws.on_upgrade(move |socket| async move {
        // every connection starts from the configuration currently on disk so that settings
        // saved by another tab or an earlier connection are not overwritten with stale values
        let mut options = data.params.clone();
        match load_router_config(&options.base_path.join("router.toml")) {
            Some(config) => options.config = config,
            None => tracing::warn!(
                target: LOG_TARGET,
                "failed to reload router configuration, using the configuration from startup",
            ),
        }

        let params = Arc::new(Mutex::new(Some(options)));
        let _ = data
            .pool
            .launch_virtualdom(axum_socket(socket), move || {
                let mut vdom = VirtualDom::new(App);
                vdom.insert_any_root_context(Box::new(params));
                vdom
            })
            .await;
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(origin: Option<&'static str>, host: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(origin) = origin {
            headers.insert(header::ORIGIN, HeaderValue::from_static(origin));
        }
        if let Some(host) = host {
            headers.insert(header::HOST, HeaderValue::from_static(host));
        }
        headers
    }

    #[test]
    fn origin_must_match_host() {
        // browser on the same origin
        assert!(origin_allowed(&headers(
            Some("http://127.0.0.1:7657"),
            Some("127.0.0.1:7657")
        )));
        assert!(origin_allowed(&headers(
            Some("http://localhost:7657"),
            Some("LOCALHOST:7657")
        )));
        assert!(origin_allowed(&headers(Some("http://[::1]:7657"), Some("[::1]:7657"))));
        assert!(origin_allowed(&headers(Some("http://console.i2p"), Some("console.i2p"))));

        // page served from another site
        assert!(!origin_allowed(&headers(
            Some("http://evil.example"),
            Some("127.0.0.1:7657")
        )));
        assert!(!origin_allowed(&headers(
            Some("http://127.0.0.1:8080"),
            Some("127.0.0.1:7657")
        )));
        assert!(!origin_allowed(&headers(Some("null"), Some("127.0.0.1:7657"))));
        assert!(!origin_allowed(&headers(Some("http://127.0.0.1:7657"), None)));

        // non-browser client without `Origin`
        assert!(origin_allowed(&headers(None, Some("127.0.0.1:7657"))));
        assert!(origin_allowed(&headers(None, None)));
    }
}
