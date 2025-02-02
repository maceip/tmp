mod config;

pub use config::ProverConfig;

use enum_try_as_inner::EnumTryAsInner;
use futures::TryFutureExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use tls_client_async::TlsConnection;
use tlsn_core::Direction;
use tlsn_prover::tls::{state, Prover};
use tracing::info;
use wasm_bindgen::{prelude::*, JsError};
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{io::FuturesIo, types::*};

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen(js_name = Prover)]
pub struct JsProver {
    state: State,
}

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
enum State {
    Initialized(Prover<state::Initialized>),
    Setup(Prover<state::Setup>),
    Closed(Prover<state::Closed>),
    Complete,
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new(config: ProverConfig) -> JsProver {
        JsProver {
            state: State::Initialized(Prover::new(config.into())),
        }
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let prover = self.state.take().try_into_initialized()?;

        info!("connecting to verifier");

        let (_, verifier_conn) = WsMeta::connect(verifier_url, None).await?;

        info!("connected to verifier");

        let prover = prover.setup(verifier_conn.into_io()).await?;

        self.state = State::Setup(prover);

        Ok(())
    }

    /// Send the HTTP request to the server.
    pub async fn send_request(
        &mut self,
        ws_proxy_url: &str,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let prover = self.state.take().try_into_setup()?;

        info!("connecting to server");

        let (_, server_conn) = WsMeta::connect(ws_proxy_url, None).await?;

        info!("connected to server");

        let (tls_conn, prover_fut) = prover.connect(server_conn.into_io()).await?;
        let prover_ctrl = prover_fut.control();

        info!("sending request");

        let (response, prover) = futures::try_join!(
            async move {
                prover_ctrl.defer_decryption().await?;
                send_request(tls_conn, request).await
            },
            prover_fut.map_err(Into::into),
        )?;

        info!("response received");

        self.state = State::Closed(prover);

        Ok(response)
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> Result<Transcript> {
        let prover = self.state.try_as_closed()?;

        let sent = prover.sent_transcript().data().clone();
        let recv = prover.recv_transcript().data().clone();

        Ok(Transcript {
            sent: sent.to_vec(),
            recv: recv.to_vec(),
        })
    }

    /// Runs the notarization protocol.
    pub async fn notarize(&mut self, commit: Commit) -> Result<NotarizedSession> {
        let mut prover = self.state.take().try_into_closed()?.start_notarize();

        info!("starting notarization");

        let builder = prover.commitment_builder();

        for range in commit.sent {
            builder.commit_sent(&range)?;
        }

        for range in commit.recv {
            builder.commit_recv(&range)?;
        }

        let notarized_session = prover.finalize().await?;

        info!("notarization complete");

        Ok(notarized_session.into())
    }

    /// Reveals data to the verifier and finalizes the protocol.
    pub async fn reveal(&mut self, reveal: Reveal) -> Result<()> {
        let mut prover = self.state.take().try_into_closed()?.start_prove();

        info!("revealing data");

        for range in reveal.sent {
            prover.reveal(range, Direction::Sent)?;
        }

        for range in reveal.recv {
            prover.reveal(range, Direction::Received)?;
        }

        prover.prove().await?;
        prover.finalize().await?;

        info!("Finalized");

        self.state = State::Complete;

        Ok(())
    }
}

impl From<Prover<state::Initialized>> for JsProver {
    fn from(value: Prover<state::Initialized>) -> Self {
        JsProver {
            state: State::Initialized(value),
        }
    }
}

async fn send_request(conn: TlsConnection, request: HttpRequest) -> Result<HttpResponse> {
    let conn = FuturesIo::new(conn);
    let request = hyper::Request::<Full<Bytes>>::try_from(request)?;

    let (mut request_sender, conn) = hyper::client::conn::http1::handshake(conn).await?;

    spawn_local(async move { conn.await.expect("connection runs to completion") });

    let response = request_sender.send_request(request).await?;

    let (response, body) = response.into_parts();

    // TODO: return the body
    let _body = body.collect().await?;

    let headers = response
        .headers
        .into_iter()
        .map(|(k, v)| {
            (
                k.map(|k| k.to_string()).unwrap_or_default(),
                v.as_bytes().to_vec(),
            )
        })
        .collect();

    Ok(HttpResponse {
        status: response.status.as_u16(),
        headers,
    })
}
