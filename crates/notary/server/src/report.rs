
use mc_sgx_core_types::{Report, TargetInfo};
use mc_sgx_dcap_ql::{Error, QeTargetInfo, TryFromReport};
use mc_sgx_dcap_quoteverify::{Collateral as CollateralTrait, Error as QuoteVerifyError};
use mc_sgx_dcap_types::{Collateral, QlError, Quote3};
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse},
    Json,
};


use serde_json::json;

   pub fn collateral<Q: AsRef<[u8]>>(quote: &Quote3<Q>) -> Result<Collateral, QuoteVerifyError> {
        quote.collateral()
    }

pub async fn Generate() 
-> impl IntoResponse {
    let report = Report::default();
        let quote = Quote3::try_from_report(report.clone()).map_err(|error| match error {
            Error::Quote3(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
            Error::QuoteLibrary(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
            _ => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
        });
        (StatusCode::OK, Json(json!({ "quote": quote.expect("err").collateral() })))

}
