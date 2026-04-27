//! Integration tests for service-hub-demo local and HTTP resolution.

#![allow(clippy::unwrap_used)]
#![cfg_attr(coverage_nightly, coverage(off))]

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use futures_util::StreamExt;
use modkit::ClientHub;
use modkit_canonical_errors::CanonicalError;
use modkit_contract::ir::binding::HttpBindingIr;
use modkit_http::HttpClient;
use modkit_security::SecurityContext;
use modkit_service_hub::hub::ServiceHub;
use modkit_service_hub::resolver::HybridResolver;
use service_hub_demo_sdk::contract::PaymentService;
use service_hub_demo_sdk::models::{ChargeRequest, ListPaymentsFilter, PaymentStatus};

use cf_service_hub_demo::api::rest::routes::register_routes;
use cf_service_hub_demo::binding::payment_service_http_binding;
use cf_service_hub_demo::client::factory::PaymentServiceFactory;
use cf_service_hub_demo::client::local::PaymentLocalClient;
use cf_service_hub_demo::client::remote::PaymentHttpClient;
use cf_service_hub_demo::domain::service::PaymentDomainService;

fn test_ctx() -> SecurityContext {
    SecurityContext::anonymous()
}

fn sample_charge_request() -> ChargeRequest {
    ChargeRequest {
        amount_cents: 1000,
        currency: "USD".to_owned(),
        description: "Test payment".to_owned(),
    }
}

// --- Local client tests ---

#[tokio::test]
async fn local_charge_returns_pending() {
    let svc = Arc::new(PaymentDomainService::new());
    let client = PaymentLocalClient::new(Arc::clone(&svc), Arc::new(modkit_service_hub::policy::PolicyStack::new()));

    let resp = client
        .charge(test_ctx(), sample_charge_request())
        .await
        .unwrap();
    assert_eq!(resp.status, PaymentStatus::Pending);
    assert!(!resp.payment_id.is_nil());
}

#[tokio::test]
async fn local_get_invoice_not_found() {
    let svc = Arc::new(PaymentDomainService::new());
    let client = PaymentLocalClient::new(svc, Arc::new(modkit_service_hub::policy::PolicyStack::new()));

    let err = client
        .get_invoice(test_ctx(), uuid::Uuid::new_v4().to_string())
        .await
        .unwrap_err();
    assert!(matches!(err, CanonicalError::NotFound { .. }));
}

#[tokio::test]
async fn local_charge_then_get_invoice() {
    let svc = Arc::new(PaymentDomainService::new());
    let client = PaymentLocalClient::new(Arc::clone(&svc), Arc::new(modkit_service_hub::policy::PolicyStack::new()));

    let charge_resp = client
        .charge(test_ctx(), sample_charge_request())
        .await
        .unwrap();

    let invoice = client
        .get_invoice(test_ctx(), charge_resp.payment_id.to_string())
        .await
        .unwrap();
    assert_eq!(invoice.payment_id, charge_resp.payment_id);
    assert_eq!(invoice.amount_cents, 1000);
    assert_eq!(invoice.currency, "USD");
}

#[tokio::test]
async fn local_list_payments_empty() {
    let svc = Arc::new(PaymentDomainService::new());
    let client = PaymentLocalClient::new(svc, Arc::new(modkit_service_hub::policy::PolicyStack::new()));

    let items: Vec<_> = client
        .list_payments(test_ctx(), ListPaymentsFilter::default())
        .collect()
        .await;
    assert!(items.is_empty());
}

#[tokio::test]
async fn local_list_payments_with_filter() {
    let svc = Arc::new(PaymentDomainService::new());
    let client = PaymentLocalClient::new(Arc::clone(&svc), Arc::new(modkit_service_hub::policy::PolicyStack::new()));

    // Charge 2 USD, 1 EUR.
    let usd = ChargeRequest {
        amount_cents: 500,
        currency: "USD".to_owned(),
        description: "usd1".to_owned(),
    };
    let eur = ChargeRequest {
        amount_cents: 300,
        currency: "EUR".to_owned(),
        description: "eur1".to_owned(),
    };
    client.charge(test_ctx(), usd.clone()).await.unwrap();
    client.charge(test_ctx(), usd).await.unwrap();
    client.charge(test_ctx(), eur).await.unwrap();

    // Filter by EUR.
    let filter = ListPaymentsFilter {
        currency: Some("EUR".to_owned()),
        status: None,
    };
    let items: Vec<_> = client
        .list_payments(test_ctx(), filter)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].currency, "EUR");
}

// --- ServiceHub resolution tests ---

#[tokio::test]
async fn service_hub_resolves_local_client() {
    let client_hub = Arc::new(ClientHub::new());
    let resolver = Arc::new(HybridResolver::new(HashMap::new()));
    resolver.register_local("service-hub-demo");

    let service_hub = ServiceHub::new(Arc::clone(&client_hub), resolver);

    let domain_svc = Arc::new(PaymentDomainService::new());
    service_hub.register_factory(Arc::new(PaymentServiceFactory {
        local_service: Some(domain_svc),
        policy_stack: Arc::new(modkit_service_hub::policy::PolicyStack::new()),
    }));

    let client = service_hub.resolve::<dyn PaymentService>().await.unwrap();

    let resp = client
        .charge(test_ctx(), sample_charge_request())
        .await
        .unwrap();
    assert_eq!(resp.status, PaymentStatus::Pending);
}

#[tokio::test]
async fn service_hub_returns_cached_client() {
    let client_hub = Arc::new(ClientHub::new());
    let resolver = Arc::new(HybridResolver::new(HashMap::new()));
    resolver.register_local("service-hub-demo");

    let service_hub = ServiceHub::new(Arc::clone(&client_hub), resolver);

    let domain_svc = Arc::new(PaymentDomainService::new());
    service_hub.register_factory(Arc::new(PaymentServiceFactory {
        local_service: Some(domain_svc),
        policy_stack: Arc::new(modkit_service_hub::policy::PolicyStack::new()),
    }));

    let client1 = service_hub.resolve::<dyn PaymentService>().await.unwrap();
    let client2 = service_hub.resolve::<dyn PaymentService>().await.unwrap();

    // Same Arc (pointer equality).
    assert!(Arc::ptr_eq(&client1, &client2));
}

#[tokio::test]
async fn service_hub_finds_direct_registration() {
    let client_hub = Arc::new(ClientHub::new());
    let resolver = Arc::new(HybridResolver::new(HashMap::new()));

    // Direct-register (like the module does in init).
    let domain_svc = Arc::new(PaymentDomainService::new());
    let local_client: Arc<dyn PaymentService> = Arc::new(PaymentLocalClient::new(domain_svc, Arc::new(modkit_service_hub::policy::PolicyStack::new())));
    client_hub.register::<dyn PaymentService>(local_client);

    let service_hub = ServiceHub::new(client_hub, resolver);

    // resolve() should find the cached entry without needing a factory.
    let client = service_hub.resolve::<dyn PaymentService>().await.unwrap();
    let resp = client
        .charge(test_ctx(), sample_charge_request())
        .await
        .unwrap();
    assert_eq!(resp.status, PaymentStatus::Pending);
}

// --- HTTP transport tests ---

/// Spin up an Axum server with REST routes and return its base URL.
async fn start_test_server() -> (String, Arc<PaymentDomainService>) {
    let svc = Arc::new(PaymentDomainService::new());
    let app = register_routes(Router::new(), Arc::clone(&svc));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), svc)
}

/// Create a `PaymentHttpClient` pointing at the test server.
fn http_client(base_url: &str) -> PaymentHttpClient {
    let http = HttpClient::builder().build().unwrap();
    let binding: Arc<HttpBindingIr> = Arc::new(payment_service_http_binding());
    PaymentHttpClient::new(http, base_url.to_owned(), binding)
}

#[tokio::test]
async fn http_charge_returns_pending() {
    let (base_url, _svc) = start_test_server().await;
    let client = http_client(&base_url);

    let resp = client
        .charge(test_ctx(), sample_charge_request())
        .await
        .unwrap();
    assert_eq!(resp.status, PaymentStatus::Pending);
    assert!(!resp.payment_id.is_nil());
}

#[tokio::test]
async fn http_charge_then_get_invoice() {
    let (base_url, _svc) = start_test_server().await;
    let client = http_client(&base_url);

    let charge_resp = client
        .charge(test_ctx(), sample_charge_request())
        .await
        .unwrap();

    let invoice = client
        .get_invoice(test_ctx(), charge_resp.payment_id.to_string())
        .await
        .unwrap();
    assert_eq!(invoice.payment_id, charge_resp.payment_id);
    assert_eq!(invoice.amount_cents, 1000);
    assert_eq!(invoice.currency, "USD");
}

#[tokio::test]
async fn http_get_invoice_not_found() {
    let (base_url, _svc) = start_test_server().await;
    let client = http_client(&base_url);

    let err = client
        .get_invoice(test_ctx(), uuid::Uuid::new_v4().to_string())
        .await
        .unwrap_err();
    assert!(matches!(err, CanonicalError::NotFound { .. }));
}

#[tokio::test]
async fn http_list_payments_sse() {
    let (base_url, _svc) = start_test_server().await;
    let client = http_client(&base_url);

    // Charge 2 USD, 1 EUR.
    client
        .charge(
            test_ctx(),
            ChargeRequest {
                amount_cents: 500,
                currency: "USD".to_owned(),
                description: "usd1".to_owned(),
            },
        )
        .await
        .unwrap();
    client
        .charge(
            test_ctx(),
            ChargeRequest {
                amount_cents: 600,
                currency: "USD".to_owned(),
                description: "usd2".to_owned(),
            },
        )
        .await
        .unwrap();
    client
        .charge(
            test_ctx(),
            ChargeRequest {
                amount_cents: 300,
                currency: "EUR".to_owned(),
                description: "eur1".to_owned(),
            },
        )
        .await
        .unwrap();

    // List all — should get 3.
    let items: Vec<_> = client
        .list_payments(test_ctx(), ListPaymentsFilter::default())
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(items.len(), 3);

    // Filter by EUR — should get 1.
    let eur_items: Vec<_> = client
        .list_payments(
            test_ctx(),
            ListPaymentsFilter {
                currency: Some("EUR".to_owned()),
                status: None,
            },
        )
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(eur_items.len(), 1);
    assert_eq!(eur_items[0].currency, "EUR");
}

#[tokio::test]
async fn service_hub_resolves_http_client() {
    let (base_url, _svc) = start_test_server().await;

    let client_hub = Arc::new(ClientHub::new());
    let mut endpoints = HashMap::new();
    endpoints.insert("service-hub-demo".to_owned(), base_url);
    let resolver = Arc::new(HybridResolver::new(endpoints));

    let service_hub = ServiceHub::new(Arc::clone(&client_hub), resolver);

    service_hub.register_factory(Arc::new(PaymentServiceFactory {
        local_service: None,
        policy_stack: Arc::new(modkit_service_hub::policy::PolicyStack::new()),
    }));

    let client = service_hub.resolve::<dyn PaymentService>().await.unwrap();

    let resp = client
        .charge(test_ctx(), sample_charge_request())
        .await
        .unwrap();
    assert_eq!(resp.status, PaymentStatus::Pending);
}
