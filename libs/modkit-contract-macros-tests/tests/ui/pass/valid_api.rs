//! Valid `Api` contract — must compile.

use modkit_contract::contract;

#[contract(module = "demo", version = "v1")]
pub trait DemoApi: Send + Sync {
    async fn ping(&self) -> Result<String, std::io::Error>;
}

fn main() {}
