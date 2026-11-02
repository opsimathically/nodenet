#[cfg(not(target_os = "linux"))]
compile_error!("nodenetraw supports Linux only");

pub mod advanced;
pub mod batch;
pub mod conversion;
pub mod error;
pub mod lifecycle;
pub mod linux;
pub mod message;
pub mod packet;
pub mod reactor;
pub mod ring;

#[cfg(feature = "fuzzing")]
pub mod fuzzing;

pub mod binding;

use napi_derive::napi;

const SMOKE_TEST_VALUE: &str = "nodenetraw:napi-ok";

/// Confirms that Node.js can call through Node-API into this Rust library.
#[must_use]
#[napi]
pub fn native_smoke_test() -> String {
    String::from(SMOKE_TEST_VALUE)
}

#[cfg(test)]
mod tests {
    use super::{SMOKE_TEST_VALUE, native_smoke_test};

    #[test]
    fn smoke_test_value_is_stable() {
        assert_eq!(native_smoke_test(), SMOKE_TEST_VALUE);
    }
}
