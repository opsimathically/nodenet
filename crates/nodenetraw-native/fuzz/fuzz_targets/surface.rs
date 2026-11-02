#![no_main]

use libfuzzer_sys::fuzz_target;
use nodenetraw_native::fuzzing::fuzz_surface;

fuzz_target!(|data: &[u8]| fuzz_surface(data));
