use nodenet_protocols::{
    UDP_PROBE_CATALOGUE, UDP_PROBE_CATALOGUE_SHA256_HEX, UDP_PROBE_CATALOGUE_VERSION,
    udp_probe_catalogue_sha256_hex, validate_udp_probe_catalogue,
};

fn main() {
    validate_udp_probe_catalogue(UDP_PROBE_CATALOGUE)
        .expect("the compiled UDP catalogue must satisfy its deterministic contract");
    let digest = udp_probe_catalogue_sha256_hex(UDP_PROBE_CATALOGUE);
    assert_eq!(
        digest, UDP_PROBE_CATALOGUE_SHA256_HEX,
        "catalogue content changed without updating its frozen capability hash"
    );
    println!(
        "{} {} {}",
        UDP_PROBE_CATALOGUE_VERSION,
        UDP_PROBE_CATALOGUE.len(),
        digest
    );
}
