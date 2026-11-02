#![no_main]

use libfuzzer_sys::fuzz_target;
use nodenet_protocols::{IpAddress, Ipv4Address, ProbePort};
use nodenetscanner_engine::{
    ProbeDefinition, ProbeFamily, ScanPlan, SchedulingSeed, SeededPermutation, TargetEndpoint,
    TargetInput, TargetIntervalInput, TargetSet,
};

fuzz_target!(|data: &[u8]| {
    let mut includes = Vec::new();
    let mut excludes = Vec::new();
    for (index, chunk) in data.chunks_exact(9).take(128).enumerate() {
        let start = endpoint([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let end = endpoint([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let input = TargetInput::Range(TargetIntervalInput { start, end });
        if chunk[8] & 1 == 0 || index == 0 {
            includes.push(input);
        } else {
            excludes.push(input);
        }
    }
    if includes.is_empty() {
        includes.push(TargetInput::Address(endpoint([127, 0, 0, 1])));
    }
    let Ok(targets) = TargetSet::normalize(&includes, &excludes) else {
        return;
    };
    for family in [4, 6] {
        let count = if family == 4 {
            targets.ipv4_count()
        } else {
            targets.ipv6_count()
        };
        if count > 0 {
            let _ = targets.target_at_family(family, count - 1);
            let _ = targets.target_at_family(family, count);
        }
    }
    let port = u16::from_be_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(1),
    ]);
    let Ok(port) = ProbePort::new(port) else {
        return;
    };
    let Ok(probe) = ProbeDefinition::new(ProbeFamily::TcpSyn, vec![port]) else {
        return;
    };
    let Ok(plan) = ScanPlan::new(targets, vec![probe], 1) else {
        return;
    };
    let seed = data
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    let Ok(permutation) =
        SeededPermutation::new(plan.logical_probe_count(), SchedulingSeed::Explicit(seed))
    else {
        return;
    };
    for ordinal in 0..plan.logical_probe_count().min(64) {
        let mapped = permutation.permute(ordinal);
        if let Some(mapped) = mapped {
            let _ = plan.logical_probe_at(mapped);
        }
    }
});

fn endpoint(octets: [u8; 4]) -> TargetEndpoint {
    TargetEndpoint {
        address: IpAddress::V4(Ipv4Address::new(octets)),
        scope: None,
    }
}
