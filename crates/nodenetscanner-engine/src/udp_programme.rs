use nodenet_protocols::{IpAddress, ProbePort};

use crate::{MAX_UDP_PROBE_VARIANTS, MAX_UDP_VARIANT_METADATA_BYTES, PlanError, ProbeVariantId};

/// Compact description of one physical request in a logical UDP programme.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpProbeVariant {
    pub catalogue_probe_id: Option<ProbeVariantId>,
    /// Index into the immutable native request snapshot for this address family.
    pub request_index: u16,
    /// Maximum metadata bytes this variant may contribute if it wins.
    pub maximum_metadata_bytes: u16,
    /// Stable service family used only to narrow adaptive follow-up probes.
    pub service_family: Option<u16>,
    pub eligibility: UdpVariantEligibility,
}

/// Frozen UDP programme execution policy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum UdpProbeStrategy {
    Adaptive,
    #[default]
    Exhaustive,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UdpVariantEligibility {
    AnyPort,
    DestinationPort(ProbePort),
    DestinationPortRange { start: ProbePort, end: ProbePort },
    UnmappedFallback,
    AfterProgrammeFallback,
}

impl UdpProbeVariant {
    /// Creates one checked immutable variant.
    ///
    /// # Errors
    ///
    /// Rejects metadata reservations above the per-variant ceiling.
    pub fn new(
        catalogue_probe_id: Option<ProbeVariantId>,
        request_index: u16,
        maximum_metadata_bytes: u16,
    ) -> Result<Self, PlanError> {
        if usize::from(maximum_metadata_bytes) > MAX_UDP_VARIANT_METADATA_BYTES {
            return Err(PlanError::InvalidUdpMetadataReservation);
        }
        Ok(Self {
            catalogue_probe_id,
            request_index,
            maximum_metadata_bytes,
            service_family: None,
            eligibility: UdpVariantEligibility::AnyPort,
        })
    }

    #[must_use]
    pub const fn with_eligibility(mut self, eligibility: UdpVariantEligibility) -> Self {
        self.eligibility = eligibility;
        self
    }

    #[must_use]
    pub const fn with_service_family(mut self, service_family: u16) -> Self {
        self.service_family = Some(service_family);
        self
    }
}

/// Immutable per-family UDP programme decoded lazily by the scheduler.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UdpProbeProgramme {
    ipv4: Box<[UdpProbeVariant]>,
    ipv6: Box<[UdpProbeVariant]>,
    strategy: UdpProbeStrategy,
}

impl UdpProbeProgramme {
    /// Creates one checked deterministic per-family programme.
    ///
    /// # Errors
    ///
    /// Rejects excessive or duplicate variants and invalid reservations.
    pub fn new(ipv4: Vec<UdpProbeVariant>, ipv6: Vec<UdpProbeVariant>) -> Result<Self, PlanError> {
        validate_family(&ipv4)?;
        validate_family(&ipv6)?;
        Ok(Self {
            ipv4: ipv4.into_boxed_slice(),
            ipv6: ipv6.into_boxed_slice(),
            strategy: UdpProbeStrategy::Exhaustive,
        })
    }

    /// Selects the immutable execution policy without changing programme bytes.
    #[must_use]
    pub const fn with_strategy(mut self, strategy: UdpProbeStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    #[must_use]
    pub const fn strategy(&self) -> UdpProbeStrategy {
        self.strategy
    }

    /// Compatibility programme used by existing empty/custom UDP scans.
    #[must_use]
    pub fn single() -> Self {
        let variant = UdpProbeVariant {
            catalogue_probe_id: None,
            request_index: 0,
            maximum_metadata_bytes: 0,
            service_family: None,
            eligibility: UdpVariantEligibility::AnyPort,
        };
        Self {
            ipv4: Box::new([variant]),
            ipv6: Box::new([variant]),
            strategy: UdpProbeStrategy::Exhaustive,
        }
    }

    #[must_use]
    pub fn variants_for(&self, address: IpAddress) -> &[UdpProbeVariant] {
        match address {
            IpAddress::V4(_) => &self.ipv4,
            IpAddress::V6(_) => &self.ipv6,
        }
    }

    #[must_use]
    pub fn maximum_metadata_bytes_for(&self, address: IpAddress) -> usize {
        self.variants_for(address)
            .iter()
            .map(|variant| usize::from(variant.maximum_metadata_bytes))
            .max()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn variant_count_for(&self, address: IpAddress, port: ProbePort) -> usize {
        self.variants_for(address)
            .iter()
            .filter(|variant| self.matches(address, port, variant))
            .count()
    }

    #[must_use]
    pub fn variant_at_for(
        &self,
        address: IpAddress,
        port: ProbePort,
        selected_index: usize,
    ) -> Option<UdpProbeVariant> {
        self.variants_for(address)
            .iter()
            .copied()
            .filter(|variant| self.matches(address, port, variant))
            .nth(selected_index)
    }

    #[must_use]
    pub fn maximum_metadata_bytes_for_port(&self, address: IpAddress, port: ProbePort) -> usize {
        self.variants_for(address)
            .iter()
            .filter(|variant| self.matches(address, port, variant))
            .map(|variant| usize::from(variant.maximum_metadata_bytes))
            .max()
            .unwrap_or(0)
    }

    #[must_use]
    pub fn requires_logical_programme(&self, address: IpAddress, port: ProbePort) -> bool {
        let mut count = 0_usize;
        let mut first_eligibility = None;
        for variant in self
            .variants_for(address)
            .iter()
            .filter(|variant| self.matches(address, port, variant))
        {
            count += 1;
            first_eligibility.get_or_insert(variant.eligibility);
        }
        count != 1 || first_eligibility != Some(UdpVariantEligibility::AnyPort)
    }

    fn matches(&self, address: IpAddress, port: ProbePort, variant: &UdpProbeVariant) -> bool {
        let has_mapped =
            self.variants_for(address)
                .iter()
                .any(|candidate| match candidate.eligibility {
                    UdpVariantEligibility::DestinationPort(value) => value == port,
                    UdpVariantEligibility::DestinationPortRange { start, end } => {
                        start.get() <= port.get() && port.get() <= end.get()
                    }
                    _ => false,
                });
        match variant.eligibility {
            UdpVariantEligibility::AnyPort | UdpVariantEligibility::AfterProgrammeFallback => true,
            UdpVariantEligibility::DestinationPort(value) => value == port,
            UdpVariantEligibility::DestinationPortRange { start, end } => {
                start.get() <= port.get() && port.get() <= end.get()
            }
            UdpVariantEligibility::UnmappedFallback => !has_mapped,
        }
    }
}

fn validate_family(variants: &[UdpProbeVariant]) -> Result<(), PlanError> {
    if variants.len() > MAX_UDP_PROBE_VARIANTS {
        return Err(PlanError::TooManyUdpVariants);
    }
    for (index, variant) in variants.iter().enumerate() {
        if usize::from(variant.maximum_metadata_bytes) > MAX_UDP_VARIANT_METADATA_BYTES {
            return Err(PlanError::InvalidUdpMetadataReservation);
        }
        if let UdpVariantEligibility::DestinationPortRange { start, end } = variant.eligibility
            && start.get() > end.get()
        {
            return Err(PlanError::InvalidUdpPortRange);
        }
        if let Some(id) = variant.catalogue_probe_id {
            for prior in variants[..index]
                .iter()
                .filter(|prior| prior.catalogue_probe_id == Some(id))
            {
                if eligibility_overlaps(prior.eligibility, variant.eligibility) {
                    return Err(PlanError::DuplicateUdpVariant);
                }
            }
        }
    }
    Ok(())
}

fn eligibility_overlaps(left: UdpVariantEligibility, right: UdpVariantEligibility) -> bool {
    fn range(value: UdpVariantEligibility) -> Option<(u16, u16)> {
        match value {
            UdpVariantEligibility::DestinationPort(port) => Some((port.get(), port.get())),
            UdpVariantEligibility::DestinationPortRange { start, end } => {
                Some((start.get(), end.get()))
            }
            _ => None,
        }
    }
    match (range(left), range(right)) {
        (Some((left_start, left_end)), Some((right_start, right_end))) => {
            left_start <= right_end && right_start <= left_end
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodenet_protocols::Ipv4Address;

    #[test]
    fn destination_selection_is_lazy_and_fallbacks_are_exact() {
        let dns = UdpProbeVariant::new(ProbeVariantId::new(1), 0, 100)
            .unwrap()
            .with_eligibility(UdpVariantEligibility::DestinationPort(
                ProbePort::new(53).unwrap(),
            ));
        let unmapped = UdpProbeVariant::new(None, 1, 0)
            .unwrap()
            .with_eligibility(UdpVariantEligibility::UnmappedFallback);
        let after = UdpProbeVariant::new(None, 2, 0)
            .unwrap()
            .with_eligibility(UdpVariantEligibility::AfterProgrammeFallback);
        let programme = UdpProbeProgramme::new(vec![dns, unmapped, after], Vec::new()).unwrap();
        let address = IpAddress::V4(Ipv4Address::new([192, 0, 2, 1]));
        assert_eq!(
            programme.variant_count_for(address, ProbePort::new(53).unwrap()),
            2
        );
        assert_eq!(
            programme.variant_at_for(address, ProbePort::new(53).unwrap(), 0),
            Some(dns)
        );
        assert_eq!(
            programme.maximum_metadata_bytes_for_port(address, ProbePort::new(53).unwrap()),
            100
        );
        assert_eq!(
            programme.variant_at_for(address, ProbePort::new(9999).unwrap(), 0),
            Some(unmapped)
        );
        assert_eq!(
            programme.variant_at_for(address, ProbePort::new(9999).unwrap(), 1),
            Some(after)
        );
    }

    #[test]
    fn checked_ranges_are_lazy_and_duplicate_ids_must_be_disjoint() {
        let ranged = UdpProbeVariant::new(ProbeVariantId::new(26), 0, 100)
            .unwrap()
            .with_eligibility(UdpVariantEligibility::DestinationPortRange {
                start: ProbePort::new(19_132).unwrap(),
                end: ProbePort::new(19_133).unwrap(),
            });
        let programme = UdpProbeProgramme::new(vec![ranged], Vec::new()).unwrap();
        let address = IpAddress::V4(Ipv4Address::new([192, 0, 2, 1]));
        assert_eq!(
            programme.variant_count_for(address, ProbePort::new(19_132).unwrap()),
            1
        );
        assert_eq!(
            programme.variant_count_for(address, ProbePort::new(19_134).unwrap()),
            0
        );

        let overlap = ranged.with_eligibility(UdpVariantEligibility::DestinationPort(
            ProbePort::new(19_133).unwrap(),
        ));
        assert_eq!(
            UdpProbeProgramme::new(vec![ranged, overlap], Vec::new()),
            Err(PlanError::DuplicateUdpVariant)
        );
    }
}
