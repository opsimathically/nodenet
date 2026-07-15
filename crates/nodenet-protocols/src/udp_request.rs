use core::fmt;

/// Maximum size of one built-in UDP request template.
pub const MAX_UDP_REQUEST_BYTES: usize = 4_096;
/// Maximum number of independently checked dynamic fields in one UDP request.
pub const MAX_UDP_REQUEST_PATCHES: usize = 8;

/// Stable dynamic values understood by the UDP request-plan boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpRequestPatchValue<'a> {
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(&'a [u8]),
}

/// The required encoding and checked span of one dynamic request field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UdpRequestPatchKind {
    U16BigEndian,
    U32BigEndian,
    U64BigEndian,
    Bytes { length: u16 },
}

impl UdpRequestPatchKind {
    const fn length(self) -> usize {
        match self {
            Self::U16BigEndian => 2,
            Self::U32BigEndian => 4,
            Self::U64BigEndian => 8,
            Self::Bytes { length } => length as usize,
        }
    }
}

/// One immutable dynamic field in a UDP request template.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpRequestPatchField {
    offset: u16,
    kind: UdpRequestPatchKind,
}

impl UdpRequestPatchField {
    #[must_use]
    pub const fn new(offset: u16, kind: UdpRequestPatchKind) -> Self {
        Self { offset, kind }
    }

    #[must_use]
    pub const fn offset(self) -> u16 {
        self.offset
    }

    #[must_use]
    pub const fn kind(self) -> UdpRequestPatchKind {
        self.kind
    }
}

/// One patch value addressed by its stable descriptor index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpRequestPatch<'a> {
    pub field_index: usize,
    pub value: UdpRequestPatchValue<'a>,
}

/// Validation or instantiation failure for a bounded UDP request plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpRequestPlanError {
    TemplateTooLarge { actual: usize },
    TooManyPatchFields { actual: usize },
    EmptyPatchField,
    PatchOutOfBounds,
    OverlappingPatchFields,
    UnknownPatchField { index: usize },
    DuplicatePatchField { index: usize },
    PatchValueMismatch { index: usize },
    BufferTooSmall { required: usize, actual: usize },
}

impl fmt::Display for UdpRequestPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid UDP request plan: {self:?}")
    }
}

impl std::error::Error for UdpRequestPlanError {}

/// Immutable exact request bytes plus independently checked dynamic fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpRequestPlan {
    bytes: Box<[u8]>,
    fields: Box<[UdpRequestPatchField]>,
}

impl UdpRequestPlan {
    /// Copies and validates a bounded request template.
    ///
    /// Validation completes before either caller-provided output or the plan is
    /// made observable. Dynamic field spans must be non-empty, in bounds, and
    /// non-overlapping.
    ///
    /// # Errors
    ///
    /// Returns a bounded template or patch-field validation error.
    pub fn new(bytes: &[u8], fields: &[UdpRequestPatchField]) -> Result<Self, UdpRequestPlanError> {
        if bytes.len() > MAX_UDP_REQUEST_BYTES {
            return Err(UdpRequestPlanError::TemplateTooLarge {
                actual: bytes.len(),
            });
        }
        if fields.len() > MAX_UDP_REQUEST_PATCHES {
            return Err(UdpRequestPlanError::TooManyPatchFields {
                actual: fields.len(),
            });
        }
        for (index, field) in fields.iter().copied().enumerate() {
            let length = field.kind.length();
            if length == 0 {
                return Err(UdpRequestPlanError::EmptyPatchField);
            }
            let start = usize::from(field.offset);
            let Some(end) = start.checked_add(length) else {
                return Err(UdpRequestPlanError::PatchOutOfBounds);
            };
            if end > bytes.len() {
                return Err(UdpRequestPlanError::PatchOutOfBounds);
            }
            for prior in fields.iter().copied().take(index) {
                let prior_start = usize::from(prior.offset);
                let prior_end = prior_start + prior.kind.length();
                if start < prior_end && prior_start < end {
                    return Err(UdpRequestPlanError::OverlappingPatchFields);
                }
            }
        }
        Ok(Self {
            bytes: bytes.to_vec().into_boxed_slice(),
            fields: fields.to_vec().into_boxed_slice(),
        })
    }

    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn template(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn fields(&self) -> &[UdpRequestPatchField] {
        &self.fields
    }

    /// Instantiates exact request bytes into caller-owned storage.
    ///
    /// Every patch and the output capacity is checked before `output` changes.
    ///
    /// # Errors
    ///
    /// Returns before mutation when the output or any patch is invalid.
    pub fn instantiate_into<'output>(
        &self,
        output: &'output mut [u8],
        patches: &[UdpRequestPatch<'_>],
    ) -> Result<&'output mut [u8], UdpRequestPlanError> {
        self.validate_patches(patches)?;
        if output.len() < self.bytes.len() {
            return Err(UdpRequestPlanError::BufferTooSmall {
                required: self.bytes.len(),
                actual: output.len(),
            });
        }
        let encoded = &mut output[..self.bytes.len()];
        encoded.copy_from_slice(&self.bytes);
        for patch in patches {
            let field = self.fields[patch.field_index];
            let start = usize::from(field.offset);
            let end = start + field.kind.length();
            match patch.value {
                UdpRequestPatchValue::U16(value) => {
                    encoded[start..end].copy_from_slice(&value.to_be_bytes());
                }
                UdpRequestPatchValue::U32(value) => {
                    encoded[start..end].copy_from_slice(&value.to_be_bytes());
                }
                UdpRequestPatchValue::U64(value) => {
                    encoded[start..end].copy_from_slice(&value.to_be_bytes());
                }
                UdpRequestPatchValue::Bytes(value) => {
                    encoded[start..end].copy_from_slice(value);
                }
            }
        }
        Ok(encoded)
    }

    fn validate_patches(&self, patches: &[UdpRequestPatch<'_>]) -> Result<(), UdpRequestPlanError> {
        if patches.len() > self.fields.len() {
            return Err(UdpRequestPlanError::TooManyPatchFields {
                actual: patches.len(),
            });
        }
        let mut seen = [false; MAX_UDP_REQUEST_PATCHES];
        for patch in patches {
            let Some(field) = self.fields.get(patch.field_index).copied() else {
                return Err(UdpRequestPlanError::UnknownPatchField {
                    index: patch.field_index,
                });
            };
            if seen[patch.field_index] {
                return Err(UdpRequestPlanError::DuplicatePatchField {
                    index: patch.field_index,
                });
            }
            seen[patch.field_index] = true;
            let matches = matches!(
                (field.kind, patch.value),
                (
                    UdpRequestPatchKind::U16BigEndian,
                    UdpRequestPatchValue::U16(_)
                ) | (
                    UdpRequestPatchKind::U32BigEndian,
                    UdpRequestPatchValue::U32(_)
                ) | (
                    UdpRequestPatchKind::U64BigEndian,
                    UdpRequestPatchValue::U64(_)
                )
            ) || matches!(
                (field.kind, patch.value),
                (
                    UdpRequestPatchKind::Bytes { length },
                    UdpRequestPatchValue::Bytes(value)
                ) if value.len() == usize::from(length)
            );
            if !matches {
                return Err(UdpRequestPlanError::PatchValueMismatch {
                    index: patch.field_index,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_plan_reports_length_and_patches_transactionally() {
        let plan = UdpRequestPlan::new(
            &[0xaa; 14],
            &[
                UdpRequestPatchField::new(2, UdpRequestPatchKind::U16BigEndian),
                UdpRequestPatchField::new(6, UdpRequestPatchKind::U64BigEndian),
            ],
        )
        .unwrap();
        let mut output = [0x55; 16];
        let encoded = plan
            .instantiate_into(
                &mut output,
                &[
                    UdpRequestPatch {
                        field_index: 0,
                        value: UdpRequestPatchValue::U16(0x1234),
                    },
                    UdpRequestPatch {
                        field_index: 1,
                        value: UdpRequestPatchValue::U64(0x0102_0304_0506_0708),
                    },
                ],
            )
            .unwrap();
        assert_eq!(plan.encoded_len(), 14);
        assert_eq!(&encoded[2..4], &[0x12, 0x34]);
        assert_eq!(&encoded[6..14], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(output[14..], [0x55; 2]);
    }

    #[test]
    fn malformed_fields_and_values_leave_output_untouched() {
        assert_eq!(
            UdpRequestPlan::new(
                &[0; 4],
                &[
                    UdpRequestPatchField::new(0, UdpRequestPatchKind::U32BigEndian),
                    UdpRequestPatchField::new(2, UdpRequestPatchKind::U16BigEndian),
                ],
            ),
            Err(UdpRequestPlanError::OverlappingPatchFields)
        );
        let plan = UdpRequestPlan::new(
            &[0; 4],
            &[UdpRequestPatchField::new(
                0,
                UdpRequestPatchKind::U32BigEndian,
            )],
        )
        .unwrap();
        let mut output = [0x77; 4];
        assert!(matches!(
            plan.instantiate_into(
                &mut output,
                &[UdpRequestPatch {
                    field_index: 0,
                    value: UdpRequestPatchValue::U16(1),
                }],
            ),
            Err(UdpRequestPlanError::PatchValueMismatch { index: 0 })
        ));
        assert_eq!(output, [0x77; 4]);
    }
}
