//! Behavioral tests for `#[derive(ProtoBridge)]`. Uses stand-in stub types
//! that mirror the prost-generated shape (enum as `i32`-convertible repr).

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use modkit_contract::ProtoBridge;

mod stubs {
    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct ChargeRequest {
        pub amount_cents: i64,
        pub currency: String,
        pub description: String,
    }

    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct ChargeResponse {
        pub payment_id: String,
        pub status: i32,
    }

    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct ListFilter {
        pub status: Option<i32>,
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    #[repr(i32)]
    pub enum PaymentStatus {
        #[default]
        Pending = 0,
        Completed = 1,
        Failed = 2,
    }

    impl TryFrom<i32> for PaymentStatus {
        type Error = ();
        fn try_from(v: i32) -> Result<Self, ()> {
            match v {
                0 => Ok(Self::Pending),
                1 => Ok(Self::Completed),
                2 => Ok(Self::Failed),
                _ => Err(()),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, ProtoBridge)]
#[proto_bridge(stub = "crate::stubs::ChargeRequest")]
pub struct ChargeRequest {
    pub amount_cents: i64,
    pub currency: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, ProtoBridge)]
#[proto_bridge(stub = "crate::stubs::ChargeResponse")]
pub struct ChargeResponse {
    #[proto_bridge(via_string)]
    pub payment_id: i64,
    pub status: PaymentStatus,
}

#[derive(Debug, Clone, PartialEq, Default, ProtoBridge)]
#[proto_bridge(stub = "crate::stubs::ListFilter")]
pub struct ListFilter {
    pub status: Option<PaymentStatus>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ProtoBridge)]
#[proto_bridge(stub = "crate::stubs::PaymentStatus")]
pub enum PaymentStatus {
    #[default]
    Pending,
    Completed,
    Failed,
}

#[test]
fn struct_round_trip_direct_fields() {
    let dto = ChargeRequest {
        amount_cents: 1_500,
        currency: "USD".into(),
        description: "demo".into(),
    };
    let proto: stubs::ChargeRequest = dto.clone().into();
    assert_eq!(proto.amount_cents, 1_500);
    assert_eq!(proto.currency, "USD");
    assert_eq!(proto.description, "demo");
    let back: ChargeRequest = proto.into();
    assert_eq!(back, dto);
}

#[test]
fn struct_via_string_field_round_trip() {
    let dto = ChargeResponse {
        payment_id: 42,
        status: PaymentStatus::Completed,
    };
    let proto: stubs::ChargeResponse = dto.clone().into();
    assert_eq!(proto.payment_id, "42");
    assert_eq!(proto.status, 1); // Completed → 1
    let back: ChargeResponse = proto.into();
    assert_eq!(back, dto);
}

#[test]
fn struct_via_string_unparseable_falls_back_to_default() {
    let proto = stubs::ChargeResponse {
        payment_id: "not-a-number".into(),
        status: 99,
    };
    let back: ChargeResponse = proto.into();
    assert_eq!(back.payment_id, 0); // i64::default()
    assert_eq!(back.status, PaymentStatus::Pending); // unknown i32 → default
}

#[test]
fn enum_round_trip_through_proto() {
    for s in [
        PaymentStatus::Pending,
        PaymentStatus::Completed,
        PaymentStatus::Failed,
    ] {
        let proto: stubs::PaymentStatus = s.into();
        let back: PaymentStatus = proto.into();
        assert_eq!(back, s);
    }
}

#[test]
fn enum_round_trip_through_i32() {
    let s = PaymentStatus::Failed;
    let i: i32 = s.into();
    assert_eq!(i, 2);
    let back: PaymentStatus = i.into();
    assert_eq!(back, s);
}

#[test]
fn enum_unknown_i32_falls_back_to_default() {
    let back: PaymentStatus = 999i32.into();
    assert_eq!(back, PaymentStatus::Pending); // #[default] variant
}

#[test]
fn option_field_with_enum_round_trips() {
    let dto = ListFilter {
        status: Some(PaymentStatus::Completed),
        note: Some("hello".into()),
    };
    let proto: stubs::ListFilter = dto.clone().into();
    assert_eq!(proto.status, Some(1));
    assert_eq!(proto.note.as_deref(), Some("hello"));
    let back: ListFilter = proto.into();
    assert_eq!(back, dto);
}

// --- Generics + skip ------------------------------------------------------
//
// Verifies that `#[derive(ProtoBridge)]` propagates generic parameters from
// the input type to the emitted impls and that `#[proto_bridge(skip)]`
// excludes a field from the wire shape.

mod stubs_generic {
    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct GenericReq {
        pub amount_cents: i64,
    }
}

/// `Tag` is a phantom-only marker — it never crosses the wire. The derive
/// must propagate `<T>` to all four impl blocks AND skip `_phantom`.
#[derive(Debug, Clone, PartialEq, ProtoBridge)]
#[proto_bridge(stub = "crate::stubs_generic::GenericReq")]
pub struct GenericReq<T> {
    pub amount_cents: i64,
    #[proto_bridge(skip)]
    pub _phantom: std::marker::PhantomData<T>,
}

#[derive(Clone)]
pub struct TagA;
#[derive(Clone)]
pub struct TagB;

#[test]
fn generic_struct_round_trips_with_phantom_skip() {
    let dto: GenericReq<TagA> = GenericReq {
        amount_cents: 42,
        _phantom: std::marker::PhantomData,
    };
    let proto: stubs_generic::GenericReq = dto.clone().into();
    assert_eq!(proto.amount_cents, 42);
    let back: GenericReq<TagA> = proto.into();
    assert_eq!(back.amount_cents, 42);
    // Different tag, same proto, same numeric content — the phantom is gone.
    let back_b: GenericReq<TagB> = stubs_generic::GenericReq { amount_cents: 7 }.into();
    assert_eq!(back_b.amount_cents, 7);
}

#[test]
fn option_field_none_round_trips() {
    let dto = ListFilter {
        status: None,
        note: None,
    };
    let proto: stubs::ListFilter = dto.clone().into();
    assert_eq!(proto.status, None);
    assert_eq!(proto.note, None);
    let back: ListFilter = proto.into();
    assert_eq!(back, dto);
}
