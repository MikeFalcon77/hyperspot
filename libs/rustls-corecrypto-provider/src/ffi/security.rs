//! FFI bindings to Security.framework for operations not exposed by the
//! `security-framework` 3.7 safe API.
//!
//! Currently this is just `SecKeyCreateWithData`, needed to import a peer's
//! public key from raw bytes received over the wire (TLS handshake gives us
//! EC uncompressed-point bytes or PKCS#1 RSAPublicKey DER, not a SecKey).

#![allow(non_upper_case_globals, non_snake_case)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::dictionary::CFDictionaryRef;
use security_framework::key::SecKey;
use security_framework_sys::base::SecKeyRef;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// Imports a key from external data. The returned `SecKeyRef` follows
    /// the Create Rule (owned, must be released by the receiver).
    fn SecKeyCreateWithData(
        keyData: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;

    // Attribute key constants used as CFDictionary keys.
    pub static kSecAttrKeyType: CFStringRef;
    pub static kSecAttrKeyClass: CFStringRef;
    pub static kSecAttrKeySizeInBits: CFStringRef;

    // KeyType values.
    pub static kSecAttrKeyTypeRSA: CFStringRef;
    pub static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;

    // KeyClass values.
    pub static kSecAttrKeyClassPublic: CFStringRef;
    pub static kSecAttrKeyClassPrivate: CFStringRef;
}

/// Curve / algorithm hint for `import_public_key`.
#[derive(Copy, Clone, Debug)]
pub enum PublicKeyKind {
    /// Uncompressed NIST P-256 point: 0x04 || X(32) || Y(32) = 65 bytes.
    EcSecPrimeRandomP256,
    /// Uncompressed NIST P-384 point: 0x04 || X(48) || Y(48) = 97 bytes.
    EcSecPrimeRandomP384,
    /// PKCS#1 RSAPublicKey DER (SEQUENCE { modulus, publicExponent }).
    RsaPkcs1,
}

/// Error returned when public-key import fails.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("SecKeyCreateWithData returned null without an error")]
    NullKey,
    #[error("SecKeyCreateWithData failed: {0}")]
    CoreFoundation(String),
}

/// Wrap an attribute key (`extern static CFStringRef`) into a safe CFString
/// borrow without consuming retain count. The static lives forever, so
/// `wrap_under_get_rule` is the correct retain pattern.
fn wrap_static_str(s: CFStringRef) -> CFString {
    // SAFETY: `s` is a non-null framework-managed static `CFStringRef`.
    unsafe { TCFType::wrap_under_get_rule(s) }
}

/// Import a raw public-key blob into a [`SecKey`].
///
/// On success the returned key is FIPS-ready (the same module Apple ships)
/// and can be passed to `SecKey::key_exchange` / `verify_signature`.
pub fn import_public_key(bytes: &[u8], kind: PublicKeyKind) -> Result<SecKey, ImportError> {
    let (type_static, size_bits) = match kind {
        PublicKeyKind::EcSecPrimeRandomP256 => {
            // SAFETY: extern statics are framework-managed, non-null.
            (unsafe { kSecAttrKeyTypeECSECPrimeRandom }, 256i64)
        }
        PublicKeyKind::EcSecPrimeRandomP384 => (unsafe { kSecAttrKeyTypeECSECPrimeRandom }, 384i64),
        PublicKeyKind::RsaPkcs1 => {
            // RSA size is encoded in the modulus length; we still set the
            // attribute as a documentation hint (Security.framework infers
            // it from the data).
            (unsafe { kSecAttrKeyTypeRSA }, 0i64)
        }
    };

    let key_type_key = wrap_static_str(unsafe { kSecAttrKeyType });
    let key_class_key = wrap_static_str(unsafe { kSecAttrKeyClass });
    let key_size_key = wrap_static_str(unsafe { kSecAttrKeySizeInBits });
    let key_type_val = wrap_static_str(type_static);
    let key_class_val = wrap_static_str(unsafe { kSecAttrKeyClassPublic });

    let mut pairs: Vec<(CFString, CFType)> = vec![
        (key_type_key, key_type_val.as_CFType()),
        (key_class_key, key_class_val.as_CFType()),
    ];
    if size_bits > 0 {
        pairs.push((key_size_key, CFNumber::from(size_bits).as_CFType()));
    }

    let attrs = CFDictionary::from_CFType_pairs(&pairs);
    let data = CFData::from_buffer(bytes);
    let mut error_ref: CFErrorRef = std::ptr::null_mut();

    // SAFETY: `data` and `attrs` are valid CF objects; we pass `error_ref` as
    // a mutable out-pointer. Whatever is returned is per the Create Rule.
    let key_ref = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attrs.as_concrete_TypeRef(),
            &mut error_ref,
        )
    };

    if key_ref.is_null() {
        if !error_ref.is_null() {
            // SAFETY: error_ref points to a CFErrorRef owned by us (the
            // function fills it on failure per Apple convention).
            let err = unsafe { CFError::wrap_under_create_rule(error_ref) };
            return Err(ImportError::CoreFoundation(format!("{err:?}")));
        }
        return Err(ImportError::NullKey);
    }

    // SAFETY: SecKeyCreateWithData transfers ownership; SecKey wraps under
    // the Create Rule and will release on drop.
    Ok(unsafe { SecKey::wrap_under_create_rule(key_ref) })
}
