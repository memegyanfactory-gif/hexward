//! The EICAR test file: a harmless string every antivirus agrees to detect.
//!
//! The string is never written out in one piece, in this source file or in the
//! compiled binary, so other antivirus products don't flag Hexward itself.

use crate::detect::{Detection, Severity, Source};

/// Builds the 68-byte EICAR string at runtime.
pub fn eicar_bytes() -> Vec<u8> {
    format!(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}}${}-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        ["EI", "CAR"].concat()
    )
    .into_bytes()
}

/// Per the EICAR spec: the file starts with the string, may be followed only by
/// whitespace, and is at most 128 bytes long.
pub fn is_eicar(data: &[u8], eicar: &[u8]) -> bool {
    data.len() <= 128
        && data.starts_with(eicar)
        && data[eicar.len()..].iter().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x1A))
}

pub fn detection() -> Detection {
    Detection::new(
        "Test/Any.EICAR!a",
        Severity::High,
        Source::Eicar,
        "The EICAR test file. It is harmless and only used to check that antivirus works.",
    )
}
