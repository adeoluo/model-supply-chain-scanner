//! Content sniffing and dispatch to the format analyzers.

use crate::compress;
use crate::finding::{ids, Finding};
use crate::numpy;
use crate::pickle;
use crate::scan::{self, Ctx};
use crate::zip;

/// Recognize a format from its magic bytes (pickles are recognized separately).
pub fn sniff(data: &[u8], _name: &str) -> Option<&'static str> {
    if zip::is_zip(data) {
        Some("zip")
    } else if numpy::is_npy(data) {
        Some("numpy")
    } else if compress::detect(data).is_some() {
        Some("compressed")
    } else {
        None
    }
}

/// Detect the format of `data` and run the matching analyzer.
pub(crate) fn dispatch(ctx: &mut Ctx, data: &[u8], member: &str, depth: u8) -> String {
    match sniff(data, member) {
        Some("zip") => return scan::scan_zip(ctx, data, member, depth),
        Some("numpy") => return scan::scan_npy(ctx, data, member),
        Some("compressed") => {
            let codec = compress::detect(data).expect("sniffed");
            return scan::scan_compressed(ctx, codec, data, member, depth);
        }
        _ => {}
    }
    if pickle::is_pickle(data) {
        return scan::scan_pickle(ctx, data, member);
    }
    ctx.findings
        .push(Finding::new(ids::FORMAT_UNKNOWN, "format not recognized", member));
    "unknown".into()
}
