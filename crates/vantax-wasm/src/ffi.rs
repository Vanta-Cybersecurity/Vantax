//! The WebAssembly exports: allocate, free, call. This is the only place
//! with `unsafe`, and it only moves bytes across the boundary.
//!
//! ```text
//! in   = vantax_alloc(len)            ; JS copies the UTF-8 request into it
//! lenp = vantax_alloc(4)
//! out  = vantax_call(in, len, lenp)   ; JS reads u32 LE at lenp, then the response
//! vantax_free(in, len); vantax_free(out, *lenp); vantax_free(lenp, 4)
//! ```
//!
//! Every buffer is a boxed byte slice of exactly the length handed out, so
//! freeing with the same length is always sound.

#![allow(unsafe_code)]

use std::ptr;

fn leak(bytes: Box<[u8]>) -> *mut u8 {
    Box::into_raw(bytes) as *mut u8
}

/// Allocate `len` zeroed bytes for the caller.
#[no_mangle]
pub extern "C" fn vantax_alloc(len: usize) -> *mut u8 {
    leak(vec![0u8; len].into_boxed_slice())
}

/// Free a buffer from [`vantax_alloc`] or [`vantax_call`].
///
/// # Safety
///
/// `ptr` and `len` must be exactly a pointer and length this module handed
/// out, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn vantax_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        // SAFETY: per the contract, (ptr, len) is a leaked Box<[u8]>.
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)) });
    }
}

/// Handle the JSON request in `(input, len)`. Writes the response length as a
/// little-endian `u32` at `out_len` and returns the response buffer.
///
/// # Safety
///
/// `input` must point to `len` readable bytes and `out_len` to 4 writable
/// bytes, both from [`vantax_alloc`].
#[no_mangle]
pub unsafe extern "C" fn vantax_call(input: *const u8, len: usize, out_len: *mut u8) -> *mut u8 {
    // SAFETY: per the contract, input is valid for len bytes.
    let request = unsafe { std::slice::from_raw_parts(input, len) };
    let response = match std::str::from_utf8(request) {
        Ok(s) => crate::api::call(s),
        Err(_) => r#"{"ok":false,"error":"request is not UTF-8"}"#.to_string(),
    };
    let bytes = response.into_bytes().into_boxed_slice();
    let n = u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes();
    // SAFETY: per the contract, out_len is valid for 4 bytes.
    unsafe { ptr::copy_nonoverlapping(n.as_ptr(), out_len, 4) };
    leak(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_the_exports() {
        let req = br#"{"op":"hash","text":"abc"}"#;
        let input = vantax_alloc(req.len());
        let lenp = vantax_alloc(4);
        unsafe {
            ptr::copy_nonoverlapping(req.as_ptr(), input, req.len());
            let out = vantax_call(input, req.len(), lenp);
            let n = u32::from_le_bytes(std::slice::from_raw_parts(lenp, 4).try_into().unwrap())
                as usize;
            let text = std::str::from_utf8(std::slice::from_raw_parts(out, n))
                .unwrap()
                .to_string();
            vantax_free(out, n);
            vantax_free(input, req.len());
            vantax_free(lenp, 4);
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(v["ok"], true);
            assert_eq!(v["result"]["digest"].as_str().unwrap().len(), 128);
        }
        let empty = vantax_alloc(0);
        unsafe { vantax_free(empty, 0) };
    }
}
