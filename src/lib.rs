use std::ffi::{CStr, CString};
use std::{
    os::raw::{c_char, c_int, c_uint, c_void},
    ptr,
};

pub type PamHandle = *const c_uint;
pub type PamFlags = c_uint;
pub type PamResult<T> = Result<T, PamResultCode>;

pub const PAM_SILENT: PamFlags = 0x8000;

/// All of the PAM result codes that can be returned by modules. See [man 3 pam](https://linux.die.net/man/3/pam)
/// for more information about what these result codes mean.
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum PamResultCode {
    PAM_SUCCESS = 0,
    PAM_OPEN_ERR = 1,
    PAM_SYMBOL_ERR = 2,
    PAM_SERVICE_ERR = 3,
    PAM_SYSTEM_ERR = 4,
    PAM_BUF_ERR = 5,
    PAM_PERM_DENIED = 6,
    PAM_AUTH_ERR = 7,
    PAM_CRED_INSUFFICIENT = 8,
    PAM_AUTHINFO_UNAVAIL = 9,
    PAM_USER_UNKNOWN = 10,
    PAM_MAXTRIES = 11,
    PAM_NEW_AUTHTOK_REQD = 12,
    PAM_ACCT_EXPIRED = 13,
    PAM_SESSION_ERR = 14,
    PAM_CRED_UNAVAIL = 15,
    PAM_CRED_EXPIRED = 16,
    PAM_CRED_ERR = 17,
    PAM_NO_MODULE_DATA = 18,
    PAM_CONV_ERR = 19,
    PAM_AUTHTOK_ERR = 20,
    PAM_AUTHTOK_RECOVERY_ERR = 21,
    PAM_AUTHTOK_LOCK_BUSY = 22,
    PAM_AUTHTOK_DISABLE_AGING = 23,
    PAM_TRY_AGAIN = 24,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
    PAM_AUTHTOK_EXPIRED = 27,
    PAM_MODULE_UNKNOWN = 28,
    PAM_BAD_ITEM = 29,
    PAM_CONV_AGAIN = 30,
    PAM_INCOMPLETE = 31,
}

/// PAM message styles.
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum MessageStyle {
    PAM_PROMPT_ECHO_OFF = 1,
    PAM_PROMPT_ECHO_ON = 2,
    PAM_ERROR_MSG = 3,
    PAM_TEXT_INFO = 4,
}

/// Sends a message to the user when doing a PAM conversation.
///
/// This function assumes the input string has no null bytes in it.
/// Using a string with a null byte in it will return Err(PamResultCode::PAM_BUF_ERR).
pub fn info(pamh: PamHandle, msg: String) -> PamResult<()> {
    let msg = CString::new(msg).map_err(|_| PamResultCode::PAM_BUF_ERR)?;
    let result_code = unsafe {
        sys::pam_prompt(
            pamh,
            MessageStyle::PAM_TEXT_INFO,
            ptr::null::<*mut c_char>(),
            msg.as_ptr(),
        )
    };

    match result_code {
        PamResultCode::PAM_SUCCESS => Ok(()),
        _ => Err(result_code),
    }
}

pub mod sys {
    use super::*;

    #[link(name = "pam")]
    extern "C" {
        pub fn pam_prompt(
            pamh: PamHandle,
            msg_type: MessageStyle,
            response: *const *mut c_char,
            fmt: *const c_char,
            ...
        ) -> PamResultCode;
    }
}

mod callbacks {
    use super::*;

    #[no_mangle]
    pub extern "C" fn pam_sm_acct_mgmt(
        _: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_authenticate(
        pamh: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        match info(pamh, "hello, world".into()) {
            Ok(_) => PamResultCode::PAM_IGNORE,
            Err(why) => why,
        }
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_chauthtok(
        _: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_close_session(
        _: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_open_session(
        _: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_setcred(
        _: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}
