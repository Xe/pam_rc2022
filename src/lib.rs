use curl::easy::{Easy, Form, List};
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

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum PamItemType {
    PAM_SERVICE = 1,
    PAM_USER = 2,
    PAM_TTY = 3,
    PAM_RHOST = 4,
    PAM_CONV = 5,
    PAM_AUTHTOK = 6,
    PAM_OLDAUTHTOK = 7,
    PAM_RUSER = 8,
    PAM_USER_PROMPT = 9,
    PAM_FAIL_DELAY = 10,
    PAM_XDISPLAY = 11,
    PAM_XAUTHDATA = 12,
    PAM_AUTHTOK_TYPE = 13,
}

fn get_item(pamh: PamHandle, item_type: PamItemType) -> PamResult<*const c_void> {
    let mut raw_item: *const c_void = ptr::null();
    let r = unsafe { sys::pam_get_item(pamh, item_type, &mut raw_item) };
    if raw_item.is_null() {
        Err(r)
    } else {
        Ok(raw_item)
    }
}

/// Gets the username that is currently authenticating out of the pam handle.
///
/// # Safety
///
/// This casts the string directly from C space into Rust space. It relies on
/// PAM doing things properly. Invalid UTF-8 will be pruned from the result.
pub fn get_user(pamh: PamHandle) -> PamResult<String> {
    get_item(pamh, PamItemType::PAM_USER).map(|u| unsafe {
        CStr::from_ptr(u as *const i8)
            .to_string_lossy()
            .into_owned()
    })
}

/// Gets the remote host out of the pam handle.
///
/// # Safety
///
/// This casts the string directly from C space into Rust space. It relies on
/// PAM doing things properly. Invalid UTF-8 will be pruned from the result.
pub fn get_rhost(pamh: PamHandle) -> PamResult<String> {
    let result = get_item(pamh, PamItemType::PAM_RHOST).map(|u| unsafe {
        CStr::from_ptr(u as *const i8)
            .to_string_lossy()
            .into_owned()
    })?;

    if result == "".to_string() {
        return Ok("<unknown>".into());
    }

    Ok(result)
}

pub fn discord_webhook(pamh: PamHandle, message: String) -> PamResult<()> {
    let mut easy = Easy::new();
    easy.url("https://discord.com/api/webhooks/994254905231560786/pCchaukdvQVRo1PoGguBM9H0NXA18iiHU-gh_qSYxPkxMUcdb_fppyy6ip0DETrpAFQK").map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;
    easy.http_headers({
        let mut list = List::new();
        list.append("User-Agent: pam_rc2022").unwrap();
        list
    })
    .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;
    easy.httppost({
        let mut form = Form::new();
        form.part("content")
            .contents(message.as_bytes())
            .add()
            .unwrap();
        form
    })
    .map_err(|_| PamResultCode::PAM_SYSTEM_ERR)?;
    easy.perform().map_err(|_| PamResultCode::PAM_IGNORE)?;
    let response_code = easy.response_code().map_err(|why| {
        let _ = info(pamh, format!("can't perform discord webhook: {}", why));
        PamResultCode::PAM_SYSTEM_ERR
    })?;
    if response_code.div_euclid(100) != 2 {
        info(
            pamh,
            format!(
                "can't send message to discord: got status code {}",
                response_code
            ),
        )?;
        return Err(PamResultCode::PAM_IGNORE);
    }
    Ok(())
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
        pub fn pam_get_item(
            pamh: PamHandle,
            item_type: PamItemType,
            item: *mut *const c_void,
        ) -> PamResultCode;
    }
}

pub fn login_message(pamh: PamHandle) -> PamResult<()> {
    discord_webhook(
        pamh,
        format!("{} logging in from {}", get_user(pamh)?, get_rhost(pamh)?),
    )?;

    Ok(())
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
        _: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
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
        pamh: PamHandle,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        match login_message(pamh) {
            Ok(_) => PamResultCode::PAM_IGNORE,
            Err(why) => why,
        }
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
