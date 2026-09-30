use std::fmt;

use anyhow::anyhow;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::DomException;

use mithril_client::MithrilResult;

/// A JS error value, displayed by its name and message when it is a DOM exception
struct JsError(JsValue);

impl fmt::Display for JsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.dyn_ref::<DomException>() {
            Some(exception) => write!(formatter, "{}: {}", exception.name(), exception.message()),
            None => write!(formatter, "{:?}", self.0),
        }
    }
}

/// Extension adding a context to a JS error
pub(super) trait JsErrorContext<T> {
    /// Convert a JS error into a Mithril error with the given context
    fn js_context<C: fmt::Display>(self, context: C) -> MithrilResult<T>;
}

impl<T> JsErrorContext<T> for Result<T, JsValue> {
    fn js_context<C: fmt::Display>(self, context: C) -> MithrilResult<T> {
        self.map_err(|error| anyhow!("{context}: {}", JsError(error)))
    }
}
