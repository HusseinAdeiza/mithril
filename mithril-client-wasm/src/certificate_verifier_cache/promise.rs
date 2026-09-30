use js_sys::{Function, Promise};
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{IdbRequest, IdbTransaction};

/// A JS promise settled from DOM events, so that an IndexedDB outcome can be awaited.
///
/// IndexedDB reports outcomes through events (`success` and `error` on a request, `complete`
/// and `abort` on a transaction) rather than promises. The resolve and reject functions of the
/// promise are called from event handlers, which are Rust closures exported to JS: such a
/// closure must outlive its event, as the browser throws when it invokes a dropped one, so the
/// handlers are owned next to the future and released once the promise has settled.
pub(super) struct EventPromise {
    /// The promise awaited on the Rust side
    future: JsFuture,
    /// The event handlers settling the promise, released once it is settled
    _callbacks: Vec<Closure<dyn FnMut()>>,
}

impl EventPromise {
    /// Create the promise, the given function receives its resolve and reject functions, attaches
    /// the event handlers built from them to their target and returns the handlers
    fn new(mut register: impl FnMut(Function, Function) -> Vec<Closure<dyn FnMut()>>) -> Self {
        let mut callbacks = Vec::new();
        let promise = Promise::new(&mut |resolve, reject| callbacks = register(resolve, reject));

        Self {
            future: JsFuture::from(promise),
            _callbacks: callbacks,
        }
    }

    /// An event handler settling the promise through the given resolve or reject function with
    /// the value computed when the event fires, settling an already settled promise is a no-op
    fn callback(settle: Function, value: impl Fn() -> JsValue + 'static) -> Closure<dyn FnMut()> {
        Closure::wrap(Box::new(move || {
            let _ = settle.call1(&JsValue::NULL, &value());
        }))
    }

    /// Wait for the promise to be settled, `Ok` with the resolved value or `Err` with the
    /// rejection value, then release the event handlers
    pub(super) async fn settled(self) -> Result<JsValue, JsValue> {
        self.future.await
    }
}

/// Extension to await an IndexedDB request through its `success` and `error` events
pub(super) trait IdbRequestExt {
    /// Wait for the request to succeed with its result or to fail with its error
    async fn settled(&self) -> Result<JsValue, JsValue>;
}

impl IdbRequestExt for IdbRequest {
    async fn settled(&self) -> Result<JsValue, JsValue> {
        EventPromise::new(|resolve, reject| {
            let succeeded = self.clone();
            let on_success = EventPromise::callback(resolve, move || {
                succeeded.result().unwrap_or(JsValue::UNDEFINED)
            });
            let failed = self.clone();
            let on_error = EventPromise::callback(reject, move || match failed.error() {
                Ok(Some(exception)) => exception.into(),
                _ => JsValue::UNDEFINED,
            });
            self.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
            self.set_onerror(Some(on_error.as_ref().unchecked_ref()));

            vec![on_success, on_error]
        })
        .settled()
        .await
    }
}

/// Extension to await an IndexedDB transaction through its `complete` and `abort` events
pub(super) trait IdbTransactionExt {
    /// Watch the transaction, the promise resolves when it completes and rejects with its error
    /// when it aborts, which follows any failed request
    fn completion(&self) -> EventPromise;
}

impl IdbTransactionExt for IdbTransaction {
    fn completion(&self) -> EventPromise {
        EventPromise::new(|resolve, reject| {
            let on_complete = EventPromise::callback(resolve, || JsValue::UNDEFINED);
            let aborted = self.clone();
            let on_abort = EventPromise::callback(reject, move || {
                aborted
                    .error()
                    .map_or_else(|| JsValue::from_str("Transaction aborted"), JsValue::from)
            });
            self.set_oncomplete(Some(on_complete.as_ref().unchecked_ref()));
            self.set_onabort(Some(on_abort.as_ref().unchecked_ref()));

            vec![on_complete, on_abort]
        })
    }
}
