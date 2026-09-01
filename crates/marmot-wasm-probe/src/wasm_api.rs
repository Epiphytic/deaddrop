use wasm_bindgen::prelude::*;

use crate::{MarmotProbe, error::ProbeError};

#[wasm_bindgen(js_name = MarmotProbe)]
pub struct WasmMarmotProbe {
    inner: MarmotProbe,
}

#[wasm_bindgen(js_class = MarmotProbe)]
impl WasmMarmotProbe {
    pub fn create(secret_key_hex: &str) -> Result<WasmMarmotProbe, JsValue> {
        Ok(Self {
            inner: MarmotProbe::create(secret_key_hex).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = fromState)]
    pub fn from_state(state: &[u8]) -> Result<WasmMarmotProbe, JsValue> {
        Ok(Self {
            inner: MarmotProbe::from_state(state).map_err(js_error)?,
        })
    }

    #[wasm_bindgen(js_name = createKeyPackage)]
    pub async fn create_key_package(
        &mut self,
        relay_url: &str,
        now_seconds: u64,
    ) -> Result<String, JsValue> {
        self.inner
            .create_key_package(relay_url, now_seconds)
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = createConversation)]
    pub async fn create_conversation(
        &mut self,
        key_package_event_json: &str,
        group_h_hex: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .create_conversation(key_package_event_json, group_h_hex)
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = joinWelcome)]
    pub async fn join_welcome(&mut self, gift_wrap_json: &str) -> Result<String, JsValue> {
        self.inner
            .join_welcome(gift_wrap_json)
            .await
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = sendChat)]
    pub async fn send_chat(
        &mut self,
        group_id_hex: &str,
        content: &str,
        created_at: u64,
    ) -> Result<String, JsValue> {
        self.inner
            .send_chat(group_id_hex, content, created_at)
            .await
            .map_err(js_error)
    }

    pub async fn ingest(&mut self, event_json: &str) -> Result<String, JsValue> {
        self.inner.ingest(event_json).await.map_err(js_error)
    }

    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_state().map_err(js_error)
    }
}

fn js_error(error: ProbeError) -> JsValue {
    JsValue::from_str(&error.to_string())
}
