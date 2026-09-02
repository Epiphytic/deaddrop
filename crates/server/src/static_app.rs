pub(crate) struct StaticAsset {
    pub(crate) bytes: &'static [u8],
    pub(crate) content_type: &'static str,
}

const INDEX: &[u8] = include_bytes!("../../../apps/web/index.html");
const APP: &[u8] = include_bytes!("../../../apps/web/app.js");
const STYLES: &[u8] = include_bytes!("../../../apps/web/styles.css");

pub(crate) fn get(path: &str) -> Option<StaticAsset> {
    let (bytes, content_type): (&'static [u8], &'static str) = match path {
        "/" => (INDEX, "text/html; charset=utf-8"),
        "/app.js" => (APP, "text/javascript; charset=utf-8"),
        "/styles.css" => (STYLES, "text/css; charset=utf-8"),
        _ => return None,
    };
    Some(StaticAsset {
        bytes,
        content_type,
    })
}
