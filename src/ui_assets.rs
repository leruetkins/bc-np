use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "dist-ui/"]
pub struct UiAssets;

impl UiAssets {
    pub fn list() -> Vec<String> {
        Self::iter().map(|s| s.to_string()).collect()
    }
}
