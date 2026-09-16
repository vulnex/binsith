use crate::string_analysis::StringFinding;
use serde::Serialize;

/// Counts affected findings, not individual omitted matches. Covers both inputs
/// when comparing; intentionally selected ranges/categories are reported as scope.
#[derive(Default, Serialize)]
pub struct Coverage {
    pub truncated_strings: usize,
    pub strings_with_omitted_details: usize,
    pub decoded_layers_with_omitted_details: usize,
    pub decode_limited_strings: usize,
    pub comparison_limited: bool,
}
impl Coverage {
    pub fn observe(&mut self, finding: &StringFinding) {
        self.truncated_strings += usize::from(finding.truncated);
        self.strings_with_omitted_details += usize::from(finding.match_details_truncated);
        self.decoded_layers_with_omitted_details += finding
            .decoded_layers
            .iter()
            .filter(|l| l.match_details_truncated)
            .count();
        self.decode_limited_strings += usize::from(
            finding.decode_status == "limit"
                || finding
                    .decoded_layers
                    .iter()
                    .any(|l| matches!(l.next_decode, "byte_limit" | "depth_limit")),
        );
    }
    pub fn limited(&self) -> bool {
        self.truncated_strings
            + self.strings_with_omitted_details
            + self.decoded_layers_with_omitted_details
            + self.decode_limited_strings
            > 0
            || self.comparison_limited
    }
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({"status": if self.limited() {"limited"} else {"complete_within_configured_scope"}, "limitations":self,
            "scope_note":"Static heuristic analysis only; absence of indicators is not proof of safety. Counts include both comparison inputs and all enabled extraction passes."})
    }
}
