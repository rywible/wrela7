//! Lower semantically closed images into the backend-independent WIR model.

#![forbid(unsafe_code)]

use wrela_sema::AnalyzedImage;
use wrela_wir::Module;

/// Lower an analyzed image without running WIR transformations or codegen.
#[must_use]
pub fn lower(image: &AnalyzedImage) -> Module {
    Module {
        name: image.hir.image_name.clone(),
        target: image.target.clone(),
        functions: Vec::new(),
    }
}
