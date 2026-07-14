//! Safe EFI link policy over the private raw LLD COFF boundary.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

use wrela_target::{ObjectFormat, Target};

/// One materialized COFF object supplied to LLD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoffObject<'a> {
    /// Object path in the private build directory.
    pub path: &'a Path,
}

/// Complete safe request for final image linking.
#[derive(Debug)]
pub struct LinkRequest<'a> {
    /// Input objects in deterministic order.
    pub objects: &'a [CoffObject<'a>],
    /// Validated target policy that owns all LLD flags.
    pub target: &'a Target,
    /// Final `.efi` path.
    pub output: &'a Path,
}

/// Successfully emitted UEFI application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiArtifact {
    /// Final PE/COFF image path.
    pub path: PathBuf,
}

/// Invalid target policy or raw LLD failure.
#[derive(Debug)]
pub enum LinkError {
    /// EFI revision 0.1 accepts COFF objects only.
    UnsupportedObjectFormat,
    /// Raw private driver failure.
    Lld(wrela_lld_sys::LldError),
}

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedObjectFormat => {
                formatter.write_str("the EFI linker requires COFF object input")
            }
            Self::Lld(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LinkError {}

/// Link materialized COFF objects into a UEFI PE/COFF application.
pub fn link(request: &LinkRequest<'_>) -> Result<EfiArtifact, LinkError> {
    if request.target.object_format != ObjectFormat::Coff {
        return Err(LinkError::UnsupportedObjectFormat);
    }

    let mut arguments = vec![
        format!("/subsystem:{}", request.target.subsystem),
        format!("/entry:{}", request.target.entry_symbol),
        "/nodefaultlib".to_owned(),
        format!("/out:{}", request.output.display()),
    ];
    arguments.extend(
        request
            .objects
            .iter()
            .map(|object| object.path.display().to_string()),
    );
    wrela_lld_sys::link_coff(&arguments).map_err(LinkError::Lld)?;

    Ok(EfiArtifact {
        path: request.output.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use wrela_target::Target;

    use super::{CoffObject, LinkError, LinkRequest, link};

    #[test]
    fn linker_contract_runs_from_coff_fixtures_without_codegen() {
        let objects = [CoffObject {
            path: Path::new("fixture.obj"),
        }];
        let target = Target::x86_64_uefi();
        let request = LinkRequest {
            objects: &objects,
            target: &target,
            output: Path::new("fixture.efi"),
        };

        assert!(matches!(link(&request), Err(LinkError::Lld(_))));
    }
}
