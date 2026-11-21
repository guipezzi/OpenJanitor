//! OpenJanitor's safety kernel (PLANNING.md §4 and §9).
//!
//! Every destructive file operation in the project goes through this crate,
//! and CI fails if any other crate deletes or moves files. The pieces:
//!
//! - [`path`]: lexical path normalization that rejects anything ambiguous.
//! - [`deny`]: the hard deny list. No rule file can override it.
//! - [`attrs`]: classification of reparse points and cloud placeholders.
//! - [`walk`]: a traversal that never enters reparse points.
//! - [`exec`]: revalidation and the actual delete, with dry-run mode.

#![forbid(unsafe_code)]

pub mod attrs;
pub mod deny;
pub mod exec;
pub mod path;
pub mod snapshot;
pub mod system;
pub mod walk;

pub use attrs::EntryClass;
pub use deny::{DenyList, DenyReason};
pub use exec::{Executor, Mode, Outcome, SkipReason};
pub use path::{NormPath, PathError};
pub use snapshot::FileSnapshot;
pub use system::{DiscoverError, SystemPaths};
pub use walk::{WalkStats, walk_files};
