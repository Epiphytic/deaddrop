#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("snapshot exceeds 16777216 bytes")]
    SnapshotTooLarge,
    #[error("unsupported snapshot version {0}")]
    SnapshotVersion(u16),
    #[error("nested transactions are not supported")]
    NestedTransaction,
    #[error("storage serialization failed")]
    Serialization,
    #[error("marmot operation failed")]
    Marmot,
}
