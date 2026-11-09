//! Process status contract shared by the S2 implementation streams.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Usage(String),
    Unavailable(String),
    ResumePrecondition(String),
    Io(std::io::Error),
    NotImplemented(&'static str),
}

impl Error {
    pub const fn exit_status(&self) -> ExitStatus {
        match self {
            Self::Usage(_) => ExitStatus::Usage,
            Self::Unavailable(_) => ExitStatus::Unavailable,
            Self::ResumePrecondition(_) => ExitStatus::ResumePrecondition,
            Self::Io(_) | Self::NotImplemented(_) => ExitStatus::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitStatus {
    Success,
    Internal,
    Usage,
    Unavailable,
    ResumePrecondition,
    Signal(u8),
}

impl ExitStatus {
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Internal => 1,
            Self::Usage => 2,
            Self::Unavailable => 3,
            Self::ResumePrecondition => 4,
            Self::Signal(signal) => 128 + signal,
        }
    }
}
