#[derive(Debug)]
pub enum NixErr {
    Exception(String),
    Receiver(tokio::sync::oneshot::error::RecvError),
}

impl std::fmt::Display for NixErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NixErr::Receiver(e) => write!(f, "{}", e),
            NixErr::Exception(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for NixErr {}

impl From<cxx::Exception> for NixErr {
    fn from(err: cxx::Exception) -> Self {
        NixErr::Exception(err.what().to_owned())
    }
}
