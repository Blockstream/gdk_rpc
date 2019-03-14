use failure::Context;
use core::fmt::Display;

#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "json rpc error")]
    JsonRpc,
    #[fail(display = "core rpc error")]
    CoreRpc,
    #[fail(display = "mnemonic error")]
    Mnemonic,
}

pub trait OptionExt<T> {
    fn or_err<D>(self, context: D) -> Result<T, Context<D>>
    where
        D: Display + Send + Sync + 'static;

    fn req(self) -> Result<T, Context<&'static str>>;
}

 impl<T> OptionExt<T> for Option<T> {
    fn or_err<D>(self, context: D) -> Result<T, Context<D>>
    where
        D: Display + Send + Sync + 'static,
    {
        self.ok_or_else(|| Context::new(context))
    }

    fn req(self) -> Result<T, Context<&'static str>>
    {
        self.ok_or_else(|| Context::new("missing required option"))
    }
}
