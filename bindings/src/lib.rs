mod impls;
mod service;

use impls::ToObject;
use neon::prelude::*;
use service::ServiceProxy;
use shared::{GenericError, PkInfo};
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use zbus::Connection;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static CONN: OnceLock<ServiceProxy> = OnceLock::new();

macro_rules! handle_err {
    ($ctx: expr => $fallible: expr) => {
        match $fallible {
            Ok(data) => data,
            Err(err) => return Err($ctx.throw_error(err.to_string())?),
        }
    };
}

macro_rules! handle_static {
    ($ctx: expr => $fallible: expr) => {
        match $fallible {
            Some(data) => data,
            None => return Err($ctx.throw_error("No valid data in static call.")?),
        }
    };
}

#[neon::main]
fn main<'a>(mut ctx: ModuleContext) -> NeonResult<()> {
    neon::registered().export(&mut ctx)?;

    let runtime = handle_err!(ctx => Runtime::new());

    let conn = handle_err!(ctx => {
        runtime.block_on(async move {
            let conn = Connection::session().await?;
            let proxy = ServiceProxy::new(&conn).await?;
            anyhow::Ok(proxy)
        })
    });

    match (RUNTIME.set(runtime), CONN.set(conn)) {
        (Ok(()), Ok(())) => Ok(()),
        _ => Err(ctx.throw_error("Failed to initialise runtime.")?),
    }
}

fn runtime() -> Option<&'static Runtime> {
    RUNTIME.get()
}

fn service<'a>() -> Option<&'static ServiceProxy<'a>> {
    CONN.get()
}

#[neon::export]
fn keyread<'a>(ctx: &mut FunctionContext<'a>, keypath: String) -> JsResult<'a, JsObject> {
    let proxy = handle_static!(ctx => service());
    let runtime = handle_static!(ctx => runtime());

    let key_info = match runtime.block_on(proxy.keyread(&keypath)) {
        Ok(service) => service,
        Err(err) => return Err(ctx.throw_error(err.to_string())?),
    };

    Ok(key_info.to_object(ctx)?)
}
