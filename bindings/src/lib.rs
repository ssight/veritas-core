mod impls;
mod service;

use impls::ToObject;
use neon::prelude::*;
use service::ServiceProxy;
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

    let key_info = handle_err!(ctx => runtime.block_on(proxy.keyread(&keypath)));
    Ok(key_info.to_object(ctx)?)
}

#[neon::export]
fn siginfo<'a>(ctx: &mut FunctionContext<'a>, path: String) -> JsResult<'a, JsObject> {
    let proxy = handle_static!(ctx => service());
    let runtime = handle_static!(ctx => runtime());

    let sig_info = handle_err!(ctx => runtime.block_on(proxy.siginfo(&path)));
    Ok(sig_info.to_object(ctx)?)
}

#[neon::export]
fn sign<'a>(
    ctx: &mut FunctionContext<'a>,
    imgpath: String,
    key_id: String,
    newpath: String,
) -> JsResult<'a, JsUndefined> {
    let proxy = handle_static!(ctx => service());
    let runtime = handle_static!(ctx => runtime());

    handle_err!(ctx => runtime.block_on(proxy.sign(&imgpath, &key_id, &newpath)));
    Ok(ctx.undefined())
}

#[neon::export]
fn verify<'a>(
    ctx: &mut FunctionContext<'a>,
    imgpath: String,
    keypath: String,
) -> JsResult<'a, JsBoolean> {
    let proxy = handle_static!(ctx => service());
    let runtime = handle_static!(ctx => runtime());

    handle_err!(ctx => runtime.block_on(proxy.verify(&imgpath, &keypath)));
    Ok(ctx.boolean(true))
}
