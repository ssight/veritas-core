use neon::prelude::*;
use shared::{PkInfo, SigInfo};

macro_rules! make_obj {
    (@ctx $ctx: expr ; $($name: literal => $value: tt as $type: tt;)*) => {{
        let obj = $ctx.empty_object();

        #[allow(unused_parens)]
        {
            $({
                let ptr = $ctx.$type($value);
                obj.prop($ctx, $name).set(ptr)?;
            })*
        }

        Ok(obj)
    }};
}

pub trait ToObject {
    fn to_object<'a>(&self, ctx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject>;
}

impl ToObject for PkInfo {
    fn to_object<'a>(&self, ctx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        make_obj! {
            @ctx ctx;
            "key_id" => (&self.id) as string;
            "authority" => (&self.authority) as string;
            "device_model" => (&self.device_model) as string;
            "issued" => (self.issued as f64) as number;
        }
    }
}

impl ToObject for SigInfo {
    fn to_object<'a>(&self, ctx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        make_obj! {
            @ctx ctx;
            "cert_id" => (&self.cert_id) as string;
        }
    }
}
