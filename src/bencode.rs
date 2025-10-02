use serde_json;
use serde_bencode;
use anyhow::{Result, Context};

pub fn decode_bencoded_value(encoded_value: &str) -> Result<serde_json::Value> {
    let decoded: serde_bencode::value::Value = serde_bencode::from_str(encoded_value)
        .context("Failed to decode bencoded value")?;

    bencode_to_json(decoded)
}

fn bencode_to_json(value: serde_bencode::value::Value) -> Result<serde_json::Value> {
    match value {
        serde_bencode::value::Value::Bytes(b) => {
            let s = String::from_utf8(b)
                .context("Invalid UTF-8 in bencoded string")?;
            Ok(serde_json::Value::String(s))
        }
        serde_bencode::value::Value::Int(i) => {
            Ok(serde_json::Value::Number(i.into()))
        }
        serde_bencode::value::Value::List(list) => {
            let json_list: Result<Vec<serde_json::Value>> = list
                .into_iter()
                .map(|v| bencode_to_json(v))
                .collect();
            Ok(serde_json::Value::Array(json_list?))
        }
        serde_bencode::value::Value::Dict(dict) => {
            let json_map: Result<serde_json::Map<String, serde_json::Value>> = dict
                .into_iter()
                .map(|(k, v)| {
                    let key = String::from_utf8(k)
                        .context("Invalid UTF-8 in dictionary key")?;
                    let value = bencode_to_json(v)?;
                    Ok((key, value))
                })
                .collect();
            Ok(serde_json::Value::Object(json_map?))
        }
    }
}
