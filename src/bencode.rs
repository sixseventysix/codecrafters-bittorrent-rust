use serde_json;
use serde_bencode;

pub fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    let decoded: serde_bencode::value::Value = serde_bencode::from_str(encoded_value).unwrap();

    match decoded {
        serde_bencode::value::Value::Bytes(b) => {
            serde_json::Value::String(String::from_utf8(b).unwrap())
        }
        serde_bencode::value::Value::Int(i) => {
            serde_json::Value::Number(i.into())
        }
        serde_bencode::value::Value::List(list) => {
            let json_list: Vec<serde_json::Value> = list
                .into_iter()
                .map(|v| bencode_to_json(v))
                .collect();
            serde_json::Value::Array(json_list)
        }
        serde_bencode::value::Value::Dict(dict) => {
            let json_map: serde_json::Map<String, serde_json::Value> = dict
                .into_iter()
                .map(|(k, v)| (String::from_utf8(k).unwrap(), bencode_to_json(v)))
                .collect();
            serde_json::Value::Object(json_map)
        }
    }
}

fn bencode_to_json(value: serde_bencode::value::Value) -> serde_json::Value {
    match value {
        serde_bencode::value::Value::Bytes(b) => {
            serde_json::Value::String(String::from_utf8(b).unwrap())
        }
        serde_bencode::value::Value::Int(i) => {
            serde_json::Value::Number(i.into())
        }
        serde_bencode::value::Value::List(list) => {
            let json_list: Vec<serde_json::Value> = list
                .into_iter()
                .map(|v| bencode_to_json(v))
                .collect();
            serde_json::Value::Array(json_list)
        }
        serde_bencode::value::Value::Dict(dict) => {
            let json_map: serde_json::Map<String, serde_json::Value> = dict
                .into_iter()
                .map(|(k, v)| (String::from_utf8(k).unwrap(), bencode_to_json(v)))
                .collect();
            serde_json::Value::Object(json_map)
        }
    }
}
