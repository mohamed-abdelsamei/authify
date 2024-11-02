use std::any::Any;
use std::fmt::Debug;

use serde::Serialize;
use serde_json::{Map, Value};

pub fn print_object<T: Serialize>(value: &T) {
    let type_name = std::any::type_name::<T>();
    println!("------------------------------");
    println!("Object of type: {}", type_name);
    println!("------------------------------");
    let json_value = serde_json::to_value(value).expect("Failed to serialize data");
    match json_value {
        Value::Object(map) => print_nested_structure(map, 0),
        _ => println!("Data is not a JSON object."),
    }
    println!("------------------------------");
}

fn print_nested_structure(map: Map<String, Value>, indent: usize) {
    for (key, value) in map {
        println!(
            "{:indent$}{:<15} {}",
            "",
            key.trim(),
            format_value(&value),
            indent = indent
        );
    }
}

/// Helper function to format values by removing `Some(...)` wrappers and displaying strings directly
fn format_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(num) => num.to_string(),
        Value::Array(_) | Value::Object(_) => format!("{:?}", value),
        _ => format!("{}", value),
    }
}
