use prettytable::{row, Cell, Row, Table};
use serde::Serialize;
use serde_json::{Map, Value};

const MAX_COLUMN_WIDTH: usize = 80;

pub fn display_request_parameters(params: &[(impl AsRef<str>, impl AsRef<str>)]) {
    let mut table = Table::new();
    table.add_row(row!["Parameter", "Value"]);
    for (key, value) in params {
        table.add_row(Row::new(vec![
            Cell::new(key.as_ref()),
            Cell::new(value.as_ref()),
        ]));
    }
    table.printstd();
}

pub fn display_json_result<T: Serialize>(value: &T) {
    let json_value = serde_json::to_value(value).expect("Failed to serialize data");
    match json_value {
        Value::Object(map) => display_nested_structure(&map, 0),
        _ => println!("Data is not a JSON object."),
    }
}

fn display_nested_structure(map: &Map<String, Value>, indent: usize) {
    let mut table = Table::new();
    for (key, value) in map {
        let formatted_key = format!("{}{}", " ".repeat(indent), key);
        let formatted_value = format_value(value);
        for (i, line) in formatted_value.lines().enumerate() {
            if i == 0 {
                table.add_row(Row::new(vec![
                    Cell::new(&formatted_key),
                    Cell::new(&truncate_line(line)),
                ]));
            } else {
                table.add_row(Row::new(vec![
                    Cell::new(""),
                    Cell::new(&truncate_line(line)),
                ]));
            }
        }
    }
    table.printstd();
}

fn format_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(num) => num.to_string(),
        Value::Array(arr) => format!(
            "[{}]",
            arr.iter().map(format_value).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(_) => "{...}".to_string(),
        _ => format!("{}", value),
    }
}

fn truncate_line(line: &str) -> String {
    if line.len() > MAX_COLUMN_WIDTH {
        format!("{}...", &line[..MAX_COLUMN_WIDTH])
    } else {
        line.to_string()
    }
}
