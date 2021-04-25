use super::awstypes::console::aws_console_sign_in;
use super::get_string_field;
use std::collections::BTreeMap;
use usiem::components::common::LogParsingError;
use usiem::events::field::SiemField;
use usiem::events::SiemLog;

pub fn aws_event_type(
    log_value: serde_json::Value,
    mut log: SiemLog,
) -> Result<SiemLog, LogParsingError> {
    let event_type = match log_value.get("eventType") {
        Some(val) => val.as_str().unwrap_or(""),
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let fields = extract_fields(&log_value);
    for (key, field) in fields.into_iter() {
        log.add_field(key, field);
    }
    match event_type {
        "" => return Err(LogParsingError::NoValidParser(log)),
        "AwsConsoleSignIn" => {
            return aws_console_sign_in(&log_value, log);
        }
        _ => {}
    };
    Ok(log)
}

fn extract_fields(log_value: &serde_json::Value) -> BTreeMap<&'static str, SiemField> {
    // See https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html
    let mut fields_added = BTreeMap::new();
    match log_value.get("userIdentity") {
        Some(additional) => {
            match additional.get("arn") {
                Some(val) => match val.as_str() {
                    Some(arn) => {
                        match domain_user_from_arn(arn) {
                            Ok((domain, user)) => {
                                fields_added.insert("user.name", SiemField::User(user));
                                fields_added.insert("user.domain", SiemField::Domain(domain));
                                fields_added
                                    .insert("user.id", SiemField::from_str(arn.to_string()));
                            }
                            Err(_) => {}
                        };
                    }
                    None => {}
                },
                None => {}
            };
        }
        None => {}
    };
    match get_string_field(&log_value, "userAgent") {
        Some(val) => {
            fields_added.insert("user_agent.original", val);
        }
        None => {}
    };
    match get_string_field(&log_value, "eventID") {
        Some(val) => {
            fields_added.insert("event.id", val);
        }
        None => {}
    };
    match get_string_field(&log_value, "recipientAccountId") {
        Some(val) => {
            fields_added.insert("cloud.account.id", val);
        }
        None => {}
    };
    match get_string_field(&log_value, "awsRegion") {
        Some(val) => {
            fields_added.insert("cloud.region", val);
        }
        None => {}
    };
    match get_string_field(&log_value, "errorMessage") {
        Some(val) => {
            fields_added.insert("error.message", val);
        }
        None => {}
    };
    fields_added
}

pub fn domain_user_from_arn(arn: &str) -> Result<(String, String), ()> {
    match arn.find("/") {
        Some(pos) => return Ok((arn[..pos].to_string(), arn[pos + 1..].to_string())),
        None => match arn.find("root") {
            Some(_) => return Ok((arn.to_string(), String::from("root"))),
            None => return Err(()),
        },
    }
}
