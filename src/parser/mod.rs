use chrono::prelude::{DateTime};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::field::{SiemField, SiemIp};
use usiem::events::{SiemLog, SiemEvent};
use usiem::events::auth::{AuthEvent,AuthLoginType, LoginOutcome, RemoteLogin};
use std::collections::BTreeMap;
mod event_types;
mod awstypes;
use event_types::aws_event_type;

pub fn parse_general_log(mut log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_value = match log.event() {
        SiemEvent::Unknown => {
            let log_message = log.message();
            if log_message.len() > 0 && &log_message[0..1] == "{" {
                let val : serde_json::Value = match serde_json::from_str(log_message) {
                    Ok(val) => val,
                    Err(_) => return Err(LogParsingError::NoValidParser(log))
                };
                val
            }else{
                return Err(LogParsingError::NoValidParser(log))
            }
        },
        // Improve this
        SiemEvent::Json(val) => val.clone(),
        _ => return Err(LogParsingError::NoValidParser(log))
    };
    let timestamp = match log_value.get("eventTime") {
        Some(val) => {
            match val.as_str() {
                Some(val) => {
                    match DateTime::parse_from_rfc3339(val) {
                        Ok(timestamp) => timestamp.timestamp_millis(),
                        Err(_err) => return Err(LogParsingError::NoValidParser(log)),
                    }
                },
                None => return Err(LogParsingError::NoValidParser(log))
            }
        },
        None => return Err(LogParsingError::NoValidParser(log))
    };    
    log.set_event_created(timestamp);
    log.set_service(Cow::Borrowed("AWS"));
    log.set_product(Cow::Borrowed("AWS"));
    log.set_category(Cow::Borrowed("Cloud"));
    log.add_field("cloud.provider", SiemField::Text(Cow::Borrowed("AWS")));
    return aws_event_type(log_value, log);
}

fn get_string_field(log_value: &serde_json::Value, name: &str) -> Option<SiemField> {
    match log_value.get(name) {
        Some(val) => match val.as_str() {
            Some(val) => Some(SiemField::from_str(val.to_string())),
            None => None,
        },
        None => None,
    }
}

