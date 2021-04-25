use usiem::events::field::{SiemField};
use usiem::events::{SiemLog, SiemEvent};
use usiem::components::common::LogParsingError;
use usiem::events::auth::{AuthEvent, AuthLoginType, LoginOutcome, RemoteLogin};
use super::super::get_string_field;
use super::super::event_types::domain_user_from_arn;
use std::borrow::Cow;

pub fn aws_console_sign_in(log_value : &serde_json::Value, mut log : SiemLog) -> Result<SiemLog, LogParsingError> {
    let event_name = match log_value.get("eventName") {
        Some(val) => val.as_str().unwrap_or(""),
        None => return Err(LogParsingError::NoValidParser(log))
    };
    if event_name == "ConsoleLogin" {
        log.set_service(Cow::Borrowed("ConsoleLogin"));
        match log_value.get("additionalEventData") {
            Some(additional) => match get_string_field(additional, "MFAUsed") {
                Some(val) => {log.add_field("user.mfa",val);},
                None => {}
            },
            None => {}
        };
        let (domain, user) = match log_value.get("userIdentity") {
            Some(v) => {
                match v.get("arn") {
                    Some(v) => match v.as_str() {
                        Some(arn) => {
                            log.add_field("user.id", SiemField::from_str(arn.to_string()));
                            match domain_user_from_arn(arn) {
                                Ok((domain, user)) => (domain,user),
                                Err(_) => return Err(LogParsingError::ParserError(log))
                            }
                        },
                        None => return Err(LogParsingError::ParserError(log))
                    },
                    None => {
                        let username = v.get("userName").map(|v2| v2.as_str().unwrap_or("_NO_USER_")).unwrap_or("_NO_USER_");
                        let account_id = v.get("accountId").map(|v2| v2.as_str().unwrap_or("_NO_ACCOUNT_")).unwrap_or("_NO_ACCOUNT_");
                        let account_type = v.get("type").map(|v2| v2.as_str().unwrap_or("_NO_TYPE_")).unwrap_or("_NO_TYPE_");
                        log.add_field("user.id", SiemField::from_str(format!("{}:{}/{}",account_type,account_id,username)));
                        (format!("{}:{}",account_type, account_id),String::from(username))
                    }
                }
            },
            None => return Err(LogParsingError::NoValidParser(log))
        };
        
        match log_value.get("responseElements") {
            Some(additional) => match additional.get("ConsoleLogin") {
                Some(val) => {
                    match val.as_str() {
                        Some(val) => {
                            let hostname = log_value.get("eventSource").map(|v| v.as_str().map(|v2| Cow::Owned(v2.to_string())).unwrap_or(Cow::Borrowed("signin.amazonaws.com"))).unwrap_or(Cow::Borrowed("signin.amazonaws.com"));
                            
                            let source_address = match log_value.get("sourceIPAddress").map(|v| v.as_str()) {
                                Some(v) => match v {
                                    Some(v) =>v,
                                    None => return Err(LogParsingError::ParserError(log))
                                },
                                None => return Err(LogParsingError::ParserError(log))
                            };
                            match val {
                                "Failure" => {
                                    log.set_event(SiemEvent::Auth(AuthEvent{
                                        hostname,
                                        outcome : LoginOutcome::FAIL,
                                        login_type : AuthLoginType::Remote(RemoteLogin {
                                            domain : Cow::Owned(domain),
                                            source_address : Cow::Owned(source_address.to_string()),
                                            user_name : Cow::Owned(user)
                                        })
                                    }));
                                },
                                "Success" => {
                                    log.set_event(SiemEvent::Auth(AuthEvent{
                                        hostname,
                                        outcome : LoginOutcome::SUCCESS,
                                        login_type : AuthLoginType::Remote(RemoteLogin {
                                            domain : Cow::Owned(domain),
                                            source_address : Cow::Owned(source_address.to_string()),
                                            user_name : Cow::Owned(user)
                                        })
                                    }));
                                },
                                _ => {return Err(LogParsingError::ParserError(log))}
                            }
                        },
                        None => {return Err(LogParsingError::ParserError(log))}
                    }
                },
                None => {return Err(LogParsingError::ParserError(log))}
            },
            None => {return Err(LogParsingError::ParserError(log))}
        };
    }
    Ok(log)
}



#[cfg(test)]
mod aws_tests {
    use super::super::super::parse_general_log;
    use usiem::events::auth::LoginOutcome;
    use usiem::events::field::{SiemField, SiemIp};
    use usiem::events::{SiemEvent, SiemLog};

    #[test]
    fn test_login_success() {
        let log_val = serde_json::json!({
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true",
                "MobileVersion": "No",
                "MFAUsed": "No"
            },
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            "eventID": "97ae0290-6b12-42c1-b091-72d486bbd7f3",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDA7ZI0RCYCPBIR0OIC3",
                "arn": "arn:aws:iam::811596193553:user/piper",
                "accountId": "811596193553",
                "userName": "piper"
            },
            "eventType": "AwsConsoleSignIn",
            "sourceIPAddress": "255.253.125.115",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "recipientAccountId": "811596193553",
            "requestParameters": null,
            "awsRegion": "us-east-1",
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "eventVersion": "1.05",
            "eventTime": "2017-05-16T23:05:01Z"
        });
        let mut log = SiemLog::new(String::new(), 0, SiemIp::V4(1));
        log.set_event(SiemEvent::Json(log_val));
        match parse_general_log(log) {
            Ok(log) => {
                assert_eq!(
                    log.field("user.mfa"),
                    Some(&SiemField::from_str("No"))
                );
                assert_eq!(
                    log.field("user.id"),
                    Some(&SiemField::from_str("arn:aws:iam::811596193553:user/piper"))
                );
                assert_eq!(
                    log.field("user.name"),
                    Some(&SiemField::User("piper".to_string()))
                );
                assert_eq!(
                    log.field("user.domain"),
                    Some(&SiemField::Domain(
                        "arn:aws:iam::811596193553:user".to_string()
                    ))
                );
                assert_eq!(
                    log.field("host.hostname"),
                    Some(&SiemField::from_str("signin.amazonaws.com".to_string()))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(
                        SiemIp::from_ip_str("255.253.125.115").unwrap()
                    ))
                );
                assert_eq!(
                    log.field("event.outcome"),
                    Some(&SiemField::from_str(LoginOutcome::SUCCESS.to_string()))
                );
                assert_eq!(
                    log.field("cloud.region"),
                    Some(&SiemField::from_str("us-east-1"))
                );
                assert_eq!(
                    log.field("cloud.account.id"),
                    Some(&SiemField::from_str("811596193553"))
                );
                assert_eq!(
                    log.field("cloud.provider"),
                    Some(&SiemField::from_str("AWS"))
                );
                assert_eq!(
                    log.field("event.id"),
                    Some(&SiemField::from_str("97ae0290-6b12-42c1-b091-72d486bbd7f3"))
                );
                assert_eq!(log.field("user_agent.original"),Some(&SiemField::from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")));
            }
            Err(_) => {
                assert_eq!("Log must be parsed", "Parsing error");
            }
        }
    }
    #[test]
    fn test_login_failed() {
        let log_val = serde_json::json!({
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/iam/home?region=us-west-2&state=hashArgs%23&isauthcode=true",
                "MobileVersion": "No",
                "MFAUsed": "No"
            },
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            "eventID": "dfa44a56-a58e-4e49-84fd-9128ee48ce8c",
            "errorMessage": "No username found in supplied account",
            "userIdentity": {
                "type": "IAMUser",
                "accountId": "811596193553",
                "accessKeyId": "",
                "userName": "HIDDEN_DUE_TO_SECURITY_REASONS"
            },
            "eventType": "AwsConsoleSignIn",
            "sourceIPAddress": "8.120.255.102",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "recipientAccountId": "811596193553",
            "requestParameters": null,
            "awsRegion": "us-east-1",
            "responseElements": {
                "ConsoleLogin": "Failure"
            },
            "eventVersion": "1.05",
            "eventTime": "2017-05-17T23:23:34Z"
        });
        let mut log = SiemLog::new(String::new(), 0, SiemIp::V4(1));
        log.set_event(SiemEvent::Json(log_val));
        match parse_general_log(log) {
            Ok(log) => {
                assert_eq!(
                    log.field("user.mfa"),
                    Some(&SiemField::from_str("No"))
                );
                assert_eq!(
                    log.field("user.id"),
                    Some(&SiemField::User("IAMUser:811596193553/HIDDEN_DUE_TO_SECURITY_REASONS".to_string()))
                );
                assert_eq!(
                    log.field("user.name"),
                    Some(&SiemField::User("HIDDEN_DUE_TO_SECURITY_REASONS".to_string()))
                );
                assert_eq!(
                    log.field("user.domain"),
                    Some(&SiemField::Domain(
                        "IAMUser:811596193553".to_string()
                    ))
                );
                assert_eq!(
                    log.field("host.hostname"),
                    Some(&SiemField::from_str("signin.amazonaws.com".to_string()))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(
                        SiemIp::from_ip_str("8.120.255.102").unwrap()
                    ))
                );
                assert_eq!(
                    log.field("event.outcome"),
                    Some(&SiemField::from_str(LoginOutcome::FAIL.to_string()))
                );
                assert_eq!(
                    log.field("cloud.region"),
                    Some(&SiemField::from_str("us-east-1"))
                );
                assert_eq!(
                    log.field("cloud.account.id"),
                    Some(&SiemField::from_str("811596193553"))
                );
                assert_eq!(
                    log.field("cloud.provider"),
                    Some(&SiemField::from_str("AWS"))
                );
                assert_eq!(
                    log.field("event.id"),
                    Some(&SiemField::from_str("dfa44a56-a58e-4e49-84fd-9128ee48ce8c"))
                );
                assert_eq!(log.field("user_agent.original"),Some(&SiemField::from_str("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")));
            }
            Err(_) => {
                assert_eq!("Log must be parsed", "Parsing error");
            }
        }
    }
    #[test]
    fn test_login_success_root() {
        let log_val = serde_json::json!({
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/iam/home?region=us-west-2&state=hashArgs%23%2Froles%2Fflaws&isauthcode=true",
                "MobileVersion": "No",
                "MFAUsed": "Yes"
            },
            "userAgent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",
            "eventID": "c5472feb-40d2-41c6-9c47-fb15aad0f326",
            "userIdentity": {
                "type": "Root",
                "principalId": "811596193553",
                "arn": "arn:aws:iam::811596193553:root",
                "accountId": "811596193553"
            },
            "eventType": "AwsConsoleSignIn",
            "sourceIPAddress": "255.253.125.115",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "recipientAccountId": "811596193553",
            "requestParameters": null,
            "awsRegion": "us-east-1",
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "eventVersion": "1.05",
            "eventTime": "2017-02-18T19:20:48Z"
        });
        let mut log = SiemLog::new(String::new(), 0, SiemIp::V4(1));
        log.set_event(SiemEvent::Json(log_val));
        match parse_general_log(log) {
            Ok(log) => {
                assert_eq!(
                    log.field("user.mfa"),
                    Some(&SiemField::from_str("Yes"))
                );
                assert_eq!(
                    log.field("user.id"),
                    Some(&SiemField::from_str("arn:aws:iam::811596193553:root"))
                );
                assert_eq!(
                    log.field("user.name"),
                    Some(&SiemField::User("root".to_string()))
                );
                assert_eq!(
                    log.field("user.domain"),
                    Some(&SiemField::Domain(
                        "arn:aws:iam::811596193553:root".to_string()
                    ))
                );
                assert_eq!(
                    log.field("host.hostname"),
                    Some(&SiemField::from_str("signin.amazonaws.com".to_string()))
                );
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(
                        SiemIp::from_ip_str("255.253.125.115").unwrap()
                    ))
                );
                assert_eq!(
                    log.field("event.outcome"),
                    Some(&SiemField::from_str(LoginOutcome::SUCCESS.to_string()))
                );
                assert_eq!(
                    log.field("cloud.region"),
                    Some(&SiemField::from_str("us-east-1"))
                );
                assert_eq!(
                    log.field("cloud.account.id"),
                    Some(&SiemField::from_str("811596193553"))
                );
                assert_eq!(
                    log.field("cloud.provider"),
                    Some(&SiemField::from_str("AWS"))
                );
                assert_eq!(
                    log.field("event.id"),
                    Some(&SiemField::from_str("c5472feb-40d2-41c6-9c47-fb15aad0f326"))
                );
                assert_eq!(log.field("user_agent.original"),Some(&SiemField::from_str("Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36")));
            }
            Err(_) => {
                assert_eq!("Log must be parsed", "Parsing error");
            }
        }
    }
}
