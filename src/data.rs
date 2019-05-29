use serde_json as j;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Message {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub body: j::Value,
    pub raw: j::Value,
}

impl Message {
    pub fn new() -> Self {
        Self {
            from: "".to_string(),
            to: "".to_string(),
            ty: "message".to_string(),
            body: json!({}),
            raw: json!({}),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Timeout {
    pub to: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub body: j::Value,
    pub raw: j::Value,
    #[serde(rename = "unique-id")]
    pub unique_id: j::Value,
}

impl Timeout {
    pub fn new() -> Self {
        Self {
            to: "".to_string(),
            ty: "timeout".to_string(),
            body: json!({}),
            raw: json!({}),
            unique_id: json!({}),
        }
    }

    pub fn clear(id: j::Value) -> Self {
        let mut t = Self::new();
        t.unique_id = id;
        t
    }
}

#[derive(Deserialize, Debug)]
#[serde(tag = "msgtype")]
pub enum Request {
    #[serde(rename = "start")]
    Start { to: String },
    #[serde(rename = "msg")]
    Message(Message),
    #[serde(rename = "timeout")]
    Timeout(Timeout),
    #[serde(rename = "quit")]
    Quit {},
}

#[derive(Serialize, Debug, Default)]
pub struct Response {
    #[serde(rename = "send-messages")]
    pub messages: Vec<Message>,
    #[serde(rename = "set-timeouts")]
    pub timeouts: Vec<Timeout>,
    #[serde(rename = "cleared-timeouts")]
    pub cleared_timeouts: Vec<Timeout>,
    pub states: j::Value,
}

impl Response {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            timeouts: Vec::new(),
            cleared_timeouts: Vec::new(),
            states: json!({}),
        }
    }
}
