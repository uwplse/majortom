use majortom::data;
use majortom::ptrace_handlers;
mod common;

#[macro_use]
extern crate serde_json;

#[test]
fn test_annotate() {
    let config = common::setup_example("annotate");
    let mut handlers = ptrace_handlers::Handlers::new(config.nodes);
    let mut response = data::Response::new();
    handlers
        .handle_start("pinger".to_string(), &mut response)
        .unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 0);
    assert_eq!(
        response.states,
        json!({"pinger": {"pings_sent": 0,
                                                  "test": "hello"}})
    );
    let timeout = response.timeouts.pop().unwrap();
    assert_eq!(timeout.ty, "Start");
    response = data::Response::new();
    handlers
        .handle_start("ponger".to_string(), &mut response)
        .unwrap();
    assert_eq!(response.timeouts.len(), 0);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 0);
    response = data::Response::new();
    handlers.handle_timeout(timeout, &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 1);
    assert_eq!(response.cleared_timeouts.len(), 1);
    assert_eq!(
        response.states,
        json!({"pinger": {"pings_sent": 1,
                                                  "test": "hello"}})
    );
    let timeout = response.timeouts.pop().unwrap();
    assert_eq!(timeout.ty, "Background thread");
    assert_eq!(timeout.body, json!({"seconds": 5}));
    let mut message = response.messages.pop().unwrap();
    assert_eq!(message.ty, "ping");
    for _ in 0..10 {
        // could do this forever!
        response = data::Response::new();
        handlers.handle_message(message, &mut response).unwrap();
        assert_eq!(response.timeouts.len(), 0);
        assert_eq!(response.messages.len(), 1);
        assert_eq!(response.cleared_timeouts.len(), 0);
        message = response.messages.pop().unwrap();
    }

    // restart, see that it sets a timeout again
    handlers
        .handle_start("pinger".to_string(), &mut response)
        .unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 0);
    assert_eq!(
        response.states,
        json!({"pinger": {"pings_sent": 0,
                                                  "test": "hello"}})
    );
}
