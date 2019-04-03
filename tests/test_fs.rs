use majortom::ptrace_handlers;
use majortom::data;
use std::fs::read_to_string;

mod common;

fn path_exists(s: &str) -> bool {
    std::path::Path::new(s).exists()
}

#[test]
fn test_fs() {
    let config = common::setup_example("fs");
    // ensure writefile doesn't exist before we start
    let _ = std::fs::remove_file("writefile");
    let mut handlers = ptrace_handlers::Handlers::new(config.nodes);
    let mut response = data::Response::new();
    handlers.handle_start("filewriter".to_string(), &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 0);
    let timeout = response.timeouts.pop().unwrap();
    response = data::Response::new();
    handlers.handle_timeout(timeout, &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 1);

    assert_eq!(read_to_string("readfile").unwrap(), "AN EXAMPLE FILE");

    let timeout = response.timeouts.pop().unwrap();
    response = data::Response::new();
    handlers.handle_timeout(timeout, &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 1);

    assert_eq!(read_to_string("existingwritefile").unwrap(),
              "A FILE WITH SOME CONTENTS\nMORE TEXT IN THE FILE");

    let timeout = response.timeouts.pop().unwrap();
    response = data::Response::new();
    handlers.handle_timeout(timeout, &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 1);

    assert_eq!(read_to_string("writefile").unwrap(),
              "TEXT IN THE FILE");


    response = data::Response::new();
    handlers.handle_start("filewriter".to_string(), &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 0);

    assert!(path_exists("readfile"));
    assert!(path_exists("existingwritefile"));
    assert!(!path_exists("writefile"));

    assert_eq!(read_to_string("readfile").unwrap(), "AN EXAMPLE FILE");
    assert_eq!(read_to_string("existingwritefile").unwrap(), "A FILE WITH SOME CONTENTS");

    // now, do the same thing again
    let timeout = response.timeouts.pop().unwrap();
    response = data::Response::new();
    handlers.handle_timeout(timeout, &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 1);

    assert_eq!(read_to_string("readfile").unwrap(), "AN EXAMPLE FILE");

    let timeout = response.timeouts.pop().unwrap();
    response = data::Response::new();
    handlers.handle_timeout(timeout, &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 1);

    assert_eq!(read_to_string("existingwritefile").unwrap(),
              "A FILE WITH SOME CONTENTS\nMORE TEXT IN THE FILE");

    let timeout = response.timeouts.pop().unwrap();
    response = data::Response::new();
    handlers.handle_timeout(timeout, &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 1);

    assert_eq!(read_to_string("writefile").unwrap(),
              "TEXT IN THE FILE");


    response = data::Response::new();
    handlers.handle_start("filewriter".to_string(), &mut response).unwrap();
    assert_eq!(response.timeouts.len(), 1);
    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.cleared_timeouts.len(), 0);

    assert!(path_exists("readfile"));
    assert!(path_exists("existingwritefile"));
    assert!(!path_exists("writefile"));

    assert_eq!(read_to_string("readfile").unwrap(), "AN EXAMPLE FILE");
    assert_eq!(read_to_string("existingwritefile").unwrap(), "A FILE WITH SOME CONTENTS");
}
