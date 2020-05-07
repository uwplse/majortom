use majortom::data;
use majortom::ptrace_handlers;
use std::fs::read_to_string;

mod common;

use common::{path_exists, setup_example};

#[ignore]
#[test]
fn test_files() {
    let config = setup_example("fs");
    // ensure writefile doesn't exist before we start
    let _ = std::fs::remove_file("writefile");
    let mut handlers = ptrace_handlers::Handlers::new(config);
    for _ in 0..2 {
        let mut response = data::Response::new();
        handlers
            .handle_start("filewriter".to_string(), &mut response)
            .unwrap();
        assert_eq!(response.timeouts.len(), 1);
        assert_eq!(response.messages.len(), 0);
        assert_eq!(response.cleared_timeouts.len(), 0);

        assert!(path_exists("readfile"));
        assert!(path_exists("existingwritefile"));
        assert!(!path_exists("writefile"));

        assert_eq!(read_to_string("readfile").unwrap(), "AN EXAMPLE FILE");
        assert_eq!(
            read_to_string("existingwritefile").unwrap(),
            "A FILE WITH SOME CONTENTS"
        );

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

        assert_eq!(
            read_to_string("existingwritefile").unwrap(),
            "A FILE WITH SOME CONTENTS\nMORE TEXT IN THE FILE"
        );

        let timeout = response.timeouts.pop().unwrap();
        response = data::Response::new();
        handlers.handle_timeout(timeout, &mut response).unwrap();
        assert_eq!(response.timeouts.len(), 1);
        assert_eq!(response.messages.len(), 0);
        assert_eq!(response.cleared_timeouts.len(), 1);

        assert_eq!(read_to_string("writefile").unwrap(), "TEXT IN THE FILE");
    }
}

#[ignore]
#[test]
fn test_directory() {
    let config = setup_example("fs");
    // ensure writefile doesn't exist before we start
    let _ = std::fs::remove_file("directory");
    let mut handlers = ptrace_handlers::Handlers::new(config.nodes);
    for _ in 0..2 {
        let mut response = data::Response::new();
        handlers
            .handle_start("directorymaker".to_string(), &mut response)
            .unwrap();
        assert_eq!(response.timeouts.len(), 1);
        assert_eq!(response.messages.len(), 0);
        assert_eq!(response.cleared_timeouts.len(), 0);

        assert!(!path_exists("directory"));

        let timeout = response.timeouts.pop().unwrap();
        response = data::Response::new();
        handlers.handle_timeout(timeout, &mut response).unwrap();
        assert_eq!(response.timeouts.len(), 1);
        assert_eq!(response.messages.len(), 0);
        assert_eq!(response.cleared_timeouts.len(), 1);

        assert!(path_exists("directory"));
    }
}
