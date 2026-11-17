#![no_main]
//! Event log maps, which a project may bring in its own `maps/` folder: parse, then apply to
//! a 4624 record (O4).
use af_windows::evtx_map::{EventMap, map_event};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(m) = EventMap::parse(&String::from_utf8_lossy(data)) else {
        return;
    };
    let event = serde_json::json!({"System": {"EventID": 4624, "Channel": "Security",
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}},
        "EventData": {"TargetUserName": "jcloudy", "LogonType": 2, "IpAddress": "-"}});
    let _ = map_event(&[m], &event);
});
