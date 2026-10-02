use std::time::Duration;

pub mod fec;
pub mod forward;
pub mod offload;
pub mod udp;
pub mod utils;

pub const UDP_TTL: Duration = Duration::from_secs(180);
