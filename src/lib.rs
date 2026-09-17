//! Core library for the Agent Inference Flight Recorder.
//!
//! The evidence layer is deliberately independent from any one agent or
//! transport. Collectors append immutable events and content-addressed blobs;
//! normalized views always point back to the raw evidence that produced them.

pub mod adapter;
pub mod adapter_sdk;
pub mod artifact_export;
pub mod audit;
pub mod blob_keys;
pub mod cgroup;
pub mod collector;
pub mod control;
pub mod correlation;
pub mod crypto;
pub mod discovery;
pub mod doctor;
pub mod egress;
pub mod export;
pub mod fake_server;
pub mod input;
pub mod inspect;
pub mod manifest;
pub(crate) mod metadata;
pub mod migration;
pub mod model;
pub mod openinference;
pub mod otlp;
pub mod pcap;
pub mod platform_export;
pub mod policy;
pub mod probe_helper;
pub mod probe_plan;
pub mod probe_policy;
pub mod process_tracker;
pub mod proxy;
pub mod replay;
pub mod retention;
pub mod runner;
pub mod runtime_injection;
pub(crate) mod secure_fs;
pub mod session;
pub mod sse;
pub mod state;
pub mod storage;
pub mod support_matrix;
/// Rootless task network isolation and fail-closed proxy-only egress.
pub mod task_netns;
/// Logical task boundaries inside long-lived multi-session Agent processes.
pub mod tasks;
pub mod timeline;
pub mod tls_keylog;
pub mod transparent;
/// Offline packet/TLS stream reconstruction and cross-source payload auditing.
pub mod transport_audit;
pub mod upload;
pub mod verify;

pub const SCHEMA_VERSION: u32 = 1;
pub const RECORDER_VERSION: &str = env!("CARGO_PKG_VERSION");
