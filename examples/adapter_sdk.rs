use std::ffi::{OsStr, OsString};

use iorec::adapter_sdk::{
    ADAPTER_SDK_VERSION, AdapterConfiguration, AdapterHost, AdapterResult, AdapterSdk,
    ConfigureContext, CorrelateContext, Correlation, DetectContext, Detection, ParseContext,
    ParsedEvent,
};

struct ExampleAdapter;

impl AdapterSdk for ExampleAdapter {
    fn detect(&self, context: &DetectContext) -> AdapterResult<Detection> {
        Ok(if context.command[0] == OsStr::new("example-agent") {
            Detection::matched(1.0, "executable name matched")
        } else {
            Detection::no_match("executable name did not match")
        })
    }

    fn configure(&self, _context: &ConfigureContext) -> AdapterResult<AdapterConfiguration> {
        let mut configuration = AdapterConfiguration::default();
        configuration.environment.insert(
            OsString::from("EXAMPLE_AGENT_OBSERVER"),
            OsString::from("enabled"),
        );
        configuration
            .known_gaps
            .push("example hook is not independent transport evidence".to_owned());
        Ok(configuration)
    }

    fn parse(&self, context: &ParseContext) -> AdapterResult<Vec<ParsedEvent>> {
        Ok(vec![ParsedEvent::new(
            "BeforeModel",
            context.payload.clone(),
        )])
    }

    fn correlate(&self, _context: &CorrelateContext) -> AdapterResult<Correlation> {
        Ok(Correlation::unresolved("no exact identifier"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = AdapterHost::new(
        "example-agent",
        "1.0.0",
        ADAPTER_SDK_VERSION,
        ExampleAdapter,
    )?;
    let detection = adapter.detect(&DetectContext::new(vec![OsString::from("example-agent")]))?;
    assert!(detection.matched);
    Ok(())
}
