use std::process::Command;
use trace_rs::{Error, Event, Tracer};

fn main() -> Result<(), Error> {
    let mut tracer = Tracer::new();

    tracer.spawn(Command::new("ls"))?;

    while tracer.is_tracing() {
        let (tracee, event) = tracer.wait()?;

        println!("{:x?}", event);

        match event {
            Event::ExitProcess { .. } => continue,
            _ => (),
        };

        tracer.resume(tracee)?;
    }

    Ok(())
}
