// logging.rs — tracing setup (stdout + optional append-only log file)

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Shared append-only log file for the file layer.
#[derive(Clone)]
struct FileMakeWriter(Arc<Mutex<std::fs::File>>);

struct FileWriter {
    file: Arc<Mutex<std::fs::File>>,
}

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.lock().expect("log file mutex poisoned").write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.lock().expect("log file mutex poisoned").flush()
    }
}

impl<'a> MakeWriter<'a> for FileMakeWriter {
    type Writer = FileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        FileWriter {
            file: Arc::clone(&self.0),
        }
    }
}

/// Initialize tracing to stdout and optionally append to `log_file`.
pub fn init(log_level: &str, log_file: Option<&Path>) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    let stdout_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true);

    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create log directory {}", parent.display()))?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file {}", path.display()))?;

        let file_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_ansi(false)
            .with_writer(FileMakeWriter(Arc::new(Mutex::new(file))));

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();

        tracing::info!(log_file = %path.display(), "Writing logs to file (append)");
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
    }

    Ok(())
}
