use anyhow::Result;
use clap::{Parser, Subcommand};
use halod::{Keypair, Publisher, parse_ticket, subscribe};
use std::net::SocketAddr;
use tracing::{Level, event};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "halod")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Publish a video from a file, using MoQ
    Publish {
        video_path: String,
        /// Optional external discovery server address (e.g. [2001:db8::1]:4444)
        #[arg(long)]
        discovery: Option<SocketAddr>,
    },

    /// Subscribe to a MoQ stream using a ticket
    Subscribe {
        ticket: String,
        /// Optional external discovery server address (e.g. [2001:db8::1]:4444)
        #[arg(long)]
        discovery: Option<SocketAddr>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Enable tracing display on terminal. The EnvFilter enables us to add DEBUG output
    // by setting the env variable RUST_LOG=debug. By default we'll display from severity INFO only.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    event!(Level::INFO, "starting halod 0.0.1");

    // Generate/use an ed25519 keypair. The public key will be used as NodeID.
    let k = Keypair::new()?;
    event!(Level::INFO, "pubkey for this node is {k}");

    match cli.command {
        Commands::Publish {
            video_path,
            discovery,
        } => {
            eprintln!("Publishing {video_path}");
            let publisher = Publisher::bind(&video_path, k.node_id(), discovery).await?;
            eprintln!("Publisher ticket: {}", publisher.ticket());
            tokio::select! {
                res = publisher.run() => res?,
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Commands::Subscribe { ticket, discovery } => {
            // Printing anything to stdout can corrupt the pipe to ffplay
            eprintln!("Subscribing to {ticket}");
            let addr = parse_ticket(&ticket)?;
            tokio::select! {
                res = subscribe(addr, tokio::io::stdout(), discovery) => res?,
                _ = tokio::signal::ctrl_c() => {}
            }
        }
    }

    Ok(())
}
