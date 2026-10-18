//! Interactive Player Messaging example using caller-supplied game and device policy.
use bedrock_services::{
    minecraft::{Config, Minecraft},
    oauth::{MicrosoftAuth, Poll},
    signaling::{
        Event,
        websocket::{MessagingSocket, Options, SocketError},
    },
    xbox,
};
use std::time::{Duration, Instant, SystemTime};

/// Uses caller-supplied game policy and persistent device identity; never prints token or signal bytes.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err(
            "usage: messaging <game-version> <protocol> <persistent-device-uuid> <network-id>"
                .into(),
        );
    }
    let protocol = args[1].parse()?;
    let device: uuid::Uuid = args[2].parse()?;
    let network = args[3].parse()?;
    let mut microsoft = MicrosoftAuth::new(xbox::Config::default())?;
    let mut attempt = microsoft.start(SystemTime::now()).await?;
    println!(
        "Open {} and enter {}",
        attempt.verification_uri(),
        attempt.user_code()
    );
    let credentials = loop {
        // Explicit example pacing belongs to this application, not a hidden SDK task.
        let delay = attempt
            .next_poll()
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(delay).await;
        if let Poll::Authorized(credentials) =
            microsoft.poll(&mut attempt, SystemTime::now()).await?
        {
            break credentials;
        }
    };
    let account = microsoft.into_account(credentials)?;
    let mut services = Minecraft::new(account, Config::desktop(&args[0], protocol, device))?;
    let request = services.messaging_connection().await?;
    let mut socket = match MessagingSocket::connect(&request, network, Options::default()).await {
        Ok(socket) => socket,
        Err(error) => {
            if error == SocketError::UpgradeStatus(401) {
                services.reject_messaging(&request);
            }
            // Reconnect/sign-in policy and persistence of any rotated refresh token belong to the application.
            return Err(error.into());
        }
    };
    let turn = socket.request_credentials(Instant::now() + Duration::from_secs(30))?;
    loop {
        match socket.drive().await? {
            Event::Completed { request, result } if request == turn => {
                result.map_err(|_| "TURN request failed")?;
                let credentials = socket.credentials().ok_or("TURN credentials expired")?;
                println!(
                    "Received {} TURN server entries",
                    credentials.servers().len()
                );
                break;
            }
            Event::Signal(_signal) => {
                // A real adapter calls acknowledge only after its NetherNet codec accepts the signal.
            }
            _ => {}
        }
    }
    socket.close();
    loop {
        match socket.drive().await {
            Ok(_) => {}
            Err(SocketError::Closed) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
