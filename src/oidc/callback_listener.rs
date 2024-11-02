use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use warp::Filter;

pub async fn listen() -> Result<String, Box<dyn std::error::Error>> {
    // Create oneshot channels for authorization code and server shutdown
    let (code_tx, code_rx) = oneshot::channel::<String>();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    // Wrap the senders in Arc<Mutex<>> to share across threads
    let code_tx = Arc::new(Mutex::new(Some(code_tx)));
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));

    // Define the callback route
    let callback_route = warp::path("callback")
        .and(warp::query::<std::collections::HashMap<String, String>>())
        .and(warp::any().map(move || (Arc::clone(&code_tx), Arc::clone(&shutdown_tx))))
        .and_then(handle_callback);

    // Start the server with a graceful shutdown signal
    let (addr, server) =
        warp::serve(callback_route).bind_with_graceful_shutdown(([127, 0, 0, 1], 3030), async {
            shutdown_rx.await.ok();
        });

    println!("Server started at http://{}", addr);

    // Run the server in a separate async task
    tokio::spawn(server);

    // Wait for the authorization code from the oneshot channel
    match code_rx.await {
        Ok(code) => {
            println!("Server closed. Authorization code: {}", code);
            Ok(code)
        }
        Err(e) => {
            eprintln!("Server closed without receiving an authorization code.");
            Err(Box::new(e))
        }
    }
}

async fn handle_callback(
    params: HashMap<String, String>,
    channels: (
        Arc<Mutex<Option<oneshot::Sender<String>>>>,
        Arc<Mutex<Option<oneshot::Sender<()>>>>,
    ),
) -> Result<impl warp::Reply, warp::Rejection> {
    let (code_tx, shutdown_tx) = channels;

    if let Some(code) = params.get("code") {
        println!("Authorization code received: {}", code);

        // Send the code and shutdown signal
        if let Some(tx) = code_tx.lock().await.take() {
            let _ = tx.send(code.to_string());
        }
        if let Some(tx) = shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }

        Ok(warp::reply::html(
            "Authorization code received. You can close this window.",
        ))
    } else {
        Ok(warp::reply::html(
            "No authorization code found in the query.",
        ))
    }
}
