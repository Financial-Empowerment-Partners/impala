use axum::{
    //routing::{get, post},
    routing::{get},
    //http::StatusCode,
    //Json,
    Router,
};

#[tokio::main]
async fn main() {
    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `default_route`
        .route("/", get(default_route))
        // `GET /version` goes to `get_version`
        .route("/version", get(get_version));

    // run our app listening globally on port 8080
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// simple handler that responds with a hello message
async fn default_route() -> &'static str {
    "Hello, World!"
}

async fn get_version() -> &'static str {
    "0.0.0"
}

