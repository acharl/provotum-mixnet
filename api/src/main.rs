use actix_web::{web, post, App, HttpResponse, HttpServer, Responder};
use substrate_subxt::{Client, PairSigner};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};
use hex_literal::hex;
use pallet_mixnet::types::{PublicKeyShare};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
mod substrate;
use substrate::rpc::store_public_key_share;
use serde::{Deserialize, Serialize};


fn get_sealer(sealer: String) -> (Pair, [u8; 32]) {
    // get the sealer and sealer_id
    if sealer == "bob" {
        return (
            AccountKeyring::Bob.pair(),
            hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48").into(),
        );
    } else {
        return (
            AccountKeyring::Charlie.pair(),
            hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22").into(),
        );
    };
}

async fn init() -> Result<Client<NodeTemplateRuntime>, Error> {
    let url = "ws://127.0.0.1:9944";
    let client = ClientBuilder::<NodeTemplateRuntime>::new()
        .set_url(url)
        .build()
        .await?;
    Ok(client)
}

#[derive(Serialize, Deserialize,Debug)]
struct PostKeygenData {
  vote: String,
  sealer: String 
}

#[post("/keygen/{vote}/{sealer}")] // <- define path parameters
async fn keygen(web::Path((vote, sealer)): web::Path<(String, String)>, pk_share: web::Json<PublicKeyShare>) -> impl Responder {
    let client = init().await.unwrap();
    let (sealer, sealer_id): (Pair, [u8; 32]) = get_sealer(sealer.to_string()); 

     let vote_id = vote.as_bytes().to_vec();
 
     // submit the public key share + proof
     let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(sealer);
     let store_public_key_share_response =
         store_public_key_share(&client, &signer, vote_id, pk_share.into_inner()).await.unwrap();
     println!(
         "store_public_key_share_response: {:?}",
         store_public_key_share_response.events[0].variant
     );
 
     HttpResponse::Ok().body("Successfully Stored Key Share!")
}


#[post("/test/{vote}/{sealer}")] // <- define path parameters
async fn index(web::Path((vote, sealer)): web::Path<(String, String)>, key_share: web::Json<PublicKeyShare>) -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
        .service(keygen)
        .service(index)
    })
    .bind(("0.0.0.0", 1111))?
    .run()
    .await
    
}
