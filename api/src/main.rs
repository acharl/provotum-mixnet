use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use substrate_subxt::{Client, PairSigner};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};
use crypto::{
    helper::Helper,
    proofs::{keygen::KeyGenerationProof},
    random::Random};
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

#[post("/keygen")]
async fn keygen(data: web::Json<PostKeygenData>) -> impl Responder {
    let sk_as_string = "10008";
    let client = init().await.unwrap();

     // create private and public key
     let (params, sk, pk) = Helper::setup_lg_system_with_sk(sk_as_string.as_bytes());

     // get the sealer and sealer_id
     let (sealer, sealer_id): (Pair, [u8; 32]) = get_sealer(data.sealer.to_string()); 
 
     // create public key share + proof
     let r = Random::get_random_less_than(&params.q());
     let proof = KeyGenerationProof::generate(&params, &sk.x, &pk.h, &r, &sealer_id);
     let pk_share = PublicKeyShare {
         proof: proof.clone().into(),
         pk: pk.h.to_bytes_be(),
     };
     let vote_id = data.vote.as_bytes().to_vec();
 
     // submit the public key share + proof
     let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(sealer);
     let store_public_key_share_response =
         store_public_key_share(&client, &signer, vote_id, pk_share).await.unwrap();
     println!(
         "store_public_key_share_response: {:?}",
         store_public_key_share_response.events[0].variant
     );
 
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
        .service(keygen)
    })
    .bind("127.0.0.1:8888")?
    .run()
    .await
}



