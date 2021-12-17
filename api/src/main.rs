use actix_web::{web,get,  post, App, HttpResponse, HttpServer, Responder, Result};
use substrate_subxt::{Client, PairSigner};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};
use hex_literal::hex;
use pallet_mixnet::types::{Cipher, PublicKeyShare, Wrapper};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
mod substrate;
use substrate::rpc::{get_ciphers, store_public_key_share, submit_partial_decryptions};
use crypto::{
    proofs::decryption::{DecryptPostBody},
    types::Cipher as BigCipher,
};

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

// #[get("/decrypt/{vote}/{question}")]
// async fn decrypt(web::Path((vote, question)): web::Path<(String, String)>) -> Result<impl Responder> {
//     let client = init().await.unwrap();
//     let vote_id = vote.as_bytes().to_vec();
//     let topic_id = question.as_bytes().to_vec();
//     let nr_of_shuffles = 3;
//     let raw_encryptions: Vec<Cipher> = get_ciphers(&client, topic_id.clone(), nr_of_shuffles).await.unwrap();
//     let encryptions: Vec<BigCipher> = Wrapper(raw_encryptions).into();

//     Ok(web::Json(encryptions))
// }


#[get("/decrypt/{vote}/{question}")]
async fn get_decrypt(web::Path((vote, question)): web::Path<(String, String)>) -> Result<impl Responder> {
    let client = init().await.unwrap();
    let vote_id = vote.as_bytes().to_vec();
    let topic_id = question.as_bytes().to_vec();
    let nr_of_shuffles = 3;
    let raw_encryptions: Vec<Cipher> = get_ciphers(&client, topic_id.clone(), nr_of_shuffles).await.unwrap();
    let encryptions: Vec<BigCipher> = Wrapper(raw_encryptions).into();

    Ok(web::Json(encryptions))
}



#[post("/decrypt/{vote}/{question}/{sealer}")] 
async fn post_decrypt(web::Path((vote, question, sealer)): web::Path<(String, String, String)>, decrypt_post_body: web::Json<DecryptPostBody>) -> impl Responder {
    // submit the partial decryption + proof
    let client = init().await.unwrap();

    let (sealer, sealer_id): (Pair, [u8; 32]) = get_sealer(sealer);
    let vote_id = vote.as_bytes().to_vec();
    let topic_id = question.as_bytes().to_vec();
    let nr_of_shuffles = 3;
  
    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(sealer);
    let response = submit_partial_decryptions(
        &client,
        &signer,
        vote_id,
        topic_id,
        decrypt_post_body.shares.clone(),
        decrypt_post_body.decryption_proof.clone().into(),
        nr_of_shuffles,
    )
    .await.unwrap();
    HttpResponse::Ok().body("Successfully Submitted Partial Decryptions!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
        .service(keygen)
        .service(get_decrypt)
        .service(post_decrypt)
    })
    .bind(("0.0.0.0", 11111))?
    .run()
    .await
}
