use actix_web::{web,get,  post, App, HttpResponse, HttpServer, Responder, Result};
use substrate_subxt::{Client, PairSigner};
use substrate_subxt::{ClientBuilder, Error, NodeTemplateRuntime};
use hex_literal::hex;
use pallet_mixnet::types::{Cipher, PublicKeyShare, Wrapper};
use sp_keyring::{sr25519::sr25519::Pair, AccountKeyring};
mod substrate;
use substrate::rpc::{get_ciphers, store_public_key_share, submit_partial_decryptions};
use crypto::{
    proofs::decryption::{DecryptPostBody, HexDecryptionProof, DecryptionProof},
    types::Cipher as BigCipher,
};
use num_bigint::BigUint;
use num_traits::Num;

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


    // This is what a DecryptionProof proof looks like when
    // we log it as 
    // 

    // 
    // DecryptionProof {
    //     CHALLENGE: "5f8d6b6156655e054edbc45c4748152d621d3e965ac734db12ed0dd89a35cf4c92905a1e0c3d08c794d4640f1139f6cb0d8d9f3823cd78ca159a0072c836cf12"
    //     RESPONSE: "73f9c243fc22ed0c47024839b0bc66c0a9514ff50f5d95804dce0653df2b3a8c551c9cb417a2136c60e2c421b172ea74139af3bbb11ffa38e34fe1f0c3be5d1b8f6329a1ddfdd4bd6d585514cae5ac9429508622fbf5008c6ef2497b1126a86cb1ffcdd59d8fc0d4e562e466af1470e88e708c580fe4aa9112f2848780bd55bf7c92cc7a684bcced3be0e729c558103af50b74f6e29cbdf186666bf8af3b1e2ee84a92038c602b8c3eda835c158d1fb1df04d4ab7e9ce77b7fe010aa91c400c94a8b5c8af4876893561ecbc02d9c7eafd9efc964ad898a74c73cd3c53edfce94d5164c34bf07409c1494a5158123052de607ce93f2baf64f395aa1b9b26f00d"    
    // }
    // 
    // Perhaps it would be ideal to pass the DecryptionProof with challenge and 
    // response encoded as hex strings as above. 
    // We could then simply convert it using from_str_radix()


    
    let raw_decryption_proof: HexDecryptionProof = decrypt_post_body.decryption_proof.clone().into();


    
    let decryption_proof = DecryptionProof {
        challenge: BigUint::from_str_radix(&raw_decryption_proof.challenge, 16), 
        response: BigUint::from_str_radix(&raw_decryption_proof.response, 16), 
    };

    println!("CHALLENGE: {:?}", decryption_proof.challenge);
    println!("RESPONSE: {:?}", decryption_proof.response);

    let signer = PairSigner::<NodeTemplateRuntime, Pair>::new(sealer);
    let response = submit_partial_decryptions(
        &client,
        &signer,
        vote_id,
        topic_id,
        decrypt_post_body.shares.clone(),
        decryption_proof.into(),
        nr_of_shuffles,
    )
    .await.unwrap();
    println!("response: {:?}", response.events[0].variant);

    HttpResponse::Ok().body("Successfully Submitted Partial Decryptions!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
        .service(keygen)
        .service(get_decrypt)
        .service(post_decrypt)
        .data(web::JsonConfig::default().limit(1024 * 1024 * 50))
    })
    .bind(("0.0.0.0", 12345))?
    .run()
    .await
}
