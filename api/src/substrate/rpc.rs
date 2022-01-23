use crate::substrate::calls::{
    StorePublicKeyShare, SubmitPartialDecryption,
};
use crate::substrate::stores::CiphersStore;
use pallet_mixnet::types::{
    Cipher, DecryptedShare, DecryptedShareProof, NrOfShuffles,
    PublicKeyShare, TopicId, VoteId,
};
use sp_keyring::{sr25519::sr25519::Pair};
use substrate_subxt::{Call, Client, ExtrinsicSuccess};
use substrate_subxt::{Error, NodeTemplateRuntime, PairSigner};

pub async fn get_ciphers(
    client: &Client<NodeTemplateRuntime>,
    topic_id: TopicId,
    nr_of_shuffles: NrOfShuffles,
) -> Result<Vec<Cipher>, Error> {
    let store = CiphersStore {
        topic_id,
        nr_of_shuffles,
    };
    let ciphers_as_bytes = client
        .fetch(&store, None)
        .await?
        .ok_or("failed to fetch ciphers!")?;
    Ok(ciphers_as_bytes)
}


pub async fn store_public_key_share(
    client: &Client<NodeTemplateRuntime>,
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    vote_id: VoteId,
    pk_share: PublicKeyShare,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let call = StorePublicKeyShare { vote_id, pk_share };
    return watch(&signer, client, call).await;
}


pub async fn submit_partial_decryptions(
    client: &Client<NodeTemplateRuntime>,
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    vote_id: VoteId,
    topic_id: TopicId,
    shares: Vec<DecryptedShare>,
    proof: DecryptedShareProof,
    nr_of_shuffles: NrOfShuffles,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    let call = SubmitPartialDecryption {
        vote_id,
        topic_id,
        shares,
        proof,
        nr_of_shuffles,
    };
    return watch(&signer, client, call).await;
}

async fn watch<C: Call<NodeTemplateRuntime> + Send + Sync>(
    signer: &PairSigner<NodeTemplateRuntime, Pair>,
    client: &Client<NodeTemplateRuntime>,
    call: C,
) -> Result<ExtrinsicSuccess<NodeTemplateRuntime>, Error> {
    return client.watch(call, signer).await;
}

