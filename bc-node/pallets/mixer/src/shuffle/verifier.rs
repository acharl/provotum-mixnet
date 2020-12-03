use crate::{Error, Module, Trait};
use crypto::{
    helper::Helper,
    proofs::shuffle::ShuffleProof,
    types::ElGamalParams,
    types::{Cipher, ModuloOperations, PublicKey},
};
use num_bigint::BigUint;
use num_traits::One;
use sp_std::{if_std, vec, vec::Vec};

/// all functions related to zero-knowledge proofs in the offchain worker
impl<T: Trait> Module<T> {
    /// GenShuffleProof Algorithm 8.51 (CHVoteSpec 3.1)
    ///
    /// Checks the correctness of a shuffle proof generated by Algorithm 8.47.
    /// The public values are the ElGamal encryptions e and e~ and
    /// the public encryption key pk.
    pub fn verify_shuffle_proof(
        id: usize, // election id
        proof: (
            BigUint, // challenge
            (
                BigUint,      // s1
                BigUint,      // s2
                BigUint,      // s3
                BigUint,      // s4
                Vec<BigUint>, // vec_s_hat
                Vec<BigUint>, // vec_s_tilde
            ),
            Vec<BigUint>, // permutation_commitments
            Vec<BigUint>, // permutation_chain_commitments
        ),
        encryptions: Vec<Cipher>,
        shuffled_encryptions: Vec<Cipher>,
        pk: &PublicKey,
    ) -> Result<bool, Error<T>> {
        let e = encryptions;
        let e_tilde = shuffled_encryptions;
        let (challenge, s, vec_c, vec_c_hat) = proof;
        let (s1, s2, s3, s4, vec_s_hat, vec_s_tilde) = s;

        // input checks
        assert!(
            e.len() == e_tilde.len(),
            "encryptions and shuffled_encryptions need to have the same length!"
        );
        assert!(
            e.len() == vec_c.len(),
            "encryptions and permutation_commitments need to have the same length!"
        );
        assert!(
            e.len() == vec_c_hat.len(),
            "encryptions and permutation_chain_commitments need to have the same length!"
        );
        assert!(
            e.len() == vec_s_hat.len(),
            "encryptions and vec_s_hat need to have the same length!"
        );
        assert!(
            e.len() == vec_s_tilde.len(),
            "encryptions and vec_s_hat need to have the same length!"
        );
        assert!(!e.is_empty(), "vectors cannot be empty!");

        // the size of the shuffle (# of encrypted votes)
        let size = e.len();
        let params = &pk.params;
        let h = &params.h;
        let p = &params.p;
        let q = &params.q();

        // get {size} independent generators: vec_h
        let vec_h = Helper::get_generators(id, p, size);

        // get {size} challenges
        // vec_u = get_challenges(size, hash(e, e_tilde, vec_c, pk))
        let vec_u =
            ShuffleProof::get_challenges(size, e.clone(), e_tilde.clone(), vec_c.clone(), pk);

        // get c_hat_0
        // h = the 2. public generator
        let c_hat_0 = &params.h;

        // get c_flat = Π(c_i) / Π(vec_h_i) mod p
        // vec_c = permutation_commitments
        // vec_h = public generators
        let prod_vec_c = vec_c
            .iter()
            .fold(BigUint::one(), |prod, c| prod.modmul(c, p));
        let prod_h = vec_h
            .iter()
            .fold(BigUint::one(), |prod, gen| prod.modmul(gen, p));
        let c_flat = prod_vec_c
            .moddiv(&prod_h, p)
            .ok_or_else(|| Error::DivModError)?;

        // get u = Π(vec_u_i) mod q
        // vec_u = challenges
        let u = vec_u
            .iter()
            .fold(BigUint::one(), |product, u| product.modmul(u, q));

        // get value c_hat = c_hat_n / h^u mod p
        // vec_c_hat = permutation_chain_commitments
        let h_pow_u = h.modpow(&u, p);
        let c_hat_n = vec_c_hat.get(size - 1).ok_or_else(|| Error::InvModError)?;
        let c_hat = c_hat_n
            .moddiv(&h_pow_u, p)
            .ok_or_else(|| Error::DivModError)?;

        // get value c_tilde = Π(c_i^u_i) mod p
        // vec_c = permutation_commitments
        // vec_u = challenges
        let c_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_c, &vec_u, p);

        if_std! {
            println!("verifier - vec_u: {:?}", vec_u);
            println!("verifier - vec_c: {:?}", vec_c);
            println!("verifier - c_tilde: {:?}\n", c_tilde);
        }

        // vec_a = vector of all components a (encryption { a, b })
        // vec_b = vector of all components b (encryption { a, b })
        let vec_a = e.clone().into_iter().map(|v| v.a).collect();
        let vec_b = e.clone().into_iter().map(|v| v.b).collect();
        let a_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_a, &vec_u, p);
        let b_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_b, &vec_u, p);

        // generate vec_t_hat values
        let vec_t_hat = Self::get_vec_t_hat_verifier(
            &c_hat_0,
            &challenge,
            &vec_c_hat,
            &vec_s_hat,
            &vec_s_tilde,
            size,
            params,
        );

        let (t1, t2, t3, (t4_1, t4_2)) = Self::get_t_values_verifier(
            &c_flat,
            &c_hat,
            &c_tilde,
            &challenge,
            &a_tilde,
            &b_tilde,
            &e_tilde,
            &vec_h,
            &vec_s_tilde,
            &s1,
            &s2,
            &s3,
            &s4,
            size,
            pk,
        )?;

        // generate challenge from (y, t)
        // public value y = ((e, e_tilde, vec_c, vec_c_hat, pk)
        // public commitment t = (t1, t2, t3, (t4_1, t4_2), (t_hat_0, ..., t_hat_(size-1)))
        let public_value = (e, e_tilde, vec_c, vec_c_hat, pk);
        let public_commitment = (t1, t2, t3, (t4_1, t4_2), vec_t_hat);
        let recomputed_challenge = ShuffleProof::get_challenge(public_value, public_commitment);

        let is_proof_valid = recomputed_challenge == challenge;
        Ok(is_proof_valid)
    }

    fn get_t_values_verifier(
        c_flat: &BigUint,
        c_hat: &BigUint,
        c_tilde: &BigUint,
        challenge: &BigUint,
        a_tilde: &BigUint,
        b_tilde: &BigUint,
        e_tilde: &Vec<Cipher>,
        vec_h: &Vec<BigUint>,
        vec_s_tilde: &Vec<BigUint>,
        s1: &BigUint,
        s2: &BigUint,
        s3: &BigUint,
        s4: &BigUint,
        size: usize,
        public_key: &PublicKey,
    ) -> Result<(BigUint, BigUint, BigUint, (BigUint, BigUint)), Error<T>> {
        let g = &public_key.params.g;
        let p = &public_key.params.p;
        let pk = &public_key.h;

        // get t1 = c_flat^challenge * g^s1 mod p
        let t1 = c_flat.modpow(challenge, p).modmul(&g.modpow(s1, p), p);

        // get t2 = c_hat^challenge * g^s2 mod p
        let g_pow_s2 = g.modpow(s2, p);
        let c_hat_pow_challenge = c_hat.modpow(challenge, p);
        let t2 = c_hat_pow_challenge.modmul(&g_pow_s2, p);

        // get t3 = c_tilde^challenge * g^s3 * Π(h_i^s_tilde_i) mod p
        let prod_h_s_tilde = Self::zip_vectors_multiply_a_pow_b(&vec_h, &vec_s_tilde, p);

        if_std! {
            println!("verifier - vec_h: {:?}", vec_h);
            println!("verifier - vec_s_tilde: {:?}", vec_s_tilde);
            println!("verifier - prod(h_i^s_tilde_i): {:?}\n", prod_h_s_tilde);
        }

        let g_pow_s3 = g.modpow(s3, p);

        if_std! {
            println!("verifier - g: {:?}", g);
            println!("verifier - s3: {:?}", s3);
            println!("verifier - g_pow_s3: {:?}\n", g_pow_s3);
        }

        let c_tilde_pow_challenge = c_tilde.modpow(challenge, p);

        if_std! {
            println!("verifier - challenge: {:?}", challenge);
            println!("verifier - c_tilde: {:?}", c_tilde);
            println!("verifier - c~^c: {:?}\n", c_tilde_pow_challenge);
        }

        let t3 = c_tilde_pow_challenge
            .modmul(&g_pow_s3, p)
            .modmul(&prod_h_s_tilde, p);

        if_std! {
            println!("verifier - t3: {:?}\n", t3);
        }

        // we need to swap pk and g
        // since our encryption conatins (a,b) with a = g^r
        // and not as in the spec a = pk^r
        // get t4_1 =
        // a_tilde^challenge * g^-s4 * Π(vec_a_tilde_i^s_tilde_i) mod p

        // g^-s4 = (g^-1)^s4 = (g^s4)^-1 = invmod(g^s4)
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let mut g_pow_minus_s4 = g.modpow(&s4, p);
        g_pow_minus_s4 = g_pow_minus_s4.invmod(p).ok_or_else(|| Error::InvModError)?;

        // compute prod_a = Π(vec_a_tilde_i^s_tilde_i)
        // compute prod_b = Π(vec_b_tilde_i^s_tilde_i)
        let mut prod_a = BigUint::one();
        let mut prod_b = BigUint::one();

        for i in 0..size {
            // a_tilde_i = component a of entry i in shuffled_encryptions
            let a_tilde_i = &e_tilde[i].a;
            // b_tilde_i = component b of entry i in shuffled_encryptions
            let b_tilde_i = &e_tilde[i].b;
            let s_tilde_i = &vec_s_tilde[i];

            let a_tilde_i_pow_s_tilde_i = a_tilde_i.modpow(s_tilde_i, p);
            prod_a = prod_a.modmul(&a_tilde_i_pow_s_tilde_i, p);

            let b_tilde_i_pow_s_tilde_i = b_tilde_i.modpow(s_tilde_i, p);
            prod_b = prod_b.modmul(&b_tilde_i_pow_s_tilde_i, p);
        }

        // compute t4_1
        let mut t4_1 = a_tilde.modpow(challenge, p);
        t4_1 = t4_1.modmul(&g_pow_minus_s4, p);
        t4_1 = t4_1.modmul(&prod_a, p);

        // we need to swap pk and g
        // since our encryption conatins (a,b) with a = g^r
        // and not as in the spec a = pk^r
        // get t4_2 =
        // b_tilde^challenge * pk^-s4 * Π(vec_b_tilde_i^s_tilde_i) mod p

        // pk^-s4 = (pk^-1)^s4 = (pk^s4)^-1 = invmod(pk^s4)
        // for an explanation see: Verifiable Re-Encryption Mixnets (Haenni, Locher, Koenig, Dubuis) page 9
        let pk_pow_s4 = pk.modpow(s4, p);
        let pk_pow_minus_s4 = pk_pow_s4.invmod(p).ok_or_else(|| Error::InvModError)?;

        // compute t4_2
        let mut t4_2 = b_tilde.modpow(challenge, p);
        t4_2 = t4_2.modmul(&pk_pow_minus_s4, p);
        t4_2 = t4_2.modmul(&prod_b, p);

        Ok((t1, t2, t3, (t4_1, t4_2)))
    }

    fn get_vec_t_hat_verifier(
        c_hat_0: &BigUint,
        challenge: &BigUint,
        vec_c_hat: &Vec<BigUint>,
        vec_s_hat: &Vec<BigUint>,
        vec_s_tilde: &Vec<BigUint>,
        size: usize,
        params: &ElGamalParams,
    ) -> Vec<BigUint> {
        let g = &params.g;
        let p = &params.p;

        // create an extended vec_c_hat
        // extended = [c_hat_0, ...c_hat];
        let mut vec_c_hat_extended = vec![c_hat_0];
        vec_c_hat_extended.extend(vec_c_hat);
        assert!(
            vec_c_hat_extended.len() == (size + 1usize),
            "vec_c_hat_extended needs to be 1 element larger than size!"
        );

        let mut vec_t_hat = Vec::new();
        for i in 0..size {
            // c_hat_i ^ challenge
            // i + 1 = the original i in vec_c_hat since the vector was extended above
            let c_hat_i = vec_c_hat_extended[i + 1];
            let c_hat_i_pow_challenge = c_hat_i.modpow(challenge, p);

            // g ^ s_hat_i
            let s_hat_i = &vec_s_hat[i];
            let g_pow_s_hat_i = g.modpow(&s_hat_i, p);

            // c_hat_(i-1) ^ s_tilde_i
            let s_tilde_i = &vec_s_tilde[i];
            let c_hat_i_minus_1 = vec_c_hat_extended[i];
            let c_hat_i_minus_1_pow_s_tilde_i = c_hat_i_minus_1.modpow(&s_tilde_i, p);

            // compute t_hat_i =
            // c_hat_i ^ challenge * g ^ s_hat_i * c_hat_(i-1) ^ s_tilde_i % p
            let t_hat_i = c_hat_i_pow_challenge
                .modmul(&g_pow_s_hat_i, p)
                .modmul(&c_hat_i_minus_1_pow_s_tilde_i, p);
            vec_t_hat.push(t_hat_i);
        }
        assert!(
            vec_t_hat.len() == size,
            "vec_t_hat should have length: {size}",
        );
        vec_t_hat
    }
}