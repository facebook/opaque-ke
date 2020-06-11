
pub trait CipherSuite {
    type Aead;
    type Group;
    type Keypair;
}
