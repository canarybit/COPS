#[derive(Debug, PartialEq, Eq, Clone)] // Derive PartialEq and Eq
pub enum CloudProvider {
    Ovh,
    Aws,
    Azure,
}
#[derive(Debug, PartialEq, Eq)] // Derive PartialEq and Eq
pub enum Owner {
    Application,
    Dataset,
    Empty,
}

#[derive(Debug, PartialEq, Eq, Clone)] // Derive PartialEq and Eq
pub enum Mode {
    AttestationOnly,
    BasicAttestation,
    Regular,
}
