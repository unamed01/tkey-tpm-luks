//main lib which provides all relevant types needed for functioning plus verify() func its split
//into one into some in client and some in host to make sure client doesnt need to pull #[derive(Debug)]
//which increase binary size by a lot.
use serialport::SerialPort;
use std::error::Error;

use std::fmt::Display;
use std::str::FromStr;
use tss_esapi::structures::MaxBuffer;
use tss_esapi::{
    Context, TctiNameConf,
    constants::SessionType,
    handles::{KeyHandle, TpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, HashScheme, PcrSelectionListBuilder, PcrSlot, SignatureScheme, SymmetricDefinition,
    },
};

//make sure you populate these with correct values
pub const LUKSUUID: &str = env!("luksUUID");
//whatever or wherever you have client app at should be in /client .
pub const BOOTDEVICE: &str = env!("bootdev");
//whatever luks2 encrypted partition is usually /dev/nvme0n1p3 but do check what is in your system.
pub const ENCRYPTEDDISK: &str = env!("luksdev");
const _: () = assert!(
    !LUKSUUID.is_empty() && !BOOTDEVICE.is_empty() && !ENCRYPTEDDISK.is_empty(),
    "make sure to populate disk devices and LUKSUUID, in lib.rs"
);
#[repr(u8)]
#[derive(Debug)]
pub enum ClientMessage {
    GoodSig = 0x20,
    GoodPass = 0x21,
    Ready4pass = 0x22,
}

#[derive(Debug)]
pub enum HostErr {
    CryptsetupErr,
    CryptsetupKilled,
    PipeError,
    IOError,
    TpmError,
    TpmRefusedToSign = 0x90,
}
#[repr(u8)]
#[derive(Debug)]
pub enum HostMessage {
    DecryptionSuccess = 0x99,
    DecryptionError = 0x98,
    TpmSigned = 0x97,
    TpmRefusedToSign = 0x90,
}

impl From<std::io::Error> for HostErr {
    fn from(_value: std::io::Error) -> Self {
        Self::IOError
    }
}
impl Display for HostErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostErr::CryptsetupErr => write!(f, "cryptsetup sent an error"),
            HostErr::PipeError => write!(f, "failed to write or create pipe"),
            HostErr::IOError => write!(f, "failed to fetch keyfile from tkey"),
            HostErr::CryptsetupKilled => write!(f, "cryptsetup was killed.."),
            HostErr::TpmError => write!(f, "tpm sent malformed sig"),
            HostErr::TpmRefusedToSign => {
                write!(f, "tpm REFUSED to sign this system is untrustworthy")
            }
        }
    }
}
impl Error for HostErr {}
#[repr(u8)]
#[derive(Debug)]
pub enum ClientError {
    Blake2 = 0x10,
    PassLen = 0x11,
    MalformedSig = 0x12,
    InvalidSig = 0x13,
    BadPubkey = 0x14,
    IOError = 0x15,
    //these two have no equivalent u8 since tkey never transmits them its host side only.
    OutOfsync,
    UnknownError,
}
//takes u8 and matches onto the proper Ok(ClientMessage) or Err(ClientError)
impl TryFrom<u8> for ClientMessage {
    type Error = ClientError;
    fn try_from(value: u8) -> Result<ClientMessage, ClientError> {
        match value {
            0x20 => Ok(ClientMessage::GoodSig),
            0x21 => Ok(ClientMessage::GoodPass),
            0x22 => Ok(ClientMessage::Ready4pass),
            0x10 => Err(ClientError::Blake2),
            0x11 => Err(ClientError::PassLen),
            0x12 => Err(ClientError::MalformedSig),
            0x13 => Err(ClientError::InvalidSig),
            0x14 => Err(ClientError::BadPubkey),
            0x15 => Err(ClientError::IOError),
            _ => Err(ClientError::UnknownError),
        }
    }
}
impl Error for ClientError {}
impl Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blake2 => write!(f, "blake2 hashing error.."),
            Self::PassLen => write!(f, "your password is too short try again.."),
            Self::MalformedSig => write!(f, "signature couldn't be imported"),
            Self::InvalidSig => write!(f, "signature is invalid."),
            Self::BadPubkey => write!(
                f,
                "public key couldnt be imported something must've went wrong on the build process."
            ),
            Self::IOError => write!(f, "couldn't communicate with tkey"),
            Self::UnknownError => write!(f, "tkey sent invalid error message."),
            Self::OutOfsync => write!(f, "host and tkey are out of sync, restart app."),
        }
    }
}
//lets SerialPort ops work with ClientError
impl From<std::io::Error> for ClientError {
    fn from(_value: std::io::Error) -> Self {
        Self::IOError
    }
}
// helper func takes in port and gives either CLientMessage or ClientError caller chooses how to proceed.
pub fn check_status(port: &mut dyn SerialPort) -> Result<ClientMessage, ClientError> {
    let mut status_byte = [0u8; 1];
    port.read_exact(&mut status_byte)?;
    ClientMessage::try_from(status_byte[0])
}

pub fn verify(nonce: &[u8; 32]) -> Result<[u8; 64], Box<dyn Error>> {
    let mut ctx = Context::new(TctiNameConf::from_str("device:/dev/tpmrm0")?)?;

    let sess = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?
        .ok_or("TPM returned no session")?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot4,
                PcrSlot::Slot8,
                PcrSlot::Slot9,
            ],
        )
        .build()?;

    let policy_sess = PolicySession::try_from(sess)?;
    ctx.policy_pcr(policy_sess, Digest::default(), pcr_selection)?;

    // load persistent key
    let tpm_handle = TpmHandle::try_from(0x8100_0001u32)?;
    let key_handle: KeyHandle = ctx.tr_from_tpm_public(tpm_handle)?.into();

    let nonce_buf = MaxBuffer::try_from(nonce.to_vec())?;
    let (digest, ticket) = ctx.hash(nonce_buf, HashingAlgorithm::Sha256, Hierarchy::Null)?;
    // apply policy session to the next command
    ctx.set_sessions((Some(AuthSession::PolicySession(policy_sess)), None, None));

    // sign it
    let scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };
    let signature = ctx.sign(key_handle, digest, scheme, ticket)?;

    //make sure its the right format
    let ecdsa = match signature {
        tss_esapi::structures::Signature::EcDsa(s) => s,
        _ => return Err("unexpected TPM signature type".into()),
    };
    let mut sig_bytes = [0u8; 64];
    let r = ecdsa.signature_r().value();
    let s = ecdsa.signature_s().value();
    if r.len() > 32 || s.len() > 32 {
        Err(HostErr::TpmError)?
    }
    // Left-pad into 32-byte slots (TPM might strip leading zeros)
    sig_bytes[32 - r.len()..32].copy_from_slice(r);
    sig_bytes[64 - s.len()..].copy_from_slice(s);
    Ok(sig_bytes)
}
