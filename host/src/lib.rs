use argon2::{Algorithm, Argon2, Params};
//main lib which provides all relevant types needed for functioning plus verify() func its split
//into one into some in client and some in host to make sure client doesnt need to pull #[derive(Debug)]
//which increase binary size by a lot.
use blake2::{Blake2s256, Digest as BlakeDigest};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::error::Error;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use chacha20::cipher::stream::StreamCipherCoreWrapper;
use chacha20::{ChaCha20, ChaCha20Rng, KeyIvInit, rand_core::SeedableRng};
use chacha20::{ChaChaCore, R20, variants::Ietf};
use std::fmt::Display;
use std::fs::File;
use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::thread;
use termios::{Termios, cfmakeraw, tcsetattr};
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
use x25519_dalek::{EphemeralSecret, PublicKey};
// helper type for exact ChaCha20 type for the cipher type we'll be using in this case to encrypt.
pub type ChaCha20Cipher = StreamCipherCoreWrapper<ChaChaCore<R20, Ietf>>;

//make sure you populate these with correct values
pub const LUKSUUID: &str = env!("luksUUID");
//whatever or wherever you have client app at should be in /client .
pub const BOOTDEVICE: &str = env!("bootdev");
//whatever luks2 encrypted partition is usually /dev/nvme0n1p3 but do check what is in your system.
pub const ENCRYPTEDDISK: &str = env!("luksdev");
// salt for argon2 operations.
pub const SALT: &[u8] = include_bytes!("../../SALT");

#[repr(u8)]
#[derive(Debug)]
pub enum ClientMessage {
    GoodSig = 0x20,
    GoodPass = 0x21,
    Ready4pass = 0x22,
}

#[derive(Debug)]
#[repr(u8)]
pub enum HostErr {
    CryptsetupErr,
    CryptsetupKilled,
    PipeError,
    IOError,
    TpmError,
    UnknownError,
    TpmRefusedToSign = 0x90,
    DecryptionError = 0x98,
    StringParseError,
}
#[repr(u8)]
#[derive(Debug)]
pub enum HostMessage {
    DecryptionSuccess = 0x99,
    TpmSigned = 0x97,
}

impl TryFrom<u8> for HostMessage {
    type Error = HostErr;
    fn try_from(value: u8) -> Result<Self, HostErr> {
        match value {
            0x99 => Ok(HostMessage::DecryptionSuccess),
            0x97 => Ok(HostMessage::TpmSigned),
            0x98 => Err(HostErr::DecryptionError),
            0x90 => Err(HostErr::TpmRefusedToSign),
            _ => Err(HostErr::UnknownError),
        }
    }
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
                write!(f, "tpm REFUSED to sign this system is unsuccessful_auth")
            }
            HostErr::UnknownError => write!(
                f,
                "unknown error found this is a bug please open a github issue to report it."
            ),
            HostErr::DecryptionError => write!(f, "couldn't decrypt passphrase is wrong."),
            //only happens in verify.rs
            HostErr::StringParseError => write!(
                f,
                "couldn't parse string correctly, qrexec stream was corrupted?"
            ),
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
    IOError(io::Error) = 0x15,
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
            0x15 => Err(ClientError::IOError(io::Error::new(
                io::ErrorKind::Interrupted,
                "tkey couldn't communicate",
            ))),
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
            Self::IOError(e) => write!(f, "IO error: {}", e),
            Self::UnknownError => write!(f, "tkey sent invalid error message."),
            Self::OutOfsync => write!(f, "host and tkey are out of sync, restart app."),
        }
    }
}
pub struct Tkey {
    tkey: File,
    _fd: OwnedFd,
}
impl Tkey {
    pub fn new() -> Result<Tkey, Box<dyn Error>> {
        let path = Path::new("/dev/ttyACM0");
        let fd = nix::fcntl::open(
            path,
            OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?;

        let mut termios = Termios::from_fd(fd.as_raw_fd())?;
        termios.c_cflag |= libc::CREAD | libc::CLOCAL;
        cfmakeraw(&mut termios);
        tcsetattr(fd.as_raw_fd(), termios::TCSANOW, &termios)?;

        fcntl(&fd, FcntlArg::F_SETFL(OFlag::empty()))?;
        let baud = 62500;
        let mut tio: libc::termios2 = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TCGETS2, &mut tio) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        tio.c_cflag &= !libc::CBAUD;
        tio.c_cflag |= libc::BOTHER;
        tio.c_ispeed = baud;
        tio.c_ospeed = baud;

        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TCSETS2, &tio) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Tkey {
            tkey: File::from(fd.try_clone()?),
            _fd: fd,
        })
    }
}
impl Read for Tkey {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tkey.read(buf)
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.tkey.read_exact(buf)
    }
}
impl Write for Tkey {
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.tkey.write_all(buf)
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tkey.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.tkey.flush()
    }
}
impl Deref for Tkey {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.tkey
    }
}
impl DerefMut for Tkey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tkey
    }
}
//lets SerialPort ops work with ClientError
impl From<std::io::Error> for ClientError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}
// helper func takes in port and gives either CLientMessage or ClientError caller chooses how to proceed.
pub fn check_status(port: &mut Tkey) -> Result<ClientMessage, ClientError> {
    let mut status_byte = [0u8; 1];
    port.read_exact(&mut status_byte)?;
    ClientMessage::try_from(status_byte[0])
}

// takes in nonce interfaces with TPM asks to sign nonce and gets sig back.
// # Errors
// when PCRs don't match or fails to communicate with TPM properly
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

    let tss_esapi::structures::Signature::EcDsa(ecdsa) = signature else {
        return Err("unexpected TPM signature type".into());
    };
    let mut sig_bytes = [0u8; 64];
    let r = ecdsa.signature_r().value();
    let s = ecdsa.signature_s().value();
    if r.len() > 32 || s.len() > 32 {
        Err(HostErr::TpmError)?;
    }
    // Left-pad into 32-byte slots (TPM might strip leading zeros)
    sig_bytes[32 - r.len()..32].copy_from_slice(r);
    sig_bytes[64 - s.len()..].copy_from_slice(s);
    Ok(sig_bytes)
}

// WIP.
pub fn get_key_seed() -> Result<[u8; 32], Box<dyn Error>> {
    let mut context = Context::new(TctiNameConf::from_str("device:/dev/tpmrm0")?)?;

    let session = context
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
    let policy_sess = PolicySession::try_from(session)?;
    context.policy_pcr(policy_sess, Digest::default(), pcr_selection)?;
    let tpm_handle = TpmHandle::try_from(0x8100_0002u32)?;
    let _key_handle = context.tr_from_tpm_public(tpm_handle)?;

    let seed_bytes = [0u8; 32];
    Ok(seed_bytes)
}

//make sure argon2 is consistent accross files provides sane defaults.
//this would only slowdown bruteforcing in a scenario where an attacker successfully extracted CDI
//from Tkey trough a vulnerability which is extremely unlikely so parameters are kept fast for
//better UX.
pub fn get_argon2() -> Argon2<'static> {
    let params = Params::new(13107, 1, 4, None).expect("hardcoded argon2 params are wrong.");
    Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params)
}

// authenticates with TPM and Tkey in paralel
pub fn auth_with_tkey_and_tpm(
    bin: Vec<u8>,
) -> Result<(Tkey, bool, ChaCha20Cipher), Box<dyn Error>> {
    let mut tkey = Tkey::new()?;
    load_app(&mut tkey, bin.as_slice())?;
    let mut nonce = [0u8; 32];
    tkey.read_exact(&mut nonce)?;
    //both TPM and Tkey are pretty slow so this saves a bit of time (kinda important here for UX)
    let verify_thread = thread::spawn(move || -> Result<[u8; 64], String> {
        verify(&nonce).map_err(|e| e.to_string())
    });

    let cipher = get_chacha20_cipher(&mut tkey)?;

    let mut trustworthy = match verify_thread.join().map_err(|e| format!("err {e:?}"))? {
        Ok(sig) => {
            tkey.write_all(&[HostMessage::TpmSigned as u8])?;
            tkey.write_all(&sig)?;
            true
        }
        Err(e) => {
            eprintln!("ERR: {e}");
            eprintln!("tpm REFUSED, to sign nonce");
            tkey.write_all(&[HostErr::TpmRefusedToSign as u8])?;
            false
        }
    };
    match check_status(&mut tkey) {
        Ok(ClientMessage::GoodSig) => println!(
            "tkey successfully authenticated with tpm (ALWAYS make sure tkey light is green before proceeding with passphrase.)"
        ),
        Err(e @ (ClientError::InvalidSig | ClientError::MalformedSig | ClientError::BadPubkey)) => {
            eprintln!("{}", e);
            eprintln!("tkey FAILED to verify nonce signature, system is considered untrustworthy.");
            trustworthy = false;
        }
        _ => return Err(ClientError::OutOfsync)?,
    }
    Ok((tkey, trustworthy, cipher))
}

// loads client app onto tkey.
//# Errors
//when tkey is already on app mode
//or binary gets corrupted on the way to tkeybinary gets corrupted on the way to tkey
pub fn load_app(tkey: &mut Tkey, bin: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut hasher = Blake2s256::new();
    let bin_len: u32 = bin.len() as u32;
    let tag: u8 = 0;
    let domain: u8 = 2;
    let len_code: u8 = 3;
    let header = (tag << 5) | (domain << 3) | len_code;
    tkey.write_all(&[header])?;
    tkey.write_all(&[0x03])?;
    tkey.write_all(&bin_len.to_le_bytes())?;
    //empty USS since we don't trust system to send it USS yet
    tkey.write_all(&[0u8])?;
    tkey.write_all(&[0u8; 32])?;
    //padding
    tkey.write_all(&[0u8; 90])?;
    let mut resp = [0u8; 5];
    tkey.read_exact(&mut resp)?;
    if resp[2] != 0 {
        Err("tkey rejected load_app request..")?;
    }
    let total = bin_len.div_ceil(127) as usize;
    for (i, bytes) in bin.chunks(127).enumerate() {
        let mut frame = [0u8; 129];
        frame[0] = header;
        frame[1] = 0x05;
        frame[2..2 + bytes.len()].copy_from_slice(bytes);
        tkey.write_all(&frame)?;
        if i == total - 1 {
            let mut resp = [0u8; 129];
            tkey.read_exact(&mut resp)?;
            hasher.update(&frame[2..2 + bytes.len()]);
            let hash = hasher.finalize();
            if resp[3..35] == hash[..32] {
                return Ok(());
            }
            Err("binary digests do not match, must restart app")?;
            break;
        }
        hasher.update(&frame[2..2 + bytes.len()]);
        let mut resp = [0u8; 5];
        tkey.read_exact(&mut resp)?;
        if resp[2] != 0 {
            return Err("TKey rejected a chunk (STATUS_BAD)".into());
        }
    }
    Ok(())
}
// communicates with tkey to get SS trough assymetric crypto (X25519)
// # Errors
// if we fail to communicate with tkey. e.g gets unplugged (shouldn't Error)
pub fn get_chacha20_cipher(
    tkey: &mut Tkey,
) -> Result<StreamCipherCoreWrapper<ChaChaCore<R20, Ietf>>, Box<dyn Error>> {
    let mut encryption_nonce = [0u8; 12];
    tkey.read_exact(&mut encryption_nonce)?;

    //TODO: take seed from TPM sealed object
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;

    let mut rng = ChaCha20Rng::from_seed(seed);
    let host_secret = EphemeralSecret::random_from_rng(&mut rng);
    let host_pub = PublicKey::from(&host_secret);
    tkey.write_all(host_pub.as_bytes())?;
    let mut tkey_pub_bytes = [0u8; 32];
    tkey.read_exact(&mut tkey_pub_bytes)?;
    let tkey_pub = PublicKey::from(tkey_pub_bytes);
    let ss = host_secret.diffie_hellman(&tkey_pub);
    let cipher = ChaCha20::new_from_slices(ss.as_bytes(), &encryption_nonce)?;
    Ok(cipher)
}
