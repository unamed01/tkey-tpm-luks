#![no_std]
#![no_main]

// this takes generates nonce sends nonce over the wire then takes in signature note this should is
// intentionally outside of measured PCR values this is fine since cdi =
// blake2s(uds + blake2s(app_bytes)) so if this app ever changes even correct passphrase cant unlock
// disk.
use core::arch::global_asm;
use core::ptr;
use core::sync::atomic::{self, Ordering};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use rustkey::io::{read_into, write_u8};
use rustkey::led::{LED_GREEN, LED_OFF, LED_PURPLE, LED_YELLOW, set};
use rustkey::timer::sleep;
use rustkey::touch::request;
use rustkey::{blake2s, done, random, read_cdi};

// Entry point: zero all registers, init stack, zero BSS, call main.
// Taken directly from the rusTkey README.
global_asm!(
    ".section \".text.init\"",
    ".global _start",
    "_start:",
    "li x1, 0",
    "li x2, 0",
    "li x3, 0",
    "li x4, 0",
    "li x5, 0",
    "li x6, 0",
    "li x7, 0",
    "li x8, 0",
    "li x9, 0",
    "li x10,0",
    "li x11,0",
    "li x12,0",
    "li x13,0",
    "li x14,0",
    "li x15,0",
    "li x16,0",
    "li x17,0",
    "li x18,0",
    "li x19,0",
    "li x20,0",
    "li x21,0",
    "li x22,0",
    "li x23,0",
    "li x24,0",
    "li x25,0",
    "li x26,0",
    "li x27,0",
    "li x28,0",
    "li x29,0",
    "li x30,0",
    "li x31,0",
    "la sp, _stack_start",
    "la a0, _sbss",
    "la a1, _ebss",
    "bge a0, a1, end_init_bss",
    "loop_init_bss:",
    "sw zero, 0(a0)",
    "addi a0, a0, 4",
    "blt a0, a1, loop_init_bss",
    "end_init_bss:",
    "call main",
    options(raw)
);

#[repr(u8)]
pub enum HostMessage {
    DecryptionSuccess = 0x99,
    DecryptionError = 0x98,
    TpmSigned = 0x97,
    //only error here
    TpmRefusedToSign = 0x90,
}

#[repr(u8)]
pub enum ClientMessage {
    GoodSig = 0x20,
    GoodPass = 0x21,
    Ready4pass = 0x22,
}

#[repr(u8)]
pub enum ClientError {
    Blake2 = 0x10,
    PassLen = 0x11,
    MalformedSig = 0x12,
    InvalidSig = 0x13,
    BadPubkey = 0x14,
    IOError = 0x15,
    UnknownError,
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    rustkey::abort()
}

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    match verify_sig() {
        Ok(_) => set(LED_GREEN),
        //this is shouldn't happen unless user renerolled to new PCR values before updating client app
        //should be way more caitious when you see purple vs yellow host might be trying to give a bad signature or replay an old one
        Err(ClientError::InvalidSig) => {
            write_u8(ClientError::InvalidSig as u8);
            if !request(30, LED_PURPLE) {
                panic!()
            }
        }
        // allows updates which change relevant PCR values and decryption on another clean system after tampering was detected
        // while trying its best to prevent social engineering attacks against a untrustworthy system
        // yellow LED is choosen to make it easily distinguishable from a panic which flashes red
        Err(e) => {
            write_u8(e as u8);
            if !request(30, LED_YELLOW) {
                panic!()
            }
        }
    }
    let mut attempts = 0;
    loop {
        if attempts >= 3 {
            rustkey::abort()
        }
        attempts += 1;
        //signal to host were ready for passphrase
        write_u8(ClientMessage::Ready4pass as u8);
        let mut len_buf = [0u8; 1];
        read_into(&mut len_buf);
        let pass_len: u8 = len_buf[0];
        if pass_len < 8 {
            write_u8(ClientError::PassLen as u8);
            let mut drain = [0u8; 256];
            read_into(&mut drain[..pass_len as usize]);
            sleep(3);
            continue;
        };
        let mut passphrase = [0u8; 256];
        read_into(&mut passphrase[..pass_len as usize]);
        let mut keyfile = [0u8; 32];
        let mut cdi = read_cdi();
        match blake2s(&mut keyfile, &cdi, &passphrase[..pass_len as usize]) {
            Ok(_) => {}
            Err(_) => {
                zeroize(&mut cdi);
                zeroize(&mut passphrase);
                zeroize(&mut keyfile);
                write_u8(ClientError::Blake2 as u8);
                sleep(3);
                continue;
            }
        }
        zeroize(&mut passphrase);
        write_u8(ClientMessage::GoodPass as u8);
        write_u8_slice(&keyfile);
        zeroize(&mut keyfile);
        zeroize(&mut cdi);
        let mut success = [0u8; 1];
        read_into(&mut success);
        if success[0] == HostMessage::DecryptionSuccess as u8 {
            break;
        }
        sleep(3);
    }
    set(LED_GREEN);
    sleep(6);
    set(LED_OFF);
    done()
}

fn verify_sig() -> Result<(), ClientError> {
    //shouldnt fail since we've checked pubkey at compile time
    let tpm_pubkey = VerifyingKey::from_public_key_der(include_bytes!("../../tpm_pubkey_raw.bin"))
        .map_err(|_| ClientError::BadPubkey)?;
    let mut nonce = [0u8; 32];
    random(&mut nonce, b"");
    write_u8_slice(&nonce);
    let mut status = [0u8; 1];
    read_into(&mut status);
    if status[0] == HostMessage::TpmSigned as u8 {
        let mut sig = [0u8; 64];
        read_into(&mut sig);
        let sig = Signature::try_from(&sig[..]).map_err(|_| ClientError::MalformedSig)?;
        tpm_pubkey
            .verify(&nonce, &sig)
            .map_err(|_| ClientError::InvalidSig)?;
        write_u8(ClientMessage::GoodSig as u8);
        Ok(())
    } else {
        Err(ClientError::InvalidSig)
    }
}

//helper func to write any byte slice onto host
fn write_u8_slice(slice: &[u8]) {
    for b in slice.iter() {
        write_u8(*b);
    }
}
//"custom" zeroize func since zeroize requires global alloc. this is functionally equivalent to .zeroize()
fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe { ptr::write_volatile(byte, 0) };
    }
    atomic::compiler_fence(Ordering::SeqCst);
}
