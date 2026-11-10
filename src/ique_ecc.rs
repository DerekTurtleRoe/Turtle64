//! Minimal sect233r1 (NIST B-233) ECDH, used to derive the "titlekek" that
//! protects non-SA iQue title keys.
//!
//! Independent implementation from the public SEC 2 v2.0 domain parameters;
//! favours clarity over speed (a single ECDH takes a few milliseconds).
//! Key layout per the iQueBrew Virage2 and Ticket pages: 32-byte private key,
//! 64-byte public key (x then y, each 32 bytes big-endian, zero-padded).

use anyhow::{bail, Result};

/// A GF(2^233) element: bit `i` is the coefficient of x^i, little-endian limbs.
type E = [u64; 4];

const ZERO: E = [0; 4];
const ONE: E = [1, 0, 0, 0];
const M: usize = 233;

fn from_be(b: &[u8]) -> E {
    let mut e = ZERO;
    for (i, chunk) in b.as_chunks::<8>().0.iter().enumerate() {
        e[3 - i] = u64::from_be_bytes(*chunk);
    }
    e
}

fn to_be(e: &E) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&e[3 - i].to_be_bytes());
    }
    out
}

fn from_hex(s: &str) -> E {
    let padded = format!("{s:0>64}");
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).unwrap()).collect();
    from_be(&bytes)
}

fn in_field(e: &E) -> bool {
    e[3] >> (M - 192) == 0
}

fn bit(e: &E, i: usize) -> bool {
    (e[i / 64] >> (i % 64)) & 1 == 1
}

fn add(a: &E, b: &E) -> E {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

/// Multiplies by x and reduces modulo x^233 + x^74 + 1.
fn mul_x(a: &E) -> E {
    let mut r = [a[0] << 1, a[1] << 1 | a[0] >> 63, a[2] << 1 | a[1] >> 63, a[3] << 1 | a[2] >> 63];
    if bit(&r, M) {
        r[3] &= !(1u64 << (M - 192));
        r[1] ^= 1 << (74 - 64);
        r[0] ^= 1;
    }
    r
}

fn mul(a: &E, b: &E) -> E {
    let (mut acc, mut shifted) = (ZERO, *a);
    for i in 0..M {
        if bit(b, i) {
            acc = add(&acc, &shifted);
        }
        shifted = mul_x(&shifted);
    }
    acc
}

/// a^-1 = a^(2^233 - 2), by Fermat's little theorem for GF(2^m).
fn inv(a: &E) -> E {
    let (mut r, mut t) = (ONE, *a);
    for _ in 1..M {
        t = mul(&t, &t);
        r = mul(&r, &t);
    }
    r
}

#[derive(Clone, Copy, PartialEq)]
struct Point {
    x: E,
    y: E,
}

struct Curve {
    b: E,
    #[cfg_attr(not(test), allow(dead_code))]
    g: Point,
    #[cfg_attr(not(test), allow(dead_code))]
    n: E,
}

fn curve() -> Curve {
    Curve {
        b: from_hex("0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD"),
        g: Point {
            x: from_hex("00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B"),
            y: from_hex("01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052"),
        },
        n: from_hex("01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7"),
    }
}

/// `None` is the point at infinity. Curve: y^2 + xy = x^3 + x^2 + b.
fn point_add(p: Option<Point>, q: Option<Point>) -> Option<Point> {
    let (p, q) = match (p, q) {
        (None, r) | (r, None) => return r,
        (Some(p), Some(q)) => (p, q),
    };
    let lambda = if p.x == q.x {
        if p.y != q.y || p.x == ZERO {
            return None;
        }
        add(&p.x, &mul(&p.y, &inv(&p.x)))
    } else {
        mul(&add(&p.y, &q.y), &inv(&add(&p.x, &q.x)))
    };
    let x = if p.x == q.x {
        add(&add(&mul(&lambda, &lambda), &lambda), &ONE)
    } else {
        add(&add(&add(&add(&mul(&lambda, &lambda), &lambda), &p.x), &q.x), &ONE)
    };
    let y =
        if p.x == q.x { add(&add(&mul(&p.x, &p.x), &mul(&lambda, &x)), &x) } else { add(&add(&mul(&lambda, &add(&p.x, &x)), &x), &p.y) };
    Some(Point { x, y })
}

fn scalar_mul(k: &E, p: Point) -> Option<Point> {
    let (mut acc, mut addend) = (None, Some(p));
    for i in 0..M {
        if bit(k, i) {
            acc = point_add(acc, addend);
        }
        addend = point_add(addend, addend);
    }
    acc
}

fn on_curve(c: &Curve, p: &Point) -> bool {
    let lhs = add(&mul(&p.y, &p.y), &mul(&p.x, &p.y));
    let xx = mul(&p.x, &p.x);
    let rhs = add(&mul(&xx, &add(&p.x, &ONE)), &c.b);
    lhs == rhs
}

/// ECDH on sect233r1. Returns the 16-byte titlekek: bytes 4..20 of the shared
/// point's 32-byte big-endian x coordinate (the layout the iQue uses).
pub fn titlekek(private_key: &[u8], public_key: &[u8]) -> Result<[u8; 16]> {
    if private_key.len() != 32 || public_key.len() != 64 {
        bail!("ECC private key must be 32 bytes and public key 64 bytes");
    }
    let c = curve();
    let k = from_be(private_key);
    let q = Point { x: from_be(&public_key[..32]), y: from_be(&public_key[32..]) };
    if !in_field(&k) || k == ZERO {
        bail!("ECC private key is zero or out of range");
    }
    if !in_field(&q.x) || !in_field(&q.y) || !on_curve(&c, &q) {
        bail!("ECC public key is not a valid point on sect233r1");
    }
    let Some(shared) = scalar_mul(&k, q) else { bail!("ECDH produced the point at infinity") };
    Ok(to_be(&shared.x)[4..20].try_into().unwrap())
}

#[cfg(test)]
pub fn public_key(private_key: &[u8; 32]) -> [u8; 64] {
    let p = scalar_mul(&from_be(private_key), curve().g).unwrap();
    [to_be(&p.x), to_be(&p.y)].concat().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(n: u64) -> E {
        [n, 0, 0, 0]
    }

    #[test]
    fn generator_is_on_curve_and_has_order_n() {
        let c = curve();
        assert!(on_curve(&c, &c.g));
        // n*G must be the point at infinity, which also validates every parameter.
        assert!(scalar_mul(&c.n, c.g).is_none());
        assert!(scalar_mul(&scalar(2), c.g).is_some());
    }

    #[test]
    fn field_inverse() {
        let a = from_hex("1234567890ABCDEF1234567890ABCDEF");
        assert_eq!(mul(&a, &inv(&a)), ONE);
    }

    #[test]
    fn diffie_hellman_agrees() {
        let c = curve();
        let (a, b) = (from_hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"), from_hex("FEDCBA9876543210FEDCBA9876543210FEDCBA98"));
        let pa = scalar_mul(&a, c.g).unwrap();
        let pb = scalar_mul(&b, c.g).unwrap();
        let (pa_be, pb_be) = ([to_be(&pa.x), to_be(&pa.y)].concat(), [to_be(&pb.x), to_be(&pb.y)].concat());
        let k1 = titlekek(&to_be(&a), &pb_be).unwrap();
        let k2 = titlekek(&to_be(&b), &pa_be).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn matches_openssl_sect233r1_ecdh() {
        // Synthetic keys generated and derived independently with OpenSSL.
        let private = to_be(&from_hex("000000ca30ed8850fa1f9187a966030771d67b0c954385b3564fa75296a232a5"));
        let x = to_be(&from_hex("00000109e1c9c3da86f3094ea7745a8e7780084007fb5204cff1f87b0d63d3b0"));
        let y = to_be(&from_hex("0000016b5061215fdc6647039b58b7a57ce8078be72d1af54233a997a575b9d2"));
        let public = [x, y].concat();
        assert_eq!(
            titlekek(&private, &public).unwrap(),
            [0xb0, 0x55, 0x14, 0xdd, 0xe1, 0xa3, 0x7e, 0x91, 0x68, 0x52, 0xf5, 0x78, 0xe5, 0xf1, 0x41, 0x4a]
        );
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(titlekek(&[1; 31], &[0; 64]).is_err());
        assert!(titlekek(&[0; 32], &[0; 64]).is_err());
        let mut off_curve = [0u8; 64];
        off_curve[31] = 1;
        off_curve[63] = 1;
        assert!(titlekek(&to_be(&scalar(5)), &off_curve).is_err());
    }
}
