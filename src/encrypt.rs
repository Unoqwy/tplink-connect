use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

use openssl::bn::{BigNum, BigNumContext};

const RSA_BIT: usize = 512;
const STR_DE_LEN: usize = RSA_BIT / 8;

pub fn rsa_encrypt(s: String, n: String, e: String) -> String {
    let (n, e) = (BigNum::from_hex_str(&n).unwrap(),
        BigNum::from_hex_str(&e).unwrap());

    let step = STR_DE_LEN;
    let (mut start_length, mut end_length) = (0, step);
    let mut out = String::new();

    let mut bn_ctx = BigNumContext::new().unwrap();
    while start_length < s.len() {
        if s.len() < end_length {
            end_length = s.len();
        }

        let val = &s[start_length..end_length];
        let m = rsa_no_padding(val.to_owned(), (n.num_bits() + 7 >> 3) as usize);
        let mut bn = BigNum::new().unwrap();
        bn.mod_exp(&m, &e, &n, &mut bn_ctx).unwrap();
        let mut h = bn.to_hex_str().unwrap().to_string();
        if (1 & h.len()) != 0 {
            h = format!("0{}", h);
        }
        out.push_str(&h);

        start_length += step; end_length += step;
    }

    out.to_lowercase()
}

fn rsa_no_padding(s: String, n: usize) -> BigNum {
    // for (var ba = new Array, i = 0, j = 0; i < s.length && j < n; ) {
    //   var c = s.charCodeAt(i++);
    //   c < 128 ?
    //     ba[j++] = c
    //   : c > 127 && c < 2048 ?
    //       (ba[j++] = 63 & c | 128, ba[j++] = c >> 6 | 192)
    //     :
    //       (ba[j++] = 63 & c | 128, ba[j++] = c >> 6 & 63 | 128, ba[j++] = c >> 12 | 224)
    // }

    if n < s.len() {
        panic!("Message too long for RSA");
    }

    let mut ba = vec![0; n];
    let (mut i, mut j) = (0, 0);
    while i < s.len() && j < n {
        let c = s.chars().nth(i).unwrap() as u32; i += 1;
        if c < 128 {
            ba[j] = c; j += 1;
        } else if c > 127 && c < 2048 {
            ba[j] = 63 & c | 128; j += 1;
            ba[j] = c >> 6 | 192; j += 1;
        } else {
            ba[j] = 63 & c | 128; j += 1;
            ba[j] = c >> 6 & 63 | 128; j += 1;
            ba[j] = c >> 12 | 224; j += 1;
        }
    }

    to_bignum(ba)
}

fn to_bignum(ba: Vec<u32>) -> BigNum {
    let ba_bytes: Vec<u8> = ba.iter()
        .map(|&x| (255 & x) as u8)
        .collect();
    BigNum::from_slice(&ba_bytes).unwrap()
}

type Aes128CBC = Cbc<Aes128, Pkcs7>;

pub fn aes_encrypt(value: String, aes_key: &str, aes_iv: &str) -> String {
    let data = value.as_bytes();
    let (key, iv) = (aes_key.as_bytes(), aes_iv.as_bytes());
    let cipher = Aes128CBC::new_var(&key, &iv).unwrap();

    let pos = value.len();
    let mut buffer = [0u8; 4096];
    buffer[..pos].copy_from_slice(data);
    base64::encode(cipher.encrypt(&mut buffer, pos).unwrap())
}

pub fn aes_decrypt(value: String, aes_key: &str, aes_iv: &str) -> String {
    let (key, iv) = (aes_key.as_bytes(), aes_iv.as_bytes());
    let cipher = Aes128CBC::new_var(&key, &iv).unwrap();

    let mut buf = (base64::decode(value)).unwrap().to_vec();
    std::str::from_utf8(cipher.decrypt(&mut buf).unwrap()).unwrap().to_owned()
}

#[cfg(test)]
mod tests {
    use crate::encrypt;

    #[test]
    fn bignum_conversion() {
        let input = vec![107,101,121,61,49,54,48,55,56,53,55,52,53,50,52,48 ,
                56,57,52,56,38,105,118,61,49,54,48,55,56,53,55,52,53,50,52  ,
                48,56,49,50,49,38,104,61,98,48,102,51,48,48,52,52,101,57,100,
                52,53,98,56,48,57,53,99,50,53];
        let bn = encrypt::to_bignum(input);
        let expected = "6b65793d313630373835373435323430383934382669763d3136303738353734353234303831323126683d623066333030343465396434356238303935633235";
        assert_eq!(bn.to_hex_str().unwrap().to_lowercase(), expected);
    }

    #[test]
    fn rsa_encrypt() {
        let val = "key=1607857452408948&iv=1607857452408121&h=b0f30044e9d45b8095c25468c6aa2b54&s=135956297";
        let n = "B4C117C503E3DFCDFF1B0BBD10F0612BA0DED48A22BE3B7CD2D7E2C3B62BBC97BE91CA41E74AA8BCF0FDE4C120A7387AD69FEA49674286D9F8EB910714BA3A39";
        let e = "010001";

        let expected = "0909446e1b0372478eb3de14e9ba1151c3ab506c538a1c9862dfccde2a0e47e669261311d729c6e030d22ae3472a1b2b8f593fc38d9bf4ff42ae77ce208e59631d754a4d7a921d1617d378386462e09a85d850c152b85101bd3349ef7293f5b9bd43c1cf36e9dd0b5f888b1da1f7d048b3533464409769761e9620a401cc4b2b";
        assert_eq!(encrypt::rsa_encrypt(val.to_owned(), n.to_owned(), e.to_owned()).to_lowercase(), expected);
    }

    #[test]
    fn aes_encrypt_decrypt() {
        let val = "admin\npasswd";
        let (key, iv) = ("1607865228488414", "1607865228488863");

        let encrypted = encrypt::aes_encrypt(val.to_owned(), key, iv);
        assert_eq!(encrypted, "4A4RiszghWRdlrFF3ovRnQ==");
        assert_eq!(encrypt::aes_decrypt(encrypted, key, iv), val);
    }

}

