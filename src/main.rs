use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

enum Secret {
    Encoded(String),
    Raw(Vec<u8>),
}

impl Secret {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Secret::Encoded(s) => {
                base32::decode(base32::Alphabet::RFC4648 { padding: false }, s).unwrap()
            }
            Secret::Raw(v) => v.clone(),
        }
    }

    fn encode(&self) -> String {
        match self {
            Secret::Encoded(s) => s.clone(),
            Secret::Raw(v) => base32::encode(base32::Alphabet::RFC4648 { padding: false }, v),
        }
    }
}

struct totp {
    secret: Vec<u8>,
    time_step: u64,
    length: u64,
    algorithm: Algorithm,
    skew: u64,
    label: Option<String>,
    url: Option<String>,
}

impl totp {
    fn new(
        secret: Vec<u8>,
        time_step: u64,
        length: u64,
        algorithm: Algorithm,
        skew: u64,
        label: Option<String>,
        url: Option<String>,
    ) -> Self {
        totp {
            secret,
            time_step,
            length,
            algorithm,
            skew,
            label,
            url,
        }
    }

    fn generate_now(&self) -> String {
        let time = system_time();
        self.generate(time, self.secret.clone())
    }

    fn generate(&self, time: u64, key: Vec<u8>) -> String {
        let time_step = (time / self.time_step).to_be_bytes();
        let result = self.algorithm.hmac(key, &time_step);

        let offset = (result.last().unwrap() & 15) as usize;
        let otp = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        let otp = otp % 10_u32.pow(self.length as u32);

        let code = format!("{:06}", otp);
        let code = code.chars().collect::<Vec<char>>();
        let code = format!(
            "{}{}{} {}{}{}",
            code[0], code[1], code[2], code[3], code[4], code[5]
        );
        code
    }
}

impl Algorithm {
    fn digest<H>(mut digest: H, data: &[u8]) -> Vec<u8>
    where
        H: Mac,
    {
        digest.update(&data);
        let result = digest.finalize().into_bytes().to_vec();
        result
    }

    fn hmac(&self, key: Vec<u8>, data: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::Sha1 => Algorithm::digest(HmacSha1::new_from_slice(&key).unwrap(), data),
            Algorithm::Sha256 => Algorithm::digest(HmacSha256::new_from_slice(&key).unwrap(), data),
            Algorithm::Sha512 => Algorithm::digest(HmacSha512::new_from_slice(&key).unwrap(), data),
        }
    }
}

fn system_time() -> u64 {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    time
}

fn main() {
    let key = "JBSWY3DPEHPK3PXP";
    let secret = Secret::Encoded(key.to_string()).to_bytes();
    let totp = totp::new(secret, 30, 6, Algorithm::Sha1, 0, None, None);
    let code = totp.generate_now();
    println!("{}", code);
}
