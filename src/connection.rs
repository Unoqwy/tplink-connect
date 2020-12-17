use crate::encrypt;

use regex::Regex;
use std::collections::HashMap;

use reqwest::header;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::blocking::Client;
use form_urlencoded;

use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;
use rand::rngs::OsRng;

use std::convert::TryFrom;

#[derive(Debug)]
pub enum Error {
    CannotCreateConnection,
    CannotLogin,
    MissingEncryptionData,
    MissingIdentificationHash,
    MissingToken,
    TokenNotFound,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct EncryptedConnection {
    address: String,
    pub client: Client,
    pub encryption: Option<EncryptionData>,

    token_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EncryptionData {
    pub seq: u32,
    pub rsa_n: String,
    pub rsa_e: String,
    pub aes_key: String,
    pub aes_iv: String,
    pub hash: Option<String>,
}

#[derive(Copy, Clone, Debug)]
pub enum ActType {
    GET = 1,
    //SET = 2,
    //ADD = 3,
    //DEL = 4,
    GL = 5,
    //GS = 6,
    //OP = 7,
    //CGI = 8,
}

impl TryFrom<u8> for ActType {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(ActType::GET),
            5 => Ok(ActType::GL),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ActRequest {
    pub act_type: ActType,
    pub oid: String,
    pub stack: Option<String>,
    pub p_stack: Option<String>,
    pub attrs: Vec<String>,
}

impl ActRequest {
    pub fn new(
        act_type: ActType, oid: &str,
        stack: Option<&str>, p_stack: Option<&str>,
        attrs: Vec<&str>,
    ) -> ActRequest {
        ActRequest {
            act_type,
            oid: oid.to_owned(),
            stack: if let Some(s) = stack { Some(s.to_owned()) } else { None },
            p_stack: if let Some(s) = p_stack { Some(s.to_owned()) } else { None },
            attrs: attrs.iter().map(|attr| attr.to_string()).collect(),
        }
    }

    pub fn new_short(act_type: ActType, oid: &str, attrs: Vec<&str>) -> ActRequest {
        ActRequest::new(act_type, oid, None, None, attrs)
    }
}

impl EncryptedConnection {
    pub fn new(address: String, client: Client) -> EncryptedConnection {
        EncryptedConnection {
            address,
            client,
            encryption: None,
            token_id: None,
        }
    }

    pub fn connect(router_address: &str, username: String, password: String) -> Result<EncryptedConnection> {
        let _conn = from_address(router_address);
        if _conn.is_err() {
            return Err(Error::CannotCreateConnection);
        }

        let mut conn = _conn.unwrap();
        conn.refresh_encryption();
        if conn.login(username, password).is_err() {
            return Err(Error::CannotLogin);
        }
        Ok(conn)
    }

    pub fn get_parm(&self) -> HashMap<String, String> {
        let mut values = HashMap::new();
        if let Some(res) = self.get("cgi/getParm") {
            let re = Regex::new(r##"var (\w+)="((?:[^"\\]|\\.)*)";"##).unwrap();
            for cap in re.captures_iter(&res) {
                values.insert(
                    cap.get(1).unwrap().as_str().to_owned(),
                    cap.get(2).unwrap().as_str().to_owned()
                );
            }
        }
        values
    }

    pub fn refresh_encryption(&mut self) {
        let current_hash = match &self.encryption {
            Some(encr) => encr.hash.clone(),
            None => None
        };
        let parm = self.get_parm();
        let millis = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Nice time machine").as_millis();
        let aes_key = &format!("{}{}", millis, OsRng.next_u32())[0..16];
        let aes_iv = &format!("{}{}", millis, OsRng.next_u32())[0..16];
        let encryption = EncryptionData {
            seq: get_or_def(&parm, "seq", "0")
                .parse().unwrap_or(0),
            rsa_n: get_or_def(&parm, "nn", "0"),
            rsa_e: get_or_def(&parm, "ee", "0"),
            aes_key: aes_key.to_owned(),
            aes_iv: aes_iv.to_owned(),
            hash: current_hash,
        };
        self.encryption = Some(encryption);
    }

    pub fn login(&mut self, username: String, password: String) -> Result<()> {
        if self.encryption.is_none() {
            return Err(Error::MissingEncryptionData);
        }

        let encryption = (&mut self.encryption).as_mut().unwrap();
        let hash_digest = md5::compute(format!("{}{}", username, password));
        encryption.hash = Some(format!("{:x}", hash_digest));

        // JS Prettified login script
            //
        // (void 0 == $.nn && getAuthParm(), 1 != loginFlag &&
        // (loginFlag = 1,
        // INCLUDE_LOGIN_GDPR_ENCRYPT ? (
        //   console.log("encrypted connection"),
        //   INCLUDE_LOGIN_USERNAME || (r = "admin"),
        //   $.Iencryptor.setHash(r, l),
        //   $.Iencryptor.genAESKey(),
        //   n = $.Iencryptor.AESEncrypt(r + "\n" + l, 1),
        //   $.newencryptorManager.recordEncryptor()
        // ) : (
        //   console.log("unencrypted further connection"),
        //   n = rsaEncrypt($.Base64Encoding(l), $.nn, $.ee),
        //   e = INCLUDE_LOGIN_USERNAME ?
        //     rsaEncrypt(r, $.nn, $.ee)
        //   :
        //     rsaEncrypt("admin", $.nn, $.ee)
        // ),
        // // doLogin
        // console.log(e, n, 1, o, o ? $("#ph-login-btn") : $("#pc-login-btn"))
        // )
        // )

        let encoded = get_login_url(self, username, password);
        let _ = self.client.post(&format!("{}/cgi/login?{}", self.address, encoded))
            .send();
        self.update_token()?;
        Ok(())
    }

    pub fn update_token(&mut self) -> Result<()> {
        let body = self.client.get(&self.address)
            .send().unwrap().text().unwrap();

        let re = Regex::new(r##"var token="([0-9a-f]*)";"##).unwrap();
        if let Some(caps) = re.captures(&body) {
            self.token_id = Some(caps.get(1).unwrap().as_str().to_owned());
            Ok(())
        } else {
            Err(Error::MissingToken)
        }
    }

    pub fn encrypt(&self, value: String, login: bool) -> Result<(String, String)> {
        if self.encryption.is_none() {
            return Err(Error::MissingEncryptionData);
        }
        let encryption = self.encryption.as_ref().unwrap().clone();
        if encryption.hash.is_none() {
            return Err(Error::MissingIdentificationHash);
        }

        let aes_out = encrypt::aes_encrypt(value, &encryption.aes_key, &encryption.aes_iv);
        let s = if login {
            format!("key={key}&iv={iv}&h={}&s={}", encryption.hash.unwrap(), encryption.seq + (aes_out.len() as u32),
                    key = encryption.aes_key, iv = encryption.aes_iv)
        } else {
            format!("h={}&s={}", encryption.hash.unwrap(), encryption.seq + (aes_out.len() as u32))
        };
        let signature = encrypt::rsa_encrypt(s, encryption.rsa_n, encryption.rsa_e);

        Ok((aes_out, signature))
    }

    pub fn get(&self, endpoint: &str) -> Option<String> {
        let res = self.client.get(&format!("{}/{}", self.address, endpoint)).send().ok()?;
        if res.status().is_success() {
            let body = res.text().ok()?;
            if !body.is_empty() {
                return Some(body);
            }
        }
        None
    }

    pub fn act(&self, requests: Vec<ActRequest>) -> Result<Vec<ActSection>> {
        if self.encryption.is_none() {
            return Err(Error::MissingEncryptionData);
        }
        if self.token_id.is_none() {
            return Err(Error::MissingToken);
        }
        let encryption = self.encryption.as_ref().unwrap();
        let token_id: &str = self.token_id.as_ref().unwrap();

        let (mut index, mut lines) = (0, Vec::new());
        for data_request in requests.iter() {
            // FIXME : length check
            lines.push(format!("[{oid}#{stack}#{pstack}]{index},{read}",
                    oid = data_request.oid, index = index, read = data_request.attrs.len(),
                    stack = data_request.stack.clone().unwrap_or(String::from("0,0,0,0,0,0")),
                    pstack = data_request.p_stack.clone().unwrap_or(String::from("0,0,0,0,0,0")),
            ));
            for attr in data_request.attrs.iter() {
                lines.push(attr.clone());
            }
            index += 1;
        }

        let header = requests.iter()
            .map(|req| format!("{}", req.act_type as u8))
            .collect::<Vec<String>>()
            .join("&");
        lines.insert(0, header);

        let mut req_body = String::new();
        for line in lines.iter() {
            req_body.push_str(&format!("{}\r\n", line));
        }

        if req_body.len() < 64 {
            // if the body length is less than 64, the router won't answer
            // so we add spaces after the header line to have at least 64 chars
            req_body = req_body.splitn(2, "\r\n")
                .collect::<Vec<&str>>()
                .join(&(" ".repeat(64 - req_body.len()) + "\r\n"));
        }

        let encrypted_body = self.encrypt(req_body, false)?;
        let body = format!("sign={}\r\ndata={}\r\n", encrypted_body.1, encrypted_body.0);
        let res = self.client.post(&format!("{}/cgi_gdpr", self.address))
            .header(HeaderName::from_static("tokenid"), HeaderValue::from_str(token_id).unwrap())
            .body(body)
            .send().unwrap();

        let response = encrypt::aes_decrypt(res.text().unwrap(), &encryption.aes_key, &encryption.aes_iv);

        // FIXME: move this in a lazy_static
        let re = Regex::new(r"\[(?:\d,?){6}\](\d+)").unwrap();

        // FIXME: handle errors
        let mut sections_out = vec![ActSection::None; requests.len()];
        let mut section: Option<ActSection> = None;
        let mut section_index = 0;
        for line in response.lines() {
            if let Some(caps) = re.captures(line) {
                if let Some(section) = section {
                    sections_out.insert(section_index, section);
                }

                section_index = caps.get(1).unwrap().as_str().parse().unwrap();
                if sections_out.len() > index {
                    section = Some(sections_out.remove(section_index));
                } else {
                    section = match requests[section_index].act_type {
                        // FIXME: support list
                        ActType::GET | ActType::GL => Some(ActSection::KeyValue(HashMap::new())),
                        _ => None
                    }
                }
            } else if let Some(section) = &mut section {
                match section {
                    ActSection::KeyValue(map) => {
                        let section_elts = line.splitn(2, "=")
                            .map(|s| s.to_owned())
                            .collect::<Vec<String>>();
                        if section_elts.len() == 2 {
                            map.insert(section_elts[0].clone(), section_elts[1].clone());
                        }
                    },
                    _ => {}
                }
            }
        }
        if let Some(section) = section {
            sections_out.insert(section_index, section);
        }

        Ok(sections_out)
    }
}

#[derive(Clone, Debug)]
pub enum ActSection {
    None,
    KeyValue(HashMap<String, String>),
}

impl ActSection {
    pub fn to_map(&self) -> HashMap<String, String> {
        match self {
            ActSection::KeyValue(map) => map.clone(),
            _ => HashMap::new()
        }
    }
}

fn get_or_def(parm: &HashMap<String, String>, key: &str, default: &str) -> String {
    if let Some(value) = parm.get(&key.to_owned()) {
        return (*value).to_owned();
    } else {
        default.to_owned()
    }
}

pub fn from_address(router_address: &str) -> Result<EncryptedConnection, Box<dyn std::error::Error>> {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip/deflate"));
    headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    headers.insert(header::ORIGIN, HeaderValue::from_str(router_address)?);
    headers.insert(header::REFERER, HeaderValue::from_str(format!("{}/", router_address).as_str())?);

    let client = Client::builder()
        .cookie_store(true)
        .user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0")
        .default_headers(headers)
        .build()?;

    Ok(EncryptedConnection::new(router_address.to_owned(), client))
}

fn get_login_url(conn: &EncryptedConnection, username: String, password: String) -> String {
    let encrypted = conn.encrypt(format!("{}\n{}", username, password), true).unwrap();
    form_urlencoded::Serializer::new(String::new())
        .append_pair("data", encrypted.0.as_str())
        .append_pair("sign", encrypted.1.as_str())
        .append_pair("Action", "1")
        .append_pair("LoginStatus", "0")
        .finish()
}

#[cfg(test)]
mod tests {
    use crate::connection::*;

    #[test]
    fn login_data() {
        let mut conn = from_address("http://192.168.1.1").unwrap();
        let encryption = EncryptionData {
            seq: 440387683,
            rsa_e: "010001".to_owned(),
            rsa_n: "D2C11D9A101BFC1C138B8B9F226D3BB290291D8F29B602505D2110F91B24564C567BB9272EF455BF0041172A56E66CD69C22F31797A810363E81A4FDB850314B".to_owned(),
            aes_key: "1607883708455267".to_owned(),
            aes_iv: "1607883708455690".to_owned(),
            hash: Some("89088dc0047cf877395138c3d9041ca0".to_owned()),
        };
        conn.encryption = Some(encryption);
        let expected = "data=dHkw0h%2BvxGNO0gvpRT92Kg%3D%3D&sign=a4664eb9370e16366ade1ef8cda3090fbd4fca8d3a3b28d97f805b2a4529b58710480059a5fbaddbc40daf6b175261b3d72de42dcb5b276932ea0314ea07e5c1690523c25f73795592244d0897d99816ae48b57d76402eb2b46ffe143524fd5fbc183f9b5879fc8d4c38c59d25e287df70034e48361125273a1ce2149598db01&Action=1&LoginStatus=0";
        assert_eq!(get_login_url(&conn, "admin".to_owned(), "passwd".to_owned()), expected);
    }

}

