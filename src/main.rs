use actix_web::web::ReqData;
use actix_web::{middleware, web, App, post, HttpResponse, HttpServer, Responder, http::{header, StatusCode}};
use actix_web_middleware_keycloak_auth::{Claims, DecodingKey, KeycloakAuth, Role};
use serde::{Serialize, Deserialize};
use awc::{self};
use serde_json::Value;

const KEYCLOAK_PK: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgjxDaoGghFwAkdoo8YqoF4rVhZVmbkNTXrqDba47muKCnaULzlzOK2n//bB9Twaa/yxZ0cwli2vqsci1cNKQNh3zZjlLjeK6lEc/iDQvPLXad8/rRqj3ZgH+01YscOZBGdVq2GAOL+WYr3bhLD6yNiUOHXJQYrRoekfMYiQRmvV+c1/eXjFEbcqwOxKGxZ6CPIwWCEjPjwW2Hp8E4Ap518bzlKie491OJ9bkjAGf/6qhM/faf7Sx99Bhq8tk/d1fVZSCkW+MP+by/EyAruOS/0KEzHU6ERSp6gtoQ9AFYdYSv/J5/fYzWnuDemTWOy7GmUrdJI8D1CDmNKVgdYPDFwIDAQAB
-----END PUBLIC KEY-----";
/*
Associated private key is:
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----
*/

#[derive(Serialize, Deserialize, Debug)]
enum ContentType {
    URLENCODED,
    JSON
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match *self {
            ContentType::JSON => "application/json",
            ContentType::URLENCODED => "application/x-www-form-urlencoded",
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Input<T> {
    data: T
}

#[derive(Serialize, Deserialize, Debug)]
struct Credentials {
    grant_type: String,
    client_id: String,
    username: String,
    password: String,
    scope: String
}

#[derive(Serialize)]
struct SimpleResponse {
    code: u16,
    message: String
}

#[post("auth_request")]
async fn auth_request(req_body: String) -> impl Responder {
    
    let req_data: Input<Credentials> = match serde_json::from_str(&req_body) {
        Ok(body) => {
            body 
        },
        Err(e) => return web::Json(
            SimpleResponse {
                code: StatusCode::BAD_REQUEST.as_u16(),
                message: e.to_string()
            }
        )
    };
    
    println!("{:?}", req_data);

    let url = "http://0.0.0.0:8080/auth/realms/Surgarfunge/protocol/openid-connect/token";

    let credentials = web::Data::new(req_data.data);

    let awc_client = awc::Client::new();

    let response = 
        awc_client.post(url)
            .header(header::CONTENT_TYPE, ContentType::URLENCODED.as_str())
            .send_form(&credentials.into_inner())
            .await;

    // println!("Response {:?}", response);

    match response {
        Ok(mut response) => {
            let body_str: String = std::str::from_utf8(&response.body().await.unwrap()).unwrap().to_string();
            let body: Value = serde_json::from_str(&body_str).unwrap();

            match response.status() {
                StatusCode::OK => {
                    println!("{:?}", body["access_token"]);
                    web::Json(
                    SimpleResponse {
                        code: StatusCode::OK.as_u16(),
                        message: body["access_token"].to_string()
                    }
                )},
                _ => {
                    web::Json(
                        SimpleResponse {
                            code: StatusCode::BAD_REQUEST.as_u16(),
                            message: "Error when requesting token".to_string()
                        }
                    )
                }
            }
        },
        Err(_) => web::Json(
            SimpleResponse {
                code: StatusCode::BAD_REQUEST.as_u16(),
                message: "Error when requesting token".to_string()
            }
        )
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info,actix_web_middleware_keycloak_auth=trace");
    env_logger::init();

    HttpServer::new(|| {
        let keycloak_auth = KeycloakAuth {
            detailed_responses: true,
            keycloak_oid_public_key: DecodingKey::from_rsa_pem(KEYCLOAK_PK.as_bytes()).unwrap(),
            required_roles: vec![Role::Realm {
                role: "student".to_owned(),
            }],
        };

        App::new()
            .wrap(middleware::Logger::default())
            .service(
                web::scope("/private")
                    .wrap(keycloak_auth)
                    .route("", web::get().to(private)),
            )
            .service(web::resource("/").to(hello_world))
            .service(auth_request)
    })
    .bind("127.0.0.1:8082")?
    .workers(1)
    .run()
    .await
}

async fn hello_world() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

async fn private(claims: ReqData<Claims>) -> impl Responder {
    HttpResponse::Ok().body(format!("{:?}", &claims))
}