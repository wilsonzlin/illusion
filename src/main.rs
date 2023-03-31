use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm_siv::Aes256GcmSiv;
use async_stream::try_stream;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::builders::CompletedMultipartUploadBuilder;
use aws_sdk_s3::types::builders::CompletedPartBuilder;
use aws_sdk_s3::Client;
use axum::body::StreamBody;
use axum::extract::BodyStream;
use axum::extract::DefaultBodyLimit;
use axum::extract::OriginalUri;
use axum::extract::State;
use axum::headers::Range;
use axum::http::StatusCode;
use axum::http::Uri;
use axum::routing::get;
use axum::Router;
use axum::Server;
use axum::TypedHeader;
use clap::Parser;
use data_encoding::BASE64URL_NOPAD;
use futures::Stream;
use futures::TryStreamExt;
use itertools::Itertools;
use off64::usz;
use pbkdf2::pbkdf2_hmac_array;
use percent_encoding::utf8_percent_encode;
use percent_encoding::CONTROLS;
use rand::thread_rng;
use rand::RngCore;
use rpassword::read_password;
use sha2::Sha512;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::ops::Bound;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::BufReader;
use tokio_util::io::StreamReader;
use tracing::warn;

const PLAIN_PAGE_SIZE: u64 = 1024 * 4;
const NONCE_SIZE: u64 = 12;
const CIPHER_PAGE_SIZE: u64 = PLAIN_PAGE_SIZE + NONCE_SIZE;

fn div_ceil(n: u64, d: u64) -> u64 {
  (n / d) + (((n % d) != 0) as u64)
}

struct Ctx {
  bucket: String,
  client: Client,
  content_key: Aes256Gcm,
  path_key: Aes256GcmSiv,
}

impl Ctx {
  pub fn encrypted_path(&self, uri: &Uri) -> String {
    // TODO Assert no ambiguous %2F. Assert not empty.
    let path_plain = utf8_percent_encode(uri.path(), CONTROLS).to_string();
    // We use AES-GCM-SIV for the path, because we can't use random nonces so we cannot guarantee they won't be reused. To reduce the chance, we derive the nonce from the blake3 hash of the path. We cannot use random nonces because we need to be able to look up a key from its plaintext form, which we wouldn't know how to transform to its encrypted form with a random nonce, unless we performed a ListObjectsV2 every time which is slow. We still use AES-GCM for contents as we can use random nonces there and its algorithm and library is more audited.
    let path_hash = blake3::hash(path_plain.as_bytes());
    let path_nonce = aes_gcm_siv::Nonce::from_slice(&path_hash.as_bytes()[..usz!(NONCE_SIZE)]);
    let mut path_enc = self
      .path_key
      .encrypt(path_nonce, path_plain.as_bytes())
      .unwrap()
      .to_vec();
    path_enc.splice(0..0, path_nonce.to_vec());
    BASE64URL_NOPAD.encode(&path_enc)
  }
}

async fn handle_get(
  State(ctx): State<Arc<Ctx>>,
  TypedHeader(ranges): TypedHeader<Range>,
  OriginalUri(uri): OriginalUri,
) -> Result<StreamBody<impl Stream<Item = Result<Vec<u8>, tokio::io::Error>>>, StatusCode> {
  let ranges = ranges.iter().collect_vec();
  assert!(ranges.len() <= 1);
  let range = ranges
    .first()
    .cloned()
    .unwrap_or((Bound::Unbounded, Bound::Unbounded));
  let start = match range.0 {
    Bound::Included(v) => v,
    Bound::Excluded(_) => {
      // Ranges must always have an inclusive start.
      return Err(StatusCode::RANGE_NOT_SATISFIABLE);
    }
    Bound::Unbounded => 0,
  };
  let end = match range.1 {
    Bound::Included(v) => Some(v),
    Bound::Excluded(0) => {
      // Prevent underflow.
      return Err(StatusCode::RANGE_NOT_SATISFIABLE);
    }
    Bound::Excluded(v) => Some(v - 1),
    Bound::Unbounded => None,
  };
  let plain_page_start = start / PLAIN_PAGE_SIZE;
  let plain_page_end = end.map(|end| div_ceil(end, PLAIN_PAGE_SIZE));
  let path_enc = ctx.encrypted_path(&uri);
  let res = ctx
    .client
    .get_object()
    .bucket(ctx.bucket.clone())
    .key(path_enc)
    .range(format!(
      "bytes={}-{}",
      plain_page_start * CIPHER_PAGE_SIZE,
      plain_page_end
        .map(|e| ((e + 1) * CIPHER_PAGE_SIZE - 1).to_string())
        .unwrap_or_default()
    ))
    .send()
    .await;
  let res = match res {
    Ok(res) => res,
    Err(err) => match err.into_service_error() {
      GetObjectError::NoSuchKey(_) => return Err(StatusCode::NOT_FOUND),
      err => {
        warn!(error = err.to_string(), "unhandled GetObject error");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
      }
    },
  };
  let page_count = u64::try_from(res.content_length()).unwrap() / CIPHER_PAGE_SIZE;
  Ok(StreamBody::from(try_stream! {
    let mut reader = BufReader::new(res.body.into_async_read());
    let mut cipher_page = vec![0u8; usz!(CIPHER_PAGE_SIZE)];
    for i in 0..page_count {
      reader.read_exact(&mut cipher_page).await?;
      let (nonce, cipher_data) = cipher_page.split_at(usz!(NONCE_SIZE));
      let mut plain_data = ctx.content_key.decrypt(aes_gcm::Nonce::from_slice(nonce), cipher_data).unwrap();
      // Trim right first in case left trim (`i == 0`)  shifts bytes down.
      if i == page_count - 1 && end.filter(|e| (e % PLAIN_PAGE_SIZE) != 0).is_some() {
        plain_data.truncate(usz!(end.unwrap() % PLAIN_PAGE_SIZE));
      };
      // This may be both the first and last page, so this is not an `else`.
      if i == 0 {
        plain_data.drain(0..usz!(start));
      };
      yield plain_data;
    };
  }))
}

async fn handle_put(
  State(ctx): State<Arc<Ctx>>,
  OriginalUri(uri): OriginalUri,
  body: BodyStream,
) -> StatusCode {
  let mut body =
    StreamReader::new(body.map_err(|err| tokio::io::Error::new(tokio::io::ErrorKind::Other, err)));
  let path_enc = ctx.encrypted_path(&uri);
  let res = ctx
    .client
    .create_multipart_upload()
    .bucket(ctx.bucket.clone())
    .key(path_enc.clone())
    .send()
    .await;
  let res = match res {
    Ok(res) => res,
    Err(err) => {
      warn!(error = err.to_string(), "failed to create multipart upload");
      return StatusCode::INTERNAL_SERVER_ERROR;
    }
  };
  let mut parts = Vec::new();
  for part_no in 0.. {
    const PAGES_PER_PART: usize = 1500;
    let plain_part_size: usize = usz!(PLAIN_PAGE_SIZE) * PAGES_PER_PART;
    let cipher_part_size: usize = usz!(CIPHER_PAGE_SIZE) * PAGES_PER_PART;
    let mut plain_part_data = vec![0u8; plain_part_size];
    let mut plain_part_len = 0;
    // We cannot use read_exact as the last part probably isn't and we don't know which part is last, as request may be using chunk encoding.
    while plain_part_len < usz!(PLAIN_PAGE_SIZE) {
      let res = body.read(&mut plain_part_data[plain_part_len..]).await;
      match res {
        Ok(0) => break,
        Ok(n) => plain_part_len += n,
        Err(err) => {
          warn!(error = err.to_string(), "failed to read part");
          return StatusCode::INTERNAL_SERVER_ERROR;
        }
      };
    }
    let mut cipher_part_data = Vec::with_capacity(cipher_part_size);
    for plain_page in plain_part_data.chunks(usz!(PLAIN_PAGE_SIZE)) {
      let mut nonce = vec![0u8; usz!(NONCE_SIZE)];
      thread_rng().fill_bytes(&mut nonce);
      let cipher_data = ctx
        .content_key
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), plain_page)
        .unwrap()
        .to_vec();
      cipher_part_data.extend_from_slice(&nonce);
      cipher_part_data.extend_from_slice(&cipher_data);
    }
    assert_eq!(cipher_part_data.len(), cipher_part_size);
    let res = ctx
      .client
      .upload_part()
      .bucket(ctx.bucket.clone())
      .key(path_enc.clone())
      .part_number(part_no)
      .body(ByteStream::from(plain_part_data))
      .send()
      .await;
    let res = match res {
      Ok(res) => res,
      Err(err) => {
        warn!(error = err.to_string(), "failed to upload part");
        return StatusCode::INTERNAL_SERVER_ERROR;
      }
    };
    parts.push(res);
  }
  if let Err(err) = ctx
    .client
    .complete_multipart_upload()
    .bucket(ctx.bucket.clone())
    .key(path_enc.clone())
    .upload_id(res.upload_id().unwrap())
    .multipart_upload(
      CompletedMultipartUploadBuilder::default()
        .set_parts(Some(
          parts
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
              CompletedPartBuilder::default()
                .e_tag(p.e_tag().unwrap())
                .part_number((i + 1).try_into().unwrap())
                .build()
            })
            .collect_vec(),
        ))
        .build(),
    )
    .send()
    .await
  {
    warn!(
      error = err.to_string(),
      "failed to complete multipart upload"
    );
    return StatusCode::INTERNAL_SERVER_ERROR;
  };
  StatusCode::CREATED
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
  /// Bucket to store files in.
  #[arg(long)]
  bucket: String,

  /// Interface for server to listen on. Defaults to 127.0.0.1.
  #[arg(long, default_value = "127.0.0.1")]
  interface: Ipv4Addr,

  /// Port for server to listen on. Defaults to 6001.
  #[arg(long, default_value_t = 6001)]
  port: u16,
}

#[tokio::main]
async fn main() {
  let cli = Cli::parse();
  let config = aws_config::from_env().load().await;
  let client = Client::new(&config);
  let password = read_password().unwrap();
  let key = pbkdf2_hmac_array::<Sha512, 32>(password.as_bytes(), &[], 256_000);
  let ctx = Arc::new(Ctx {
    bucket: cli.bucket,
    client,
    path_key: Aes256GcmSiv::new(&key.try_into().unwrap()),
    content_key: Aes256Gcm::new(&key.try_into().unwrap()),
  });

  let app = Router::new()
    .fallback(get(handle_get).put(handle_put))
    .layer(DefaultBodyLimit::disable())
    .with_state(ctx.clone());

  let addr = SocketAddr::from((cli.interface, cli.port));

  Server::bind(&addr)
    .serve(app.into_make_service())
    .await
    .unwrap();
}
