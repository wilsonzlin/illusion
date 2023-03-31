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
use axum::http::header::ACCEPT_RANGES;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_RANGE;
use axum::http::Response;
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
use rpassword::prompt_password;
use sha2::Sha512;
use std::error::Error;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::ops::Bound;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::BufReader;
use tokio_util::io::StreamReader;
use tracing::info;
use tracing::warn;

const PLAIN_PAGE_SIZE: u64 = 1024 * 4;
const NONCE_SIZE: u64 = 12;
// 16 bytes for MAC.
const CIPHER_PAGE_SIZE: u64 = NONCE_SIZE + PLAIN_PAGE_SIZE + 16;

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
  ranges: Option<TypedHeader<Range>>,
  OriginalUri(uri): OriginalUri,
) -> Result<Response<StreamBody<impl Stream<Item = Result<Vec<u8>, tokio::io::Error>>>>, StatusCode>
{
  assert!(ranges
    .as_ref()
    .filter(|ranges| ranges.iter().count() > 1)
    .is_none());
  let range = ranges
    .as_ref()
    .and_then(|ranges| ranges.iter().next())
    .unwrap_or((Bound::Unbounded, Bound::Unbounded));
  let start = match range.0 {
    Bound::Included(v) => v,
    Bound::Excluded(_) => {
      // Ranges must always have an inclusive start.
      return Err(StatusCode::RANGE_NOT_SATISFIABLE);
    }
    Bound::Unbounded => 0,
  };
  // Inclusive.
  let end = match range.1 {
    Bound::Included(v) => Some(v),
    Bound::Excluded(0) => {
      // Prevent underflow.
      return Err(StatusCode::RANGE_NOT_SATISFIABLE);
    }
    Bound::Excluded(v) => Some(v - 1),
    Bound::Unbounded => None,
  };
  if end.is_some() && start > end.unwrap() {
    return Err(StatusCode::RANGE_NOT_SATISFIABLE);
  };
  // Inclusive.
  let page_start = start / PLAIN_PAGE_SIZE;
  // Inclusive because `end` is inclusive.
  let page_end = end.map(|end| end / PLAIN_PAGE_SIZE);
  let path_enc = ctx.encrypted_path(&uri);
  let res = ctx
    .client
    .get_object()
    .bucket(ctx.bucket.clone())
    .key(path_enc)
    .range(format!(
      "bytes={}-{}",
      page_start * CIPHER_PAGE_SIZE,
      page_end
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
        warn!(
          error_type = err.to_string(),
          error_source = err.source(),
          "unhandled GetObject error"
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
      }
    },
  };

  // We don't want to make a separate extra request to get full object size, so we parse from Content-Range. We can't use Content-Length because that's only the range request length, not the full object size. Also remember that these Content-* values are for the encrypted format, not original, and are page aligned, not exact [start, end].
  let object_size: u64 = {
    let raw = res.content_range().unwrap();
    let raw = raw.strip_prefix("bytes ").unwrap();
    let (_, size_enc_raw) = raw.split_once('/').unwrap();
    let size_enc: u64 = size_enc_raw.parse().unwrap();
    let whole_pages = size_enc / CIPHER_PAGE_SIZE;
    let rem = size_enc % CIPHER_PAGE_SIZE;
    let mut sz = whole_pages * PLAIN_PAGE_SIZE;
    if rem != 0 {
      sz += rem - (CIPHER_PAGE_SIZE - PLAIN_PAGE_SIZE);
    };
    sz
  };
  // TODO object_size may be zero.
  let resolved_end = end.unwrap_or(object_size - 1);
  if start > resolved_end {
    return Err(StatusCode::RANGE_NOT_SATISFIABLE);
  };

  let mut out = Response::builder();
  out = out.status(if ranges.is_some() {
    StatusCode::PARTIAL_CONTENT
  } else {
    StatusCode::OK
  });
  out = out.header(ACCEPT_RANGES, "bytes");
  out = out.header(CONTENT_LENGTH, resolved_end + 1 - start);
  if ranges.is_some() {
    out = out.header(
      CONTENT_RANGE,
      format!("bytes={start}-{resolved_end}/{object_size}"),
    );
  };

  Ok(out.body(StreamBody::from(try_stream! {
    let mut reader = BufReader::new(res.body.into_async_read());
    let mut cipher_buf = vec![0u8; usz!(CIPHER_PAGE_SIZE)];
    for i in page_start..=page_end.unwrap_or(u64::MAX) {
      let mut eof = false;
      let mut read_n = 0;
      while read_n < cipher_buf.len() {
        let n = reader.read(&mut cipher_buf[read_n..]).await?;
        if n == 0 {
          // EOF.
          eof = true;
          break;
        };
        read_n += n;
      };
      let (nonce, cipher_data) = cipher_buf[..read_n].split_at(usz!(NONCE_SIZE));
      let mut plain_data = ctx.content_key.decrypt(aes_gcm::Nonce::from_slice(nonce), cipher_data).unwrap();
      // Trim right first in case left trim (`i == 0`) shifts bytes down.
      if Some(i) == page_end {
        let end_rem = (end.unwrap() + 1) % PLAIN_PAGE_SIZE;
        if end_rem != 0 {
          plain_data.truncate(usz!(end_rem));
        };
      };
      // This may be both the first and last page, so this is not an `else`.
      if i == page_start {
        plain_data.drain(0..usz!(start % PLAIN_PAGE_SIZE));
      };
      yield plain_data;
      if eof {
        break;
      };
    };
  })).unwrap())
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
  let upload = match res {
    Ok(res) => res,
    Err(err) => {
      warn!(error = err.to_string(), "failed to create multipart upload");
      return StatusCode::INTERNAL_SERVER_ERROR;
    }
  };
  let mut parts = Vec::new();
  for part_no in 1.. {
    const MAX_PAGES_PER_PART: usize = 1500;
    let plain_part_max_size: usize = usz!(PLAIN_PAGE_SIZE) * MAX_PAGES_PER_PART;
    let cipher_part_max_size: usize = usz!(CIPHER_PAGE_SIZE) * MAX_PAGES_PER_PART;
    let mut plain_part_buf = vec![0u8; plain_part_max_size];
    let mut plain_part_byte_count = 0;
    let mut eof = false;
    // We cannot use read_exact as the last part probably isn't and we don't know which part is last, as request may be using chunked encoding.
    while plain_part_byte_count < plain_part_max_size {
      let res = body
        .read(&mut plain_part_buf[plain_part_byte_count..])
        .await;
      match res {
        Ok(0) => {
          eof = true;
          break;
        }
        Ok(n) => {
          plain_part_byte_count += n;
        }
        Err(err) => {
          warn!(error = err.to_string(), "failed to read part");
          return StatusCode::INTERNAL_SERVER_ERROR;
        }
      };
    }
    plain_part_buf.truncate(plain_part_byte_count);
    let mut cipher_part_data = Vec::with_capacity(cipher_part_max_size);
    for plain_page in plain_part_buf.chunks(usz!(PLAIN_PAGE_SIZE)) {
      let mut nonce = vec![0u8; usz!(NONCE_SIZE)];
      thread_rng().fill_bytes(&mut nonce);
      let cipher_data = ctx
        .content_key
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), plain_page)
        .unwrap()
        .to_vec();
      cipher_part_data.extend_from_slice(&nonce);
      cipher_part_data.extend_from_slice(&cipher_data);
      assert_eq!(cipher_data.len(), plain_page.len() + 16);
    }
    let res = ctx
      .client
      .upload_part()
      .bucket(ctx.bucket.clone())
      .key(path_enc.clone())
      .upload_id(upload.upload_id().unwrap())
      .part_number(part_no)
      .body(ByteStream::from(cipher_part_data))
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
    if eof {
      break;
    };
  }
  if let Err(err) = ctx
    .client
    .complete_multipart_upload()
    .bucket(ctx.bucket.clone())
    .key(path_enc.clone())
    .upload_id(upload.upload_id().unwrap())
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
  tracing_subscriber::fmt::init();
  let cli = Cli::parse();
  let config = aws_config::from_env().load().await;
  let client = Client::new(&config);
  let password = prompt_password("Enter your master password: ").unwrap();
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
  info!(
    interface = cli.interface.to_string(),
    port = cli.port,
    "server starting"
  );

  Server::bind(&addr)
    .serve(app.into_make_service())
    .await
    .unwrap();
}
