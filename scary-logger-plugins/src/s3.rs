use anyhow::Error;
use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_s3::{config::Region, error::SdkError, Client};
use chrono::{DateTime, Datelike, Timelike, Utc};

use scary_userspace_common::logger::LoggerPlugin;
use serde_json::Value;
use std::fmt;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use zstd::stream::write::Encoder as ZstdEncoder;

#[derive(Clone)]
pub struct S3Logger {
    client: Client,
    bucket: String,
    prefix: String,
    batch: Arc<Mutex<Vec<Value>>>,
    last_flush: Arc<Mutex<SystemTime>>,
    batch_size: usize,
    flush_interval: Duration,
    shutdown: Arc<Notify>,
}

#[derive(Clone, Debug)]
pub struct S3LoggerConfig {
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub batch_size: usize,
    pub flush_interval: Duration,
}

/// Represents an S3 key following the Hive partition strategy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HivePartitionedS3Key {
    prefix: String,
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    timestamp: i64,
}

impl HivePartitionedS3Key {
    /// Creates a new HivePartitionedS3Key with the current UTC time.
    pub fn new(prefix: String) -> Self {
        let now = Utc::now();
        Self {
            prefix,
            year: now.year(),
            month: now.month(),
            day: now.day(),
            hour: now.hour(),
            timestamp: now.timestamp_nanos_opt().unwrap_or(0),
        }
    }

    /// Creates a new HivePartitionedS3Key with a specific DateTime.
    pub fn with_datetime(prefix: String, dt: DateTime<Utc>) -> Self {
        Self {
            prefix,
            year: dt.year(),
            month: dt.month(),
            day: dt.day(),
            hour: dt.hour(),
            timestamp: dt.timestamp_nanos_opt().unwrap_or(0),
        }
    }
}

impl fmt::Display for HivePartitionedS3Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/year={}/month={:02}/day={:02}/hour={:02}/{}.json.zst",
            self.prefix, self.year, self.month, self.day, self.hour, self.timestamp
        )
    }
}

impl S3Logger {
    /// Creates a new S3Logger instance with the given configuration.
    ///
    /// This method initializes the S3 client, sets up the logger with the provided
    /// configuration, and starts the background flush task.
    ///
    /// # Arguments
    ///
    /// * `config` - An `S3LoggerConfig` struct containing the configuration parameters.
    ///
    /// # Returns
    ///
    /// Returns a `Result<S3Logger, Error>` where `S3Logger` is the initialized logger
    /// instance if successful.
    ///
    /// # Errors
    ///
    /// This method will return an `Error` if there's an issue initializing the AWS client
    /// or setting up the logger.
    pub async fn new(config: S3LoggerConfig) -> Result<Self, Error> {
        tracing::debug!(
            "Initializing S3Logger with region: {}, bucket: {}, prefix: {}",
            config.region,
            config.bucket,
            config.prefix
        );

        let region_provider = RegionProviderChain::first_try(Region::new(config.region));
        let mut aws_config_builder = aws_config::from_env().region(region_provider);

        if let (Some(access_key), Some(secret_key)) = (config.access_key, config.secret_key) {
            aws_config_builder =
                aws_config_builder.credentials_provider(aws_sdk_s3::config::Credentials::new(
                    access_key,
                    secret_key,
                    None,
                    None,
                    "scary-ebpf-agent",
                ));
        }

        let aws_config = aws_config_builder.load().await;
        let client = Client::new(&aws_config);

        tracing::debug!(
            "S3Logger created with batch_size: {}, flush_interval: {:?}",
            config.batch_size,
            config.flush_interval
        );

        let logger = S3Logger {
            client,
            bucket: config.bucket,
            prefix: config.prefix,
            batch: Arc::new(Mutex::new(Vec::new())),
            last_flush: Arc::new(Mutex::new(SystemTime::now())),
            batch_size: config.batch_size,
            flush_interval: config.flush_interval,
            shutdown: Arc::new(Notify::new()),
        };

        logger.start_background_flush_task();

        Ok(logger)
    }

    /// Checks if a flush is needed and performs it if necessary.
    ///
    /// This method checks two conditions for flushing:
    /// 1. If the time since the last flush exceeds the configured flush interval.
    /// 2. If the current batch size exceeds or equals the configured batch size limit.
    ///
    /// If either condition is met, it triggers a flush operation.
    ///
    /// # Returns
    ///
    /// Returns a `Result<(), Error>` indicating success or failure of the operation.
    ///
    /// # Errors
    ///
    /// This method will return an `Error` if there's an issue during the flush operation.
    async fn flush_if_needed(&self) -> Result<(), Error> {
        let mut last_flush = self.last_flush.lock().await;
        let now = SystemTime::now();
        let time_since_last_flush = now.duration_since(*last_flush)?;
        let batch_size = self.batch.lock().await.len();

        tracing::debug!(
            "Checking if flush is needed. Time since last flush: {:?}, Current batch size: {}, Flush interval: {:?}, Batch size limit: {}",
            time_since_last_flush, batch_size, self.flush_interval, self.batch_size
        );

        if time_since_last_flush > self.flush_interval || batch_size >= self.batch_size {
            debug!("Flushing batch to S3");
            self.flush().await?;
            *last_flush = now;
        } else {
            debug!("Flush not needed at this time");
        }
        Ok(())
    }

    /// Starts the background flush task.
    ///
    /// This method spawns a new asynchronous task that periodically flushes the log batch
    /// based on the configured flush interval.
    fn start_background_flush_task(&self) {
        let logger_clone = self.clone();
        tokio::spawn(async move {
            logger_clone.run_background_flush().await;
        });
        debug!("Background flush task started");
    }

    /// Runs the background flush loop.
    ///
    /// This method continuously checks for the flush interval or a shutdown signal.
    /// It performs a flush operation when the interval is reached and exits when
    /// a shutdown signal is received.
    async fn run_background_flush(&self) {
        debug!(
            "Background flush task running with interval: {:?}",
            self.flush_interval
        );
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.flush_interval) => {
                    debug!("Background flush interval reached");
                    if let Err(e) = self.flush().await {
                        error!("Error during periodic flush: {:?}", e);
                    }
                }
                _ = self.shutdown.notified() => {
                    debug!("Shutdown signal received, exiting background flush task");
                    break;
                }
            }
        }
    }

    /// Uploads a batch of log events to S3.
    ///
    /// This method generates an S3 key, compresses the batch data, and initiates
    /// the upload to S3.
    ///
    /// # Arguments
    ///
    /// * `batch` - A vector of `Value` objects representing the log events to upload.
    ///
    /// # Returns
    ///
    /// Returns a `Result<(), Error>` indicating success or failure of the upload.
    ///
    /// # Errors
    ///
    /// This method will return an `Error` if there's an issue during key generation,
    /// data compression, or the S3 upload process.
    async fn upload_batch(&self, batch: Vec<Value>) -> Result<(), Error> {
        debug!("Uploading batch of {} events to S3", batch.len());

        let key = self.generate_s3_key();
        let compressed_data = self.compress_batch(&batch)?;

        self.upload_to_s3(key, compressed_data).await
    }

    /// Generates an S3 key following the Hive partition strategy.
    ///
    /// This method creates a key that organizes log data into a directory structure
    /// compatible with Hive's partitioning scheme. The structure is as follows:
    ///
    /// ```text
    /// {prefix}/year={YYYY}/month={MM}/day={DD}/hour={HH}/{timestamp}.json.zst
    /// ```
    ///
    /// Where:
    /// - `{prefix}` is the configured S3 prefix
    /// - `{YYYY}` is the four-digit year
    /// - `{MM}` is the two-digit month (01-12)
    /// - `{DD}` is the two-digit day of the month (01-31)
    /// - `{HH}` is the two-digit hour (00-23)
    /// - `{timestamp}` is the nanosecond precision Unix timestamp
    ///
    /// This partitioning strategy allows for efficient querying and data management
    /// in Hive and Hive-compatible systems like Amazon Athena.
    ///
    /// # Returns
    ///
    /// Returns a `Result<String, Error>` where the `String` is the generated S3 key.
    ///
    /// # Errors
    ///
    /// This method will return an `Error` if there's an issue generating the timestamp.
    ///
    /// # More Information
    ///
    /// For more details on Hive partitioning, see the Apache Hive documentation:
    /// https://cwiki.apache.org/confluence/display/Hive/LanguageManual+DDL#LanguageManualDDL-PartitionedTables
    fn generate_s3_key(&self) -> HivePartitionedS3Key {
        HivePartitionedS3Key::new(self.prefix.clone())
    }

    /// Compresses a batch of log events using Zstandard compression.
    ///
    /// # Arguments
    ///
    /// * `batch` - A slice of `Value` objects representing the log events to compress.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Vec<u8>, Error>` where `Vec<u8>` is the compressed data.
    ///
    /// # Errors
    ///
    /// This method will return an `Error` if there's an issue during JSON serialization
    /// or Zstandard compression.
    fn compress_batch(&self, batch: &[Value]) -> Result<Vec<u8>, Error> {
        let json_string = serde_json::to_string(batch)?;
        let mut compressed = Vec::new();
        let mut encoder = ZstdEncoder::new(&mut compressed, 3)?;
        encoder.write_all(json_string.as_bytes())?;
        encoder.finish()?;
        Ok(compressed)
    }

    /// Uploads compressed data to S3 with retry logic.
    ///
    /// This method attempts to upload the data to S3, retrying up to a maximum
    /// number of times in case of retryable errors.
    ///
    /// # Arguments
    ///
    /// * `key` - The S3 object key to use for the upload.
    /// * `data` - The compressed data to upload.
    ///
    /// # Returns
    ///
    /// Returns a `Result<(), Error>` indicating success or failure of the upload.
    ///
    /// # Errors
    ///
    /// This method will return an `Error` if all upload attempts fail or if an
    /// unrecoverable error occurs.
    async fn upload_to_s3(&self, key: HivePartitionedS3Key, data: Vec<u8>) -> Result<(), Error> {
        const MAX_RETRIES: u32 = 3;

        for retry_count in 0..MAX_RETRIES {
            match self.try_upload(&key, &data).await {
                Ok(_) => {
                    info!("Successfully uploaded batch to S3: {}", key);
                    return Ok(());
                }
                Err(err) => {
                    if retry_count == MAX_RETRIES - 1 {
                        error!(
                            "Failed to upload batch to S3 after {} retries: {:?}",
                            MAX_RETRIES, err
                        );
                        return Err(err);
                    }

                    if Self::is_retryable_error(&err) {
                        warn!("Retryable error occurred: {:?}", err);
                        sleep(Duration::from_secs(2u64.pow(retry_count))).await;
                    } else {
                        error!("Unrecoverable error occurred: {:?}", err);
                        return Err(err);
                    }
                }
            }
        }

        unreachable!("Loop should have returned before reaching this point")
    }

    /// Attempts a single upload to S3.
    ///
    /// # Arguments
    ///
    /// * `key` - The S3 object key to use for the upload.
    /// * `data` - The data to upload.
    ///
    /// # Returns
    ///
    /// Returns a `Result<(), Error>` indicating success or failure of the upload attempt.
    ///
    /// # Errors
    ///
    /// This method will return an `Error` if the S3 PUT operation fails.
    async fn try_upload(&self, key: &HivePartitionedS3Key, data: &[u8]) -> Result<(), Error> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key.to_string())
            .body(data.to_vec().into())
            .content_encoding("zstd")
            .send()
            .await
            .map(|_| ())
            .map_err(Error::from)
    }

    /// Determines if an S3 error is retryable.
    ///
    /// # Arguments
    ///
    /// * `err` - The error to check.
    ///
    /// # Returns
    ///
    /// Returns `true` if the error is considered retryable, `false` otherwise.
    fn is_retryable_error(err: &Error) -> bool {
        match err.downcast_ref::<SdkError<PutObjectError>>() {
            Some(SdkError::ServiceError(service_err)) => {
                // Check if the error code indicates a non-retryable error
                let error_code = service_err.err().meta().code();
                !matches!(
                    error_code,
                    Some("NoSuchBucket") | Some("InvalidObjectState")
                )
            }
            _ => true,
        }
    }
}

#[async_trait]
impl LoggerPlugin for S3Logger {
    async fn log_event(&self, event: Value) -> Result<(), Error> {
        debug!("Logging event to S3");
        {
            let mut batch = self.batch.lock().await;
            batch.push(event);
            debug!("Event added to batch. Current batch size: {}", batch.len());
        }
        self.flush_if_needed().await
    }

    async fn flush(&self) -> Result<(), Error> {
        let events_to_flush = {
            let batch = self.batch.lock().await;
            if batch.is_empty() {
                debug!("No events to flush");
                return Ok(());
            }
            debug!("Preparing to flush {} events", batch.len());
            batch.clone()
        };

        info!("Flushing {} events to S3", events_to_flush.len());

        if let Err(e) = self.upload_batch(events_to_flush).await {
            error!("Failed to upload batch: {:?}", e);
            return Err(e);
        }

        let mut batch = self.batch.lock().await;
        debug!("Clearing batch after successful upload");
        batch.clear();

        Ok(())
    }
}
