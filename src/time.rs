extern crate chrono;            // DateTime manipulation

use std::io;

use chrono::{DateTime, Utc, ParseError};
use std::io::Error;
use crate::{data_defs::*};

// get date into the format we need
pub fn format_date(
                    time: DateTime::<Utc>
                ) -> Result<String, Error>  
{
    Ok(time.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string())
}

// get the current date time
pub fn get_now() -> Result<String, Error>  {
    Ok(format_date(Utc::now())?)
}

// used to initialize a date time to epoch start
pub fn get_epoch_start() -> String  
{
    "1970-01-01T00:00:00.000Z".to_string()
}

// convert string to utc datetime
pub fn to_utc_datetime(time: &str) -> Result<DateTime<Utc>, ParseError> {
    DateTime::parse_from_rfc3339(time)
        .map(|dt| dt.with_timezone(&Utc))
}

// is the datetime within the time window we are examining?
pub fn in_time_window(time: &str) -> Result<bool, ParseError> {
    let t = to_utc_datetime(time)?;

    // The '*' dereferences the lazy_static value.
    Ok(*TIME_START <= t && t < *TIME_END)
}