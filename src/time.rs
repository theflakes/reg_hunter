extern crate chrono;            // DateTime manipulation

use std::io;

use chrono::*;
use io::Error;
use crate::{data_defs::*};

// get date into the format we need
pub fn format_date(
                    time: DateTime::<Utc>
                ) -> Result<String, Error>  
{
    Ok(time.format("%Y-%m-%dT%H:%M:%S.%3f").to_string())
}

// get the current date time
pub fn get_now() -> Result<String, Error>  {
    Ok(format_date(Utc::now())?)
}

// used to initialize a date time to epoch start
pub fn get_epoch_start() -> String  
{
    "1970-01-01T00:00:00.000".to_string()
}

// convert string to utc datetime
pub fn to_utc_datetime(
    time: &str
) -> Result<DateTime::<Utc>, Error>  
{
    let _: DateTime<Utc> = match Utc.datetime_from_str(time, "%Y-%m-%dT%H:%M:%S.%3f") {
        Ok(t) => return Ok(t),
        Err(_) => return Ok(*TIME_END)
    };
}

// is the datetime within the time window we are examining?
pub fn in_time_window(
                    time: &str
                ) -> Result<bool, Error>  
{
    // convert time for comparision to time window start and end
    let t = to_utc_datetime(time)?;

    if TIME_START.le(&t) && TIME_END.gt(&t) {
        Ok(true)
    } else {
        Ok(false)
    }
}