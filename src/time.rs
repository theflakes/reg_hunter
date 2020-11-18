extern crate chrono;            // DateTime manipulation


use chrono::DateTime;
use chrono::offset::Utc;



// get date into the format we need
pub fn format_date(
                    time: DateTime::<Utc>
                ) -> Result<String, std::io::Error>  
{
    Ok(time.format("%Y-%m-%dT%H:%M:%S.%3f").to_string())
}

// get the current date time
pub fn get_now() -> Result<String, std::io::Error>  {
    Ok(format_date(Utc::now())?)
}

// used to initialize a date time to epoch start
pub fn get_epoch_start() -> String  
{
    "1970-01-01 00:00:00.000".to_string()
}