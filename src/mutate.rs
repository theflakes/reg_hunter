extern crate chrono;            // DateTime manipulation
extern crate arrayvec;

// split string on string and return vec
pub fn split_to_vec(
                    source: &str, 
                    split_by: &str
                ) -> Vec<String> 
{
    source.split(split_by).map(|s| s.to_string()).collect()
}

// convert a string to a Rust file path
pub fn push_file_path(
                        path: &str, 
                        suffix: &str
                    ) -> std::path::PathBuf 
{
    let mut p = path.to_owned();
    p.push_str(suffix);
    let r = std::path::Path::new(&p);
    return r.to_owned()
}

pub fn value_to_string(
                    value: &Vec<u8>
                ) -> std::io::Result<(bool, String)> 
{
    let mut result = false;

    let mut val: String = match std::str::from_utf8(value) { // refactor to deal with other reg types; e.g. binary
        Ok(v) => v.to_string().replace("\u{0}", ""),
        _ => "".to_string(),
    };

    // if conversion failed, lets convert the value to a hex array
    if val.is_empty() {
        val = format!("{:02x?}", value); 
    } else {
        result = true;
    }

    Ok((result, val))
}