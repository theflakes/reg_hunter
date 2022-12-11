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
        Err(_e) => String::new(),
    };

    // if conversion failed, lets convert the value to a hex array
    if val.is_empty() {
        val = format!("{:02x?}", value); 
    } else {
        result = true;
    }

    Ok((result, val))
}

/*
    Converts hex string to Vec<u8> byte array.
        e.g. "0a1b2c3d4e5f" convert it to [0, a, 1, b, 2, c, 3, d, 4, e, 5, f]
    Solution provided by H2CO3
    See: https://users.rust-lang.org/t/hex-string-to-vec-u8/51903
*/
pub fn hex_to_bytes(
                    hex: &str
                ) -> Option<Vec<u8>> {
    if hex.len() % 2 == 0 {
        (0..hex.len())
            .step_by(2)
            .map(|i| hex.get(i..i + 2)
                      .and_then(|sub| u8::from_str_radix(sub, 16).ok()))
            .collect()
    } else {
        None
    }
}