// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::string::String;

pub(crate) fn rfc_to_json(input: &str) -> String {
    format!("{{\n{}\n}}", parse_vector_types(input))
}

fn parse_vector_types(input: &str) -> String {
    let re = regex::Regex::new(r" (?P<type>.+?) Test Vectors").unwrap();
    let mut vector_types = vec![];

    let chunks: Vec<&str> = re.split(input).collect();

    println!("{:?}", chunks.len());
    let mut count = 1;
    for caps in re.captures_iter(input) {
        println!("{:?}", caps["type"].to_string());
        let vector_type = format!(
            "\"{}\": [\n {} \n]",
            caps["type"].to_string(),
            parse_ciphersuites(chunks[count])
        );
        vector_types.push(vector_type);
        count += 1;
    }

    vector_types.join(",\n")
}

fn parse_ciphersuites(input: &str) -> String {
    let re = regex::Regex::new(
        r"# Configuration(.|\n)+?Hash: (?P<hash>.*?)\n(.|\n)*?Group: (?P<group>.*?)\n",
    )
    .unwrap();
    let mut ciphersuites = vec![];

    let chunks: Vec<&str> = re.split(input).collect();

    let mut count = 1;
    for caps in re.captures_iter(input) {
        let ciphersuite = format!(
            "{{ \"{}, {}\": {{ {} }} }}",
            caps["group"].to_string(),
            caps["hash"].to_string(),
            parse_params(chunks[count])
        );
        ciphersuites.push(ciphersuite);
        count += 1;
    }

    ciphersuites.join(",\n")
}

fn parse_params(input: &str) -> String {
    let mut params = vec![];
    let mut param = String::new();

    let mut lines = input.lines();

    loop {
        match lines.next() {
            None => {
                // Clear out any existing string and flush to params
                param += "\"";
                params.push(param);

                return params.join(",\n");
            }
            Some(line) => {
                // If line contains :, then
                if line.contains(':') {
                    // Clear out any existing string and flush to params
                    if !param.is_empty() {
                        param += "\"";
                        params.push(param);
                    }

                    let mut iter = line.split(':');
                    let key = iter.next().unwrap().split_whitespace().next().unwrap();
                    let val = iter.next().unwrap().split_whitespace().next().unwrap();

                    param = format!("    \"{}\": \"{}", key, val);
                } else {
                    let s = line.trim().to_string();
                    if s.contains('~') || s.contains('#') {
                        // Ignore comment lines
                        continue;
                    }
                    if !s.is_empty() {
                        param += &s;
                    }
                }
            }
        }
    }
}
