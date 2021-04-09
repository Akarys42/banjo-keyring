use itertools::Itertools;
use std::io::Read;
use log::debug;

pub fn compare_buffers(a: &Vec<u8>, b: &Vec<u8>) -> bool {
    let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
    matching == a.len() && matching == b.len()
}

pub fn buffer_to_string(buf: &Vec<u8>) -> String {
    buf.iter().join(" ")
}

pub fn read_null_string<R: Read>(reader: &mut R) -> String {
    let mut buffer = String::new();
    let mut iterator = reader.bytes();

    while let Some(Ok(byte)) = iterator.next() {
        if byte == 0 { break }
        buffer.push(char::from(byte));
    }

    debug!("Read string \"{}\"", buffer);
    buffer
}
