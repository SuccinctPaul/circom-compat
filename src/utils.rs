use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::Write;

const DEFAULT_DIR: &str = "artifacts";

pub fn write_to_file<T: CanonicalSerialize>(path: &str, rawdata: &T) {
    let mut bytes = Vec::new();
    rawdata.serialize_compressed(&mut bytes).unwrap();

    std::fs::create_dir_all("artifacts").unwrap();
    let mut vk_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("{DEFAULT_DIR}/{}", path))
        .unwrap();
    vk_file.write_all(&bytes).unwrap();
}

pub fn read_from_file<T: CanonicalDeserialize>(path: &str) -> T {
    let bytes = std::fs::read(format!("{DEFAULT_DIR}/{}", path)).unwrap();
    T::deserialize_compressed(&bytes[..]).unwrap()
}
