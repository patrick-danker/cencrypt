mod encryption;

use encryption::CryptPack;

fn main() {
    let file_path = "./test_files/test_img.jpg";
    let pack = CryptPack::new(file_path).unwrap();
    pack.encrypt().unwrap();
    pack.decrypt().unwrap();
}
