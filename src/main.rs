use iostore_uasset::IoUObject;
use std::fs::File;

mod iostore_uasset;

fn main() {
    let mut file = File::open().unwrap();
    let asset = IoUObject::from_buffer::<_, byteorder::LE>(&mut file).unwrap();

    let mut stdout = std::io::stdout();
    asset.to_string(&mut stdout);
}
