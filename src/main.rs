use byteorder::LE;
use config::{Config, Command};
use std::{env, error::Error, fs::File, io::{BufReader, Cursor, Read}, process};

mod iostore_uasset;
mod config;

pub use iostore_uasset::IoUObject;

fn main() {
    let config = Config::new(env::args()).unwrap_or_else(|err| {
        eprintln!("{}", err);
        eprintln!("{}", Config::usage());
        process::exit(1);
    });

    if let Err(e) = execute(config) {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}

fn execute(config: Config) -> Result<(), Box<dyn Error>> {
    let infile = File::open(&config.inpath)?;
    match config.command {
        Command::Encode => {
            if !config.inpath.ends_with(".yaml_uasset") {
                println!("WARNING: Encoding a file that does not have the '.yaml_uasset' extension");
            }
            let mut outfile = match config.outpath {
                Some(path) => File::create(path)?,
                None => {
                    let infilename = config.inpath.rsplit_once(std::path::MAIN_SEPARATOR_STR).map(|f| f.1).unwrap_or(&config.inpath);
                    let outfilename = infilename.rsplit_once('.').map(|f| f.0).unwrap_or(infilename);
                    File::create(format!("{outfilename}.uasset"))?
                }
            };
            let object = IoUObject::from_string(&mut BufReader::new(infile))?;
            object.to_bytes::<_, LE>(&mut outfile);
        },
        Command::Decode => {
            if !config.inpath.ends_with(".uasset") {
                println!("WARNING: Decoding a file that does not have the '.uasset' extension");
            }
            let mut outfile = match config.outpath {
                Some(path) => File::create(path)?,
                None => {
                    let infilename = config.inpath.rsplit_once(std::path::MAIN_SEPARATOR_STR).map(|f| f.1).unwrap_or(&config.inpath);
                    let outfilename = infilename.rsplit_once('.').map(|f| f.0).unwrap_or(infilename);
                    File::create(format!("{outfilename}.yaml_uasset"))?
                }
            };
            let object = IoUObject::from_buffer::<_, LE>(&mut BufReader::new(infile))?;
            object.to_string(&mut outfile);
        },
        Command::Test => {
            if !config.inpath.ends_with(".uasset") {
                println!("WARNING: Testing a file that does not have the '.uasset' extension");
            }

            let mut infile = infile;
            let mut original_file_bytes = {
                let mut file_bytes = vec![];
                infile.read_to_end(&mut file_bytes).unwrap();
                Cursor::new(file_bytes)
            };

            let mut stringified = IoUObject::from_buffer::<_, LE>(&mut BufReader::new(&mut original_file_bytes)).map(|o| {
                let mut s = Cursor::new(vec![]);
                o.to_string(&mut s);            
                s.set_position(0);
                s
            })?;
            let result = IoUObject::from_string(&mut stringified).map(|r| {
                let mut bytes = vec![];
                r.to_bytes::<_,byteorder::LE>(&mut bytes);
                bytes
            })?;
    
            for (i, byte) in original_file_bytes.into_inner().iter().enumerate() {
                assert_eq!(byte, &result[i], "File bytes differ at 0x{i:x}");
            }
            println!("SUCCESS: Decode/reencode resulted in same binary.")
        }
    }
    Ok(())
}