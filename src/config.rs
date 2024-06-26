pub struct Config {
    pub command: Command,
    pub inpath: String,
    pub outpath: Option<String>,
}

pub enum Command {
    Encode,
    Decode,
    Test,
}

impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Self, String> {
        args.next(); //Skip executable path

        let command = match args.next().ok_or("Missing command")?.as_str() {
            "encode" => Command::Encode,
            "decode" => Command::Decode,
            "test" => Command::Test,
            "--help" | "-h" => Err(String::new())?,
            other => Err(format!("Unknown command: {other}"))?
        };

        let inpath = args.next().ok_or("Missing inpath")?;
        let outpath = args.next();

        Ok(Self { 
            command, 
            inpath, 
            outpath
        })
    }

    pub fn usage() -> &'static str {
        r#"

Converts a packed iouasset between binary and a yaml-like format. Built
and tested using UE4.27 (no guarantees on other verions).

Usage:     uasset-data-parser <command> <input path> [output path]

    <command>         Command to execute.  
    One of:
        decode        Decodes a .uasset file.
        encode        Encodes a .yaml_uasset file.
        test          Decodes and reencodes a .uasset file, verifying that
                      the final output matches the input.  Useful to ensure
                      this tool will work with a given file.

    <input path>      Path to file that should be converted.

    [output path]     Optional. Path to the file that should be written. If
                      omitted, defaults to the input file with a modified 
                      extension (either .uasset or .yaml_uasset)

    -h, --help        Show this help and exit.

        "#
    }
}