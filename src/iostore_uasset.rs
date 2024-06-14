use base64::{prelude::BASE64_STANDARD, Engine};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::{error::Error, io::{BufRead, Cursor, Read, Seek, Write, SeekFrom}, iter};

struct UObjectSummaryHeader {
    name: u64,     
    source_name: u64,
    package_flags: u32,
    cooked_header_size: u32,
    name_map_names_offset: i32,
    name_map_names_size: i32,
    name_map_hashes_offset: i32,
    name_map_hashes_size: i32,
    import_map_offset: i32,
    export_map_offset: i32,
    export_bundles_offset: i32,
    graph_data_offset: i32,
    graph_data_size: i32,
    pad: i32
}

impl UObjectSummaryHeader {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let name = reader.read_u64::<E>().unwrap();
        let source_name = reader.read_u64::<E>().unwrap();
        let package_flags = reader.read_u32::<E>().unwrap();
        let cooked_header_size = reader.read_u32::<E>().unwrap();
        let name_map_names_offset = reader.read_i32::<E>().unwrap();
        let name_map_names_size = reader.read_i32::<E>().unwrap();
        let name_map_hashes_offset = reader.read_i32::<E>().unwrap();
        let name_map_hashes_size = reader.read_i32::<E>().unwrap();
        let import_map_offset = reader.read_i32::<E>().unwrap();
        let export_map_offset = reader.read_i32::<E>().unwrap();
        let export_bundles_offset = reader.read_i32::<E>().unwrap();
        let graph_data_offset = reader.read_i32::<E>().unwrap();
        let graph_data_size = reader.read_i32::<E>().unwrap();
        reader.read_u32::<E>().unwrap(); //move reader past padding

        Ok(Self {
            name,
            source_name,
            package_flags,
            cooked_header_size,
            name_map_names_offset,
            name_map_names_size,
            name_map_hashes_offset,
            name_map_hashes_size,
            import_map_offset,
            export_map_offset,
            export_bundles_offset,
            graph_data_offset,
            graph_data_size,
            pad: 0
        })
    }

    pub fn to_bytes<E: byteorder::ByteOrder>(&self) -> Vec<u8> {
        let mut result = vec![];
        
        result.write_u64::<E>(self.name).unwrap();
        result.write_u64::<E>(self.source_name).unwrap();
        result.write_u32::<E>(self.package_flags).unwrap();
        result.write_u32::<E>(self.cooked_header_size).unwrap();
        result.write_i32::<E>(self.name_map_names_offset).unwrap();
        result.write_i32::<E>(self.name_map_names_size).unwrap();
        result.write_i32::<E>(self.name_map_hashes_offset).unwrap();
        result.write_i32::<E>(self.name_map_hashes_size).unwrap();
        result.write_i32::<E>(self.import_map_offset).unwrap();
        result.write_i32::<E>(self.export_map_offset).unwrap();
        result.write_i32::<E>(self.export_bundles_offset).unwrap();
        result.write_i32::<E>(self.graph_data_offset).unwrap();
        result.write_i32::<E>(self.graph_data_size).unwrap();
        result.write_i32::<E>(self.pad).unwrap();

        result
    }
}


struct UObjectSummary {
    header: UObjectSummaryHeader,
    name_map: Vec<String>,
    remaining_bytes: Vec<u8>,
}

impl UObjectSummary {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let header = UObjectSummaryHeader::from_buffer::<R, E>(reader)?;
        reader.read_u8().unwrap(); // Seems to always be an empty byte here

        let names_count = (header.name_map_hashes_size/(std::mem::size_of::<u64>() as i32)) - 1;
        let mut name_map = Vec::with_capacity(names_count as usize);
        for _ in 0..names_count {
            let len = reader.read_u8().unwrap() as usize;
            let mut raw_string = vec![0;len];
            reader.read_exact(&mut raw_string).unwrap();
            if reader.read_u8().unwrap() != 0 {
                Err(format!("Malformed FString at byte 0x{:x} - length or termination byte is incorrect", reader.stream_position().unwrap()))?;
            }
            name_map.push(String::from_utf8(raw_string).unwrap());
        }

        let pos = reader.stream_position().unwrap() as usize;
        let raw_byte_length = (header.graph_data_offset + header.graph_data_size) as usize;
        let mut raw_bytes = vec![0;raw_byte_length-pos];

        reader.read_exact(&mut raw_bytes).unwrap();
        
        Ok(Self {
            header,
            name_map,
            remaining_bytes: raw_bytes,
        })
    }

    pub fn to_bytes<E: byteorder::ByteOrder>(&self) -> Vec<u8> {
        let mut result = self.header.to_bytes::<E>();
        result.push(0);

        for name in &self.name_map {
            result.push(name.len() as u8);
            result.write(name.as_bytes()).unwrap();
            result.push(0);
        }
        
        result.write(&self.remaining_bytes).unwrap();

        result
    }

    pub fn to_string(&self) -> String {
        BASE64_STANDARD.encode(self.to_bytes::<LE>())
    }

    pub fn from_string(str: &str) -> Result<Self, Box<dyn Error>> {
        let bytes = BASE64_STANDARD.decode(str).map_err(|_| "Unable to read object summary header from base64 string. This value shouldn't be manually edited.")?;
        let mut bytes = Cursor::new(bytes);
        Self::from_buffer::<_, LE>(&mut bytes)
    }
}

#[derive(PartialEq, Debug)]
pub struct UObjectProperty {
    name: String,
    arr_index: usize,
    data: UObjectPropertyData,
}

impl UObjectProperty {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(mut reader: &mut R, name_map: &[String]) -> Result<Option<Self>, Box<dyn Error>> {
        let name_index = reader.read_u64::<E>().unwrap() as usize;
        let name = name_map[name_index].clone();

        if name == "None" {
            return Ok(None);
        }

        let type_index = reader.read_u64::<E>().unwrap() as usize;
        let r#type = name_map[type_index].clone();

        let _data_size = reader.read_u32::<E>().unwrap() as usize;
        let arr_index = reader.read_u32::<E>().unwrap() as usize;

        let data = UObjectPropertyData::from_buffer::<R,E>(&mut reader, &r#type, name_map)?;
        
        Ok(Some(Self {
            name,
            arr_index,
            data,
        }))
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, writer: &mut W, name_map: &[String]) -> usize {
        let name_index = name_map.iter().position(|n| n == &self.name).expect(&format!("Object type [{}] wasn't in name map", self.name)) as u64;
        if self.name == "None" {
            writer.write_u64::<E>(name_index).unwrap();
            std::mem::size_of::<u64>()
        } else {
            let r#type = match &self.data {
                UObjectPropertyData::BoolProperty(_) => "BoolProperty",
                UObjectPropertyData::ByteProperty(_,_) => "ByteProperty",
                UObjectPropertyData::FloatProperty(_) => "FloatProperty",
                UObjectPropertyData::IntProperty(_) => "IntProperty",
                UObjectPropertyData::MapProperty(_, _, _) => "MapProperty",
                UObjectPropertyData::StringProperty(_) => "StrProperty",
                UObjectPropertyData::StructProperty(_) => "StructProperty",
                UObjectPropertyData::UInt16Property(_) => "UInt16Property",
            };

            let type_index = name_map.iter().position(|n| n == r#type).expect(&format!("Object type [{}] wasn't in name map", r#type)) as u64;
            let mut data = vec![];
            self.data.to_bytes::<_,E>(&mut data, name_map);
            let data_size = data.len() as u32;

            writer.write_u64::<E>(name_index).unwrap();
            writer.write_u64::<E>(type_index).unwrap();
            writer.write_u32::<E>(data_size).unwrap();
            writer.write_u32::<E>(self.arr_index as u32).unwrap();
            writer.write_all(&data).unwrap();

            8 + 8 + 4 + 4 + data.len()
        }
    }

    pub fn to_string<W: Write>(&self, writer: &mut W, indent_spaces: usize) {
        writer.write(format!("{}{}: ", indent(indent_spaces), self.name).as_bytes()).unwrap();
        self.data.to_string(writer, indent_spaces);
    }

    pub fn from_string<R: BufRead + Seek>(mut reader: &mut R, expected_indent_level: usize) -> Result<Option<Self>, Box<dyn Error>> {
        let next_line = next_nonempty_line(&mut reader);
        if next_line.is_empty() || !check_indent(&next_line, expected_indent_level) {
            reader.seek(SeekFrom::Current(-(next_line.len() as i64))).unwrap();
            return Ok(None);
        }

        let (name, val) = next_line.split_once(':').ok_or(format!("Missing ':' delimiter for property at position 0x{:x}", reader.stream_position().unwrap()))?;
        let data = UObjectPropertyData::from_string::<R>(val, &mut reader, expected_indent_level)?;

        Ok(Some(UObjectProperty {
            name: name.trim().to_owned(),
            arr_index: 0,
            data
        }))
    }
}

#[derive(PartialEq, Debug)]
pub enum UObjectPropertyData {
    BoolProperty(bool),
    ByteProperty(u64, u8),
    StructProperty(Vec<UObjectProperty>),
    FloatProperty(f32),
    StringProperty(String),
    MapProperty(String, String, Vec<(UObjectPropertyData, UObjectPropertyData)>),
    UInt16Property(u16),
    IntProperty(i32),
}

impl UObjectPropertyData {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(mut reader: &mut R, r#type: &str, name_map: &[String]) -> Result<Self, Box<dyn Error>> {
        match r#type {
            "BoolProperty" => {
                let val = if reader.read_u8().unwrap() > 0 { 
                    UObjectPropertyData::BoolProperty(true) 
                } else {
                    UObjectPropertyData::BoolProperty(false)
                };
                let _unknown_byte = reader.read_u8().unwrap();
                Ok(val)
            },
            "ByteProperty" => {
                let enum_name = reader.read_u64::<E>().unwrap();
                let val = reader.read_u8().unwrap();
                let _unknown_byte = reader.read_u8().unwrap();
                Ok(UObjectPropertyData::ByteProperty(enum_name, val))
            },
            "StructProperty" => {
                let mut props = vec![];
                while let Some(prop) = UObjectProperty::from_buffer::<R,E>(&mut reader, name_map)? {
                    props.push(prop);
                }
                Ok(UObjectPropertyData::StructProperty(props))
            },
            "FloatProperty" => {
                let _unknown_byte = reader.read_u8().unwrap();
                let val = reader.read_f32::<E>().unwrap();
                Ok(UObjectPropertyData::FloatProperty(val))
            },
            "StrProperty" => {
                let _unknown_byte = reader.read_u8().unwrap();

                let len = reader.read_u32::<E>().unwrap() as usize;
                let mut raw_string = vec![0;len-1];
                reader.read_exact(&mut raw_string).unwrap();
                if reader.read_u8().unwrap() != 0 {
                    Err(format!("Malformed FString at byte 0x{:x} - length or termination byte is incorrect", reader.stream_position().unwrap()))?;
                }
                Ok(UObjectPropertyData::StringProperty(String::from_utf8(raw_string).unwrap()))
            },
            "MapProperty" => {
                let key_type = reader.read_u64::<E>().unwrap() as usize;
                let key_type = &name_map[key_type];

                let value_type = reader.read_u64::<E>().unwrap() as usize;
                let value_type = &name_map[value_type];

                let _unknown_byte = reader.read_u8().unwrap();
                let _unknown_value = reader.read_u32::<E>().unwrap() as usize;
                let arr_size = reader.read_u32::<E>().unwrap() as usize;

                let mut sets = vec![];

                for _ in 0..arr_size {
                    let next_key = UObjectPropertyData::from_buffer::<R,E>(&mut reader, key_type, name_map)?;
                    let next_value = UObjectPropertyData::from_buffer::<R,E>(&mut reader, value_type, name_map)?;
                    sets.push((next_key, next_value));
                }

                Ok(UObjectPropertyData::MapProperty(key_type.clone(), value_type.clone(), sets))
            },
            "UInt16Property" => {
                let _unknown_byte = reader.read_u8().unwrap();
                Ok(UObjectPropertyData::UInt16Property(reader.read_u16::<E>().unwrap()))
            },
            "IntProperty" => {
                let val = reader.read_i32::<E>().unwrap();
                Ok(UObjectPropertyData::IntProperty(val))
            }
            _ => {
                Err(format!("Unhandled property type: {}", r#type))?
            }
        }
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, mut writer: &mut W, name_map: &[String]) -> usize {
        match self {
            Self::BoolProperty(val) => {
                if *val {
                    writer.write_u8(1).unwrap(); // true
                } else {
                    writer.write_u8(0).unwrap(); // false
                }
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?
                2
            },
            Self::ByteProperty(enum_name, val, ) => {
                writer.write_u64::<E>(*enum_name).unwrap();
                writer.write_u8(*val).unwrap();
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?

                8 + 2
            },
            Self::StructProperty(val) => {
                let mut len = 0;
                for v in val {
                    len += v.to_bytes::<W,E>(&mut writer, name_map);
                }
                let none_index = name_map.iter().position(|n| n == "None").expect(&format!("Object type [None] wasn't in name map")) as u64;
                writer.write_u64::<E>(none_index).unwrap();
                len += std::mem::size_of::<u64>();
                len
            },
            Self::FloatProperty(val) => {
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?
                writer.write_f32::<E>(*val).unwrap();
                5
            },
            Self::StringProperty(val) => {
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?

                let len = val.len() + 1; // +1 for termination byte
                writer.write_u32::<E>(len as u32).unwrap();
                writer.write_all(val.as_bytes()).unwrap();
                writer.write_u8(0).unwrap();  // FString termination byte
                
                1 + 4 + len
            },
            Self::MapProperty(key_type, val_type, val) => {
                let key_type_index = name_map.iter().position(|n| n == key_type).expect(&format!("Object type [{}] wasn't in name map", key_type)) as u64;
                let val_type_index = name_map.iter().position(|n| n == val_type).expect(&format!("Object type [{}] wasn't in name map", val_type)) as u64;

                writer.write_u64::<E>(key_type_index).unwrap();
                writer.write_u64::<E>(val_type_index).unwrap();

                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?
                writer.write_u32::<E>(0).unwrap();   // Unknown value - seems to be 0?

                writer.write_u32::<E>(val.len() as u32).unwrap();
                

                let mut size = 8 + 8 + 1 + 4 + 4;

                for v in val {
                    size += v.0.to_bytes::<W,E>(&mut writer, name_map);
                    size += v.1.to_bytes::<W,E>(&mut writer, name_map);
                }

                size
            },
            Self::UInt16Property(val) => {
                writer.write_u8(0).unwrap();  // Unknown value - seems to be 0?
                writer.write_u16::<E>(*val).unwrap();
                3
            },
            Self::IntProperty(val) => {
                writer.write_i32::<E>(*val).unwrap();
                4
            },
        }
    }

    pub fn to_string<W: Write>(&self, mut writer: &mut W, indent_spaces: usize) {
        match self {
            Self::BoolProperty(val) => {
                if *val {
                    writer.write("true\n".as_bytes()).unwrap();
                } else {
                    writer.write("false\n".as_bytes()).unwrap();
                }
            },
            Self::ByteProperty(enum_name, val, ) => {
                writer.write(format!("!ByteProperty {enum_name:x} {val:x}\n").as_bytes()).unwrap();
            },
            Self::StructProperty(val) => {
                writer.write("\n".as_bytes()).unwrap();

                for v in val {
                    v.to_string::<W>(&mut writer, indent_spaces + 2);
                }
            },
            Self::FloatProperty(val) => {
                writer.write(format!("{:.4}\n", val).as_bytes()).unwrap();
            },
            Self::StringProperty(val) => {
                writer.write(format!("{val}\n").as_bytes()).unwrap();
            },
            Self::MapProperty(key_type, val_type, val) => {
                writer.write("!Map\n".as_bytes()).unwrap();

                let indention = indent(indent_spaces + 2);
                writer.write(format!("{}key_type: {key_type}\n", indention).as_bytes()).unwrap();
                writer.write(format!("{}val_type: {val_type}\n", indention).as_bytes()).unwrap();
                writer.write(format!("{}map_data:\n", indention).as_bytes()).unwrap();

                for v in val {
                    let key_string = match &v.0 {
                        Self::BoolProperty(v) => { if *v { "true".to_string() } else { "false".to_string() }},
                        Self::IntProperty(v) => v.to_string(),
                        Self::UInt16Property(v) => v.to_string(),
                        Self::StringProperty(v) => v.clone(),
                        Self::FloatProperty(v) => format!("{v:.4}"),
                        _ => panic!("Unprintable map key type: {key_type}")
                    };
                    writer.write(format!("{}- {}:", indent(indent_spaces + 4), key_string).as_bytes()).unwrap();
                    v.1.to_string::<W>(&mut writer, indent_spaces + 6);
                }
            },
            Self::UInt16Property(val) => {
                writer.write(format!("!u16 {val}\n").as_bytes()).unwrap();
            },
            Self::IntProperty(val) => {
                writer.write(format!("!i32 {val}\n").as_bytes()).unwrap();
            },
        }
    }

    pub fn from_string<R: BufRead + Seek>(val: &str, mut reader: &mut R, expected_indent_level: usize) -> Result<Self, Box<dyn Error>> {
        let val = val.trim();
        if val.is_empty() { // Struct start
            let mut props = vec![];
            while let Some(prop) = UObjectProperty::from_string::<R>(&mut reader, expected_indent_level + 2)? {
                props.push(prop);
            }
            Ok(UObjectPropertyData::StructProperty(props))
        } else if val.starts_with("!Map") {
            let start_position = reader.stream_position().unwrap();
            let mut key_type:   Option<String> = None;
            let mut value_type: Option<String> = None;
            let mut sets = vec![];

            for _ in 0..3 {
                let next_line = next_nonempty_line(&mut reader);
                if !check_indent(&next_line, expected_indent_level + 2) {
                    Err(format!("Map at 0x{start_position:x} should have properties (in order): key_type, val_type, map_data"))?;
                }

                let (key, val) = next_line.split_once(':').ok_or(format!("Map at 0x{:x} - expected [key_type:] or [val_type:] property, but got:\n{}", start_position, next_line.trim()))?;
                match key.trim() {
                    "key_type" => { key_type = Some(val.trim().to_owned()); },
                    "val_type" => { value_type = Some(val.trim().to_owned()); },
                    "map_data" => {
                        if key_type.is_none() {
                            Err(format!("Map at 0x{start_position:x} - key_type should come before map_data"))?;
                        }
                        if value_type.is_none() {
                            Err(format!("Map at 0x{start_position:x} - val_type should come before map_data"))?;
                        }

                        let format_err = format!("Map at 0x{start_position:x} - map_data should use format ' - key: value'");
                        loop {
                            let next_line = next_nonempty_line(&mut reader);
                            if !next_line.trim().starts_with('-') || !check_indent(&next_line, expected_indent_level + 4) {
                                reader.seek(SeekFrom::Current(-(next_line.len() as i64))).unwrap();
                                break;
                            }
    
                            let (key, val) = next_line.split_once('-').ok_or(format_err.clone())?.1.split_once(':').ok_or(format_err.clone())?;
                            let key = key.trim();
                            let key = match key_type.as_ref().unwrap().as_str() {
                                "BoolProperty" => UObjectPropertyData::BoolProperty(key.parse()?),
                                "IntProperty" => UObjectPropertyData::IntProperty(key.parse()?),
                                "UInt16Property" => UObjectPropertyData::UInt16Property(key.parse()?),
                                "StrProperty" => UObjectPropertyData::StringProperty(key.to_owned()),
                                "FloatProperty" => UObjectPropertyData::FloatProperty(key.parse()?),
                                other => Err(format!("Map at 0x{start_position:x} - unable to read data of key type '{other}'"))?,
                            };
                            let val = UObjectPropertyData::from_string::<R>(val, &mut reader, expected_indent_level + 6)?;
                            sets.push((key, val));
                        }

                        let val_type = value_type.as_ref().unwrap().as_str();
                        for set in &sets {
                            let set_val_type = match set.1 {
                                UObjectPropertyData::BoolProperty(_) => "BoolProperty",
                                UObjectPropertyData::ByteProperty(_, _) => "ByteProperty",
                                UObjectPropertyData::StructProperty(_) => "StructProperty",
                                UObjectPropertyData::FloatProperty(_) => "FloatProperty",
                                UObjectPropertyData::StringProperty(_) => "StrProperty",
                                UObjectPropertyData::MapProperty(_, _, _) => "MapProperty",
                                UObjectPropertyData::UInt16Property(_) => "UInt16Property",
                                UObjectPropertyData::IntProperty(_) => "IntProperty",
                            };
                            if set_val_type != val_type {
                                Err(format!("Map at 0x{start_position:x} - expected value type '{val_type}', but got '{set_val_type}'"))?;
                            }
                        }
                    }
                    _ => { Err(format!("Map at 0x{:x} - expected key_type or val_type, but got {}", start_position, key.trim()))?; }
                }
            }

            if sets.is_empty() {
                Err(format!("Map at 0x{start_position:x} - missing map_data!"))?;
            }

            Ok(UObjectPropertyData::MapProperty(
                key_type.ok_or(format!("Map at 0x{start_position:x} - missing key_type!"))?,
                value_type.ok_or(format!("Map at 0x{start_position:x} - missing val_type!"))?,
                sets
            ))

        } else if val.starts_with("!u16") {
            let (_, u16value) = val.split_once(" ").ok_or(format!("Error at 0x{:x}: !u16 should have one integer parameter", reader.stream_position().unwrap()))?;
            Ok(UObjectPropertyData::UInt16Property(u16::from_str_radix(u16value, 10)?))
        } else if val.starts_with("!i32") {
            let (_, i32value) = val.split_once(" ").ok_or(format!("Error at 0x{:x}: !i32 should have one integer parameter", reader.stream_position().unwrap()))?;
            Ok(UObjectPropertyData::IntProperty(i32::from_str_radix(i32value, 10)?))
        } else if val.starts_with("!ByteProperty") {
            let mut vals = val.split_whitespace();
            vals.next().unwrap(); // !ByteProperty

            let err = format!("Error at 0x{:x}: !ByteProperty should have two integer parameters", reader.stream_position().unwrap());
            let enum_id = vals.next().ok_or(err.clone())?;
            let enum_val = vals.next().ok_or(err)?;
            
            Ok(UObjectPropertyData::ByteProperty(u64::from_str_radix(enum_id, 16)?, u8::from_str_radix(enum_val, 16)?))
        } else if let Ok(val) = val.parse::<f32>() {
            Ok(UObjectPropertyData::FloatProperty(val))
        } else if let Ok(val) = val.parse::<bool>() {
            Ok(UObjectPropertyData::BoolProperty(val))
        } else {
            Ok(UObjectPropertyData::StringProperty(val.to_owned()))
        }
    }
}

fn indent(spaces: usize) -> String {
    iter::repeat(' ').take(spaces).collect()
}

fn check_indent(val: &str, spaces: usize) -> bool {
    val.replace("\t", "  ").chars().take(spaces).all(|c| c == ' ')
}

/// 
/// Returns the next non-empty line in the reader.  If an empty line is returned, the reader has reached EOF.
/// 
fn next_nonempty_line<R: BufRead + Seek>(mut reader: &mut R) -> String {
    let mut line = String::new();
    while line.trim().is_empty() {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
    }
    line
}

pub struct IoUObject {
    summary: UObjectSummary,
    properties: Vec<UObjectProperty>,
}

impl IoUObject {
    pub fn from_buffer<R: Read + Seek, E: byteorder::ByteOrder>(mut reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let summary = UObjectSummary::from_buffer::<R,E>(&mut reader)?;
        let mut properties = vec![];
        while let Some(prop) = UObjectProperty::from_buffer::<R,E>(&mut reader, &summary.name_map)? {
            properties.push(prop);
        }

        Ok(Self {
            summary,
            properties,
        })
    }

    pub fn to_bytes<W: Write, E: byteorder::ByteOrder>(&self, writer: &mut W) -> usize {
        let mut properties_bytes = vec![];
        for prop in &self.properties {
            prop.to_bytes::<_,E>(&mut properties_bytes, &self.summary.name_map);
        }
        let none_index = self.summary.name_map.iter().position(|n| n == "None").expect(&format!("Object type [None] wasn't in name map")) as u64;
        properties_bytes.write_u64::<E>(none_index).unwrap();

        let summary_bytes = self.summary.to_bytes::<E>();
        writer.write(&summary_bytes).unwrap();
        writer.write(&properties_bytes).unwrap();

        summary_bytes.len() + properties_bytes.len()
    }

    pub fn to_string<W: Write>(&self, mut writer: &mut W) {
        writer.write(format!("summary: {}\n", self.summary.to_string()).as_bytes()).unwrap();
        writer.write("contents:\n".as_bytes()).unwrap();

        for prop in &self.properties {
            let indent_spaces = 2usize;
            prop.to_string(&mut writer, indent_spaces);
        }
    }

    pub fn from_string<R: BufRead + Seek>(mut reader: &mut R) -> Result<Self, Box<dyn Error>> {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        if !line.starts_with("summary:") {
            Err("IoUObject string should start with 'summary:' property!")?;
        }

        let (_, summary) = line.split_once(':').ok_or("Missing summary value")?;
        let summary = UObjectSummary::from_string(summary.trim())?;

        line.clear();
        reader.read_line(&mut line).unwrap();

        if !line.starts_with("contents:") {
            Err("IoUObject string should follow 'summary:' with 'contents:'")?;
        }

        let mut properties = vec![];
        while let Some(prop) = UObjectProperty::from_string::<R>(&mut reader, 2)? {
            properties.push(prop);
        }

        Ok(Self {
            summary,
            properties,
        })
    }
}

#[allow(dead_code)]
#[allow(unused_imports)]
mod test {
    use byteorder::LE;
    use std::io::{Cursor, Write};

    use super::{IoUObject, UObjectSummary, UObjectSummaryHeader, UObjectProperty, UObjectPropertyData};

    fn get_test_object() -> IoUObject {
        let summary_header = UObjectSummaryHeader {
            name: 1,
            source_name: 5,
            package_flags: 0,
            cooked_header_size: 0x40,
            name_map_names_offset: 0x40,
            name_map_names_size: 0x10,
            name_map_hashes_offset: 0x50,
            name_map_hashes_size: 0x80,
            import_map_offset: 0x130,
            export_bundles_offset: 0x140,
            export_map_offset: 0x150,
            graph_data_offset: 0xfc,
            graph_data_size: 0x04,
            pad: 0
        };
        let summary = UObjectSummary {
            header: summary_header,
            name_map: vec![
                "None".to_string(),
                "BoolProperty".to_string(),
                "TestBool".to_string(),
                "ByteProperty".to_string(),
                "TestByte".to_string(),
                "IntProperty".to_string(),
                "TestInt".to_string(),
                "FloatProperty".to_string(),
                "TestFloat".to_string(),
                "MapProperty".to_string(),
                "TestMap".to_string(),
                "StrProperty".to_string(),
                "TestString".to_string(),
                "StructProperty".to_string(),
                "TestStruct".to_string(),
            ],
            remaining_bytes: vec![0;14]
        };

        let mkbool = |v| {
            UObjectProperty {
                name: "TestBool".to_string(),
                arr_index: 0,
                data: UObjectPropertyData::BoolProperty(v)
            }
        };

        let mkbyte = |t,v| {
            UObjectProperty {
                name: "TestByte".to_string(),
                arr_index: 0,
                data: UObjectPropertyData::ByteProperty(t,v)
            }
        };

        let mkint = |v| {
            UObjectProperty {
                name: "TestInt".to_string(),
                arr_index: 0,
                data: UObjectPropertyData::IntProperty(v)
            }
        };

        let mkfloat = |v| {
            UObjectProperty {
                name: "TestFloat".to_string(),
                arr_index: 0,
                data: UObjectPropertyData::FloatProperty(v)
            }
        };

        let mkstr = |v: &str| {
            UObjectProperty {
                name: "TestString".to_string(),
                arr_index: 0,
                data: UObjectPropertyData::StringProperty(v.to_string())
            }
        };
        
        IoUObject {
            summary,
            properties: vec![
                mkbool(true),
                mkbyte(25,0),
                mkint(77),
                mkfloat(192f32),
                mkstr("TEEESTString"),
                UObjectProperty {
                    name: "TestMap".to_string(),
                    arr_index: 0,
                    data: UObjectPropertyData::MapProperty("IntProperty".to_string(), "StructProperty".to_string(), vec![
                        (
                            UObjectPropertyData::IntProperty(0),
                            UObjectPropertyData::StructProperty(vec![
                                mkint(0),
                                mkint(1),
                                mkint(2),
                                mkfloat(3f32),
                            ])
                        ),
                        (
                            UObjectPropertyData::IntProperty(1),
                            UObjectPropertyData::StructProperty(vec![
                                mkbool(true),
                                mkbool(false),
                                mkbyte(7,7),
                                mkstr("MoreTesting"),
                            ])
                        ),
                        (
                            UObjectPropertyData::IntProperty(2),
                            UObjectPropertyData::StructProperty(vec![
                                UObjectProperty { 
                                    name: "TestMap".to_string(), 
                                    arr_index: 0, 
                                    data: UObjectPropertyData::MapProperty("StrProperty".to_string(), "IntProperty".to_string(), vec![
                                        (UObjectPropertyData::StringProperty("Prop1".to_string()), UObjectPropertyData::IntProperty(5)),
                                        (UObjectPropertyData::StringProperty("TestProp2".to_string()), UObjectPropertyData::IntProperty(7)),
                                    ])
                                }
                            ])
                        ),
                        (
                            UObjectPropertyData::IntProperty(30),
                            UObjectPropertyData::StructProperty(vec![
                                mkstr("SkipMapKeys")
                            ])
                        ),
                        (
                            UObjectPropertyData::IntProperty(2),
                            UObjectPropertyData::StructProperty(vec![
                                UObjectProperty { 
                                    name: "TestMap".to_string(), 
                                    arr_index: 0, 
                                    data: UObjectPropertyData::MapProperty("StrProperty".to_string(), "StructProperty".to_string(), vec![
                                        (UObjectPropertyData::StringProperty("Prop1".to_string()), UObjectPropertyData::StructProperty(vec![
                                            mkstr("NestedStruct"),
                                            mkfloat(77f32),
                                        ])),
                                        (UObjectPropertyData::StringProperty("TestProp2".to_string()), UObjectPropertyData::StructProperty(vec![
                                            mkbyte(25,6),
                                            mkstr("TestEndMapOnNestedStruct"),
                                        ])),
                                    ])
                                }
                            ])
                        ),
                    ])
                },
                mkfloat(999f32),
                mkstr("End of the object"),
            ]
        }
    }

    fn assert_equality(a: IoUObject, b: IoUObject) {

        // Summary Header
        assert_eq!(a.summary.header.cooked_header_size, b.summary.header.cooked_header_size);
        assert_eq!(a.summary.header.export_bundles_offset, b.summary.header.export_bundles_offset);
        assert_eq!(a.summary.header.export_map_offset, b.summary.header.export_map_offset);
        assert_eq!(a.summary.header.graph_data_offset, b.summary.header.graph_data_offset);
        assert_eq!(a.summary.header.graph_data_size, b.summary.header.graph_data_size);
        assert_eq!(a.summary.header.import_map_offset, b.summary.header.import_map_offset);
        assert_eq!(a.summary.header.name, b.summary.header.name);
        assert_eq!(a.summary.header.name_map_hashes_offset, b.summary.header.name_map_hashes_offset);
        assert_eq!(a.summary.header.name_map_hashes_size, b.summary.header.name_map_hashes_size);
        assert_eq!(a.summary.header.name_map_names_offset, b.summary.header.name_map_names_offset);
        assert_eq!(a.summary.header.name_map_names_size, b.summary.header.name_map_names_size);
        assert_eq!(a.summary.header.package_flags, b.summary.header.package_flags);
        assert_eq!(a.summary.header.pad, b.summary.header.pad);
        assert_eq!(a.summary.header.source_name, b.summary.header.source_name);

        // Summary other properties
        assert_eq!(a.summary.name_map, b.summary.name_map);
        assert_eq!(a.summary.remaining_bytes, b.summary.remaining_bytes);

        // Properties
        assert_eq!(a.properties.len(), b.properties.len());
        for i in 0..a.properties.len() {
            assert_eq!(a.properties[i].name, b.properties[i].name);
            assert_eq!(a.properties[i].arr_index, b.properties[i].arr_index);
            assert_eq!(a.properties[i].data, b.properties[i].data);
        }
    }

    #[test]
    pub fn byte_serialization_is_consistent() {
        let test = get_test_object();

        let mut serialized_bytes = Cursor::new(vec![]);
        test.to_bytes::<_,LE>(&mut serialized_bytes);
        serialized_bytes.set_position(0);
        match IoUObject::from_buffer::<_,LE>(&mut serialized_bytes) {
            Ok(deserialized) => assert_equality(deserialized, get_test_object()),
            Err(err) => panic!("{:?}",err.source()),
        }
    }

    #[test]
    pub fn string_serialization_is_consistent() {
        let test = get_test_object();

        let mut serialized_string = Cursor::new(vec![]);
        test.to_string(&mut serialized_string);
        serialized_string.set_position(0);
        std::io::stdout().write_all(serialized_string.get_ref()).unwrap();
        match IoUObject::from_string(&mut serialized_string) {
            Ok(deserialized) => assert_equality(deserialized, get_test_object()),
            Err(err) => panic!("{:?}",err),
        }
    }
}