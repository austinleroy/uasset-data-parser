#[allow(non_snake_case)]
mod test_files {
    use std::{fs::File, io::{Cursor, Read}, path::Path};
    
    use byteorder::LE;
    use test_each_file::test_each_path;
    use uasset_data_parser::IoUObject;

    test_each_path!{ for ["uasset"] in "./test_files" => test}
    
    fn test(path: [&Path; 1]) {
        let mut original_file_bytes = {
            let mut file_bytes = vec![];
            File::open(path[0]).unwrap().read_to_end(&mut file_bytes).unwrap();
            Cursor::new(file_bytes)
        };
        
        let deserialized_file = match IoUObject::from_buffer::<_, LE>(&mut original_file_bytes) {
            Ok(deserialized) => deserialized,
            Err(err) => panic!("{:?}",err),
        };
        
        let mut serialized_string = Cursor::new(vec![]);
        deserialized_file.to_string(&mut serialized_string);
        
        // Print string to help with debugging purposes
        let string_content = String::from_utf8(serialized_string.clone().into_inner()).unwrap();
        println!("{string_content}");
        
        serialized_string.set_position(0);
        let deserialized_string = match IoUObject::from_string(&mut serialized_string) {
            Ok(deserialized) => deserialized,
            Err(err) => panic!("{:?}",err),
        };
        
        let mut final_bytes = vec![];
        deserialized_string.to_bytes::<_, LE>(&mut final_bytes);

        for (i, byte) in original_file_bytes.into_inner().iter().enumerate() {
            assert_eq!(byte, &final_bytes[i], "File bytes differ at 0x{i:x}");
        }
    }
}