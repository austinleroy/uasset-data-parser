use byteorder::LE;
use config::{Config, Command};
use iostore_uasset::IoUObject;
use std::{fs::File, process, env, error::Error, io::BufReader};

mod iostore_uasset;
mod config;

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
    }
    Ok(())
}

#[allow(dead_code)]
mod test {
    use std::{fs::File, io::{Cursor, Read}};
    use byteorder::LE;
    use crate::iostore_uasset::IoUObject;

    fn verify_decode_and_reencode(filepath: &str) {
        let mut original_file_bytes = {
            let mut file_bytes = vec![];
            File::open(filepath).unwrap().read_to_end(&mut file_bytes).unwrap();
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
    
    #[test]
    pub fn add_content_bundle_name_data_asset() {
        verify_decode_and_reencode("test/AddContentBundleNameDataAsset.uasset");
    }

    #[test]
    pub fn add_content_data_asset() {
        verify_decode_and_reencode("test/AddContentDataAsset.uasset");
    }

    #[test]
    pub fn add_content_disp_name_data_asset() {
        verify_decode_and_reencode("test/AddContentDispNameDataAsset.uasset");
    }

    #[test]
    pub fn add_content_entitlement_name_data_asset() {
        verify_decode_and_reencode("test/AddContentEntitlementNameDataAsset.uasset");
    }

    #[test]
    pub fn bustup_anim_data_asset() {
        verify_decode_and_reencode("test/BustupAnimDataAsset.uasset");
    }

    #[test]
    pub fn bustup_environment_data_asset() {
        verify_decode_and_reencode("test/BustupEnvironmentDataAsset.uasset");
    }

    #[test]
    pub fn bustup_exist_data_asset() {
        verify_decode_and_reencode("test/BustupExistDataAsset.uasset");
    }

    #[test]
    pub fn bustup_gradation_data_asset() {
        verify_decode_and_reencode("test/BustupGradationDataAsset.uasset");
    }

    #[test]
    pub fn cmm_profile_help_data_asset() {
        verify_decode_and_reencode("test/CmmProfileHelpDataAsset.uasset");
    }

    #[test]
    pub fn dat_antique_shop_lineup_data_asset() {
        verify_decode_and_reencode("test/DatAntiqueShopLineupDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_accs_data_asset() {
        verify_decode_and_reencode("test/DatItemAccsDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_accs_name_data_asset() {
        verify_decode_and_reencode("test/DatItemAccsNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_armor_data_asset() {
        verify_decode_and_reencode("test/DatItemArmorDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_armor_name_data_asset() {
        verify_decode_and_reencode("test/DatItemArmorNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_common_data_asset() {
        verify_decode_and_reencode("test/DatItemCommonDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_common_name_data_asset() {
        verify_decode_and_reencode("test/DatItemCommonNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_costume_data_asset() {
        verify_decode_and_reencode("test/DatItemCostumeDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_costume_name_data_asset() {
        verify_decode_and_reencode("test/DatItemCostumeNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_evitem_data_asset() {
        verify_decode_and_reencode("test/DatItemEvitemDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_evitem_name_data_asset() {
        verify_decode_and_reencode("test/DatItemEvitemNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_material_data_asset() {
        verify_decode_and_reencode("test/DatItemMaterialDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_material_name_data_asset() {
        verify_decode_and_reencode("test/DatItemMaterialNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_shoes_data_asset() {
        verify_decode_and_reencode("test/DatItemShoesDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_shoes_name_data_asset() {
        verify_decode_and_reencode("test/DatItemShoesNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_shop_lineup_data_asset() {
        verify_decode_and_reencode("test/DatItemShopLineupDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_skillcard_data_asset() {
        verify_decode_and_reencode("test/DatItemSkillcardDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_skillcard_name_data_asset() {
        verify_decode_and_reencode("test/DatItemSkillcardNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_weapon_data_asset() {
        verify_decode_and_reencode("test/DatItemWeaponDataAsset.uasset");
    }

    #[test]
    pub fn dat_item_weapon_name_data_asset() {
        verify_decode_and_reencode("test/DatItemWeaponNameDataAsset.uasset");
    }

    #[test]
    pub fn dat_suggestion_data_asset() {
        verify_decode_and_reencode("test/DatSuggestionDataAsset.uasset");
    }

    #[test]
    pub fn dat_suggestion_text_data_asset() {
        verify_decode_and_reencode("test/DatSuggestionTextDataAsset.uasset");
    }

    #[test]
    pub fn dat_weapon_shop_lineup_data_asset() {
        verify_decode_and_reencode("test/DatWeaponShopLineupDataAsset.uasset");
    }

    #[test]
    pub fn disappear_data_asset() {
        verify_decode_and_reencode("test/DisappearDataAsset.uasset");
    }

    #[test]
    pub fn font_adjustment_data_asset() {
        verify_decode_and_reencode("test/FontAdjustmentDataAsset.uasset");
    }

    #[test]
    pub fn mail_incoming_data_asset() {
        verify_decode_and_reencode("test/MailIncomingDataAsset.uasset");
    }

    #[test]
    pub fn name_entry_cnv_char_data_asset() {
        verify_decode_and_reencode("test/NameEntryCnvCharDataAsset.uasset");
    }

    #[test]
    pub fn persona_list_layout_data_asset() {
        verify_decode_and_reencode("test/PersonaListLayoutDataAsset.uasset");
    }

    #[test]
    pub fn persona_status_layout_data_asset() {
        verify_decode_and_reencode("test/PersonaStatusLayoutDataAsset.uasset");
    }

    #[test]
    pub fn support_bustup_data_asset() {
        verify_decode_and_reencode("test/SupportBustupDataAsset.uasset");
    }

    #[test]
    pub fn uitext_data_asset() {
        verify_decode_and_reencode("test/UITextDataAsset.uasset");
    }

    #[test]
    pub fn velvet_room_quest_data_asset() {
        verify_decode_and_reencode("test/VelvetRoomQuestDataAsset.uasset");
    }

}