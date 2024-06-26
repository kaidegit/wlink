//! The chip DB.
//! These ids are from the note of function `GetCHIPID` in EVT code, or from datasheet.

#[derive(Copy, Clone)]
pub struct ChipInfo {
    pub name: &'static str,
    pub ram_size: u32,
    pub zw_flash_size: u32,
    pub nzw_flash_size: u32,
}

pub fn chip_id_to_chip_info(chip_id: u32) -> Option<ChipInfo> {
    match chip_id & 0xFFF00000 {
        0x650_00000 => Some(ChipInfo { name: "CH565", ram_size: 112, zw_flash_size: 32, nzw_flash_size: 414 }),
        0x690_00000 => Some(ChipInfo { name: "CH569", ram_size: 112, zw_flash_size: 32, nzw_flash_size: 414 }),
        0x710_00000 => Some(ChipInfo { name: "CH571", ram_size: 18, zw_flash_size: 0, nzw_flash_size: 192 }),
        0x730_00000 => Some(ChipInfo { name: "CH573", ram_size: 18, zw_flash_size: 0, nzw_flash_size: 448 }),
        0x810_00000 => Some(ChipInfo { name: "CH581", ram_size: 32, zw_flash_size: 0, nzw_flash_size: 192 }),
        0x820_00000 => Some(ChipInfo { name: "CH582", ram_size: 32, zw_flash_size: 0, nzw_flash_size: 448 }),
        0x830_00000 => Some(ChipInfo { name: "CH583", ram_size: 32, zw_flash_size: 0, nzw_flash_size: 448 }),
        0x910_00000 => Some(ChipInfo { name: "CH591", ram_size: 26, zw_flash_size: 0, nzw_flash_size: 192 }),
        0x920_00000 => Some(ChipInfo { name: "CH592", ram_size: 26, zw_flash_size: 0, nzw_flash_size: 448 }),
        0x003_00000 => match chip_id & 0xFFFFFF0F {
            0x003_00500 => Some(ChipInfo { name: "CH32V003F4P6", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            0x003_10500 => Some(ChipInfo { name: "CH32V003F4U6", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            0x003_20500 => Some(ChipInfo { name: "CH32V003A4M6", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            0x003_30500 => Some(ChipInfo { name: "CH32V003J4M6", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            _ => None,
        },
        0x035_00000 => match chip_id & 0xFFFFFF0F {
            0x035_00601 => Some(ChipInfo { name: "CH32X035R8T6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x035_10601 => Some(ChipInfo { name: "CH32X035C8T6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x035_E0601 => Some(ChipInfo { name: "CH32X035F8U6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x035_60601 => Some(ChipInfo { name: "CH32X035G8U6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x035_B0601 => Some(ChipInfo { name: "CH32X035G8R6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x035_70601 => Some(ChipInfo { name: "CH32X035F7P6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x035_A0601 => Some(ChipInfo { name: "CH32X033F8P6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            _ => None,
        },
        0x103_00000 => match chip_id & 0xFFFFFF0F {
            0x103_00700 => Some(ChipInfo { name: "CH32L103C8U6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            0x103_10700 => Some(ChipInfo { name: "CH32L103C8T6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            0x103_A0700 => Some(ChipInfo { name: "CH32L103F8P6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            0x103_B0700 => Some(ChipInfo { name: "CH32L103G8R6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            0x103_20700 => Some(ChipInfo { name: "CH32L103K8U6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            0x103_D0700 => Some(ChipInfo { name: "CH32L103F8U6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            0x103_70700 => Some(ChipInfo { name: "CH32L103F7P6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            _ => None,
        },
        0x250_00000 => match chip_id & 0xFFFFFF0F {
            // some_id => Some(ChipInfo { name: "CH32V103C6T6", ram_size: 10, zw_flash_size: 0, nzw_flash_size: 32 }),
            0x250_04102 => Some(ChipInfo { name: "CH32V103C8T6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            // some_id => Some(ChipInfo { name: "CH32V103C8U6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            0x250_0410F => Some(ChipInfo { name: "CH32V103R8T6", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 64 }),
            _ => None,
        },
        0x203_00000 => match chip_id & 0xFFFFFF0F {
            0x203_00500 => Some(ChipInfo { name: "CH32V203C8U6", ram_size: 20, zw_flash_size: 64, nzw_flash_size: 160 }),
            0x203_10500 => Some(ChipInfo { name: "CH32V203C8T6", ram_size: 20, zw_flash_size: 64, nzw_flash_size: 160 }),
            0x203_20500 => Some(ChipInfo { name: "CH32V203K8T6", ram_size: 20, zw_flash_size: 64, nzw_flash_size: 160 }),
            0x203_30500 => Some(ChipInfo { name: "CH32V203C6T6", ram_size: 10, zw_flash_size: 32, nzw_flash_size: 192 }),
            0x203_50500 => Some(ChipInfo { name: "CH32V203K6T6", ram_size: 10, zw_flash_size: 32, nzw_flash_size: 192 }),
            0x203_60500 => Some(ChipInfo { name: "CH32V203G6U6", ram_size: 10, zw_flash_size: 32, nzw_flash_size: 192 }),
            0x203_70500 => Some(ChipInfo { name: "CH32V203F6P6", ram_size: 10, zw_flash_size: 32, nzw_flash_size: 192 }),
            0x203_90500 => Some(ChipInfo { name: "CH32V203F6P6", ram_size: 10, zw_flash_size: 32, nzw_flash_size: 192 }),
            0x203_B0500 => Some(ChipInfo { name: "CH32V203G8R6", ram_size: 20, zw_flash_size: 64, nzw_flash_size: 160 }),
            0x203_E0500 => Some(ChipInfo { name: "CH32V203F8U6", ram_size: 20, zw_flash_size: 64, nzw_flash_size: 160 }),
            0x203_A0500 => Some(ChipInfo { name: "CH32V203F8P6", ram_size: 20, zw_flash_size: 64, nzw_flash_size: 160 }),
            0x203_4050C => Some(ChipInfo { name: "CH32V203RBT6", ram_size: 64, zw_flash_size: 128, nzw_flash_size: 96 }),
            _ => None,
        },
        0x208_00000 => match chip_id & 0xFFFFFF0F {
            0x208_0050C => Some(ChipInfo { name: "CH32V208WBU6", ram_size: 64, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x208_1050C => Some(ChipInfo { name: "CH32V208RBT6", ram_size: 64, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x208_2050C => Some(ChipInfo { name: "CH32V208CBU6", ram_size: 64, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x208_3050C => Some(ChipInfo { name: "CH32V208GBU6", ram_size: 64, zw_flash_size: 128, nzw_flash_size: 352 }),
            _ => None,
        },
        0x303_00000 | 0x305_00000 | 0x307_00000 => match chip_id & 0xFFFFFF0F {
            0x303_30504 => Some(ChipInfo { name: "CH32V303CBT6", ram_size: 32, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x303_20504 => Some(ChipInfo { name: "CH32V303RBT6", ram_size: 32, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x303_10504 => Some(ChipInfo { name: "CH32V303RCT6", ram_size: 64, zw_flash_size: 256, nzw_flash_size: 224 }),
            0x303_00504 => Some(ChipInfo { name: "CH32V303VCT6", ram_size: 64, zw_flash_size: 256, nzw_flash_size: 224 }),
            0x305_20508 => Some(ChipInfo { name: "CH32V305FBP6", ram_size: 32, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x305_00508 => Some(ChipInfo { name: "CH32V305RBT6", ram_size: 32, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x305_B0508 => Some(ChipInfo { name: "CH32V305GBU6", ram_size: 32, zw_flash_size: 128, nzw_flash_size: 352 }),
            0x307_30508 => Some(ChipInfo { name: "CH32V307WCU6", ram_size: 64, zw_flash_size: 256, nzw_flash_size: 224 }),
            0x307_20508 => Some(ChipInfo { name: "CH32V307FBP6", ram_size: 0, zw_flash_size: 0, nzw_flash_size: 0 }),  // There is no CH32V307FBP6 in datasheet.
            0x307_10508 => Some(ChipInfo { name: "CH32V307RCT6", ram_size: 64, zw_flash_size: 256, nzw_flash_size: 224 }),
            0x307_00508 => Some(ChipInfo { name: "CH32V307VCT6", ram_size: 64, zw_flash_size: 256, nzw_flash_size: 224 }),
            _ => None,
        },
        0x641_00000 => match chip_id & 0xFFFFFF0F {
            0x641_00500 => Some(ChipInfo { name: "CH641F", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            0x641_10500 => Some(ChipInfo { name: "CH641D", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            0x641_50500 => Some(ChipInfo { name: "CH641U", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            0x641_60500 => Some(ChipInfo { name: "CH641P", ram_size: 2, zw_flash_size: 0, nzw_flash_size: 16 }),
            _ => None,
        },
        0x643_00000 => match chip_id {
            0x643_00601 => Some(ChipInfo { name: "CH643W", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x643_10601 => Some(ChipInfo { name: "CH643Q", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x643_30601 => Some(ChipInfo { name: "CH643L", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            0x643_40601 => Some(ChipInfo { name: "CH643U", ram_size: 20, zw_flash_size: 0, nzw_flash_size: 62 }),
            _ => None,
        },
        _ => None,
    }
}
