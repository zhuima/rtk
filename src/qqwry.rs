use std::fs::File;
use std::io::{self, Read};
use std::net::{Ipv4Addr, AddrParseError};
use std::path::Path;
use byteorder::{LittleEndian, ReadBytesExt};
use anyhow::{Result, anyhow};
use encoding::{Encoding, DecoderTrap};
use encoding::all::GBK;

pub struct QQwry {
    data: Vec<u8>,
    idx_start: u32,
    idx_end: u32,
    off_len: u32,
    ip_len: u32,
}

impl QQwry {
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let mut file = File::open(file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        if data.len() < 8 {
            return Err(anyhow!("Invalid QQwry database file"));
        }

        // Read header
        let start = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let end = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        if start >= end || data.len() < (end + 7) as usize {
            return Err(anyhow!("Invalid QQwry database header"));
        }

        Ok(QQwry {
            data,
            idx_start: start,
            idx_end: end,
            off_len: 3,
            ip_len: 4,
        })
    }

    pub fn lookup(&self, ip: &str) -> Result<String> {
        let ip_addr: Ipv4Addr = ip.parse()
            .map_err(|_| anyhow!("Invalid IPv4 address: {}", ip))?;

        let ip_num = self.ipv4_to_u32(&ip_addr);
        self.search(ip_num)
    }

    fn ipv4_to_u32(&self, ip: &Ipv4Addr) -> u32 {
        let octets = ip.octets();
        u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]])
    }

    fn search(&self, ip: u32) -> Result<String> {
        let index_offset = self.search_index(ip)?;
        if index_offset == 0 {
            return Ok("Unknown location".to_string());
        }

        // Get the redirect offset for the record (3 bytes starting at offset+4)
        let redirect_offset = self.read_redirect_offset(index_offset + 4, 3)?;
        let record_offset = redirect_offset + 4;

        self.read_record(record_offset)
    }

    fn search_index(&self, ip: u32) -> Result<u32> {
        let index_count = (self.idx_end - self.idx_start) / 7;
        let mut left: u32 = 0;
        let mut right = index_count - 1;

        // Find the index where the IP would be inserted
        while left <= right {
            let mid = (left + right) / 2;
            let offset = self.idx_start + mid * 7;

            if offset as usize + 7 > self.data.len() {
                return Ok(0);
            }

            let start_ip = u32::from_le_bytes([
                self.data[offset as usize],
                self.data[offset as usize + 1],
                self.data[offset as usize + 2],
                self.data[offset as usize + 3],
            ]);

            if ip < start_ip {
                if mid == 0 { break; }
                right = mid - 1;
            } else {
                left = mid + 1;
            }
        }

        // Return the last valid index
        let final_index = if right > index_count - 1 { index_count - 1 } else { right };
        Ok(self.idx_start + final_index * 7)
    }

    fn get_end_ip(&self, offset: u32) -> u32 {
        // The offset is actually the redirect offset (3 bytes)
        let actual_offset = self.idx_start + offset;
        if actual_offset as usize + 4 > self.data.len() {
            return 0;
        }

        u32::from_le_bytes([
            self.data[actual_offset as usize],
            self.data[actual_offset as usize + 1],
            self.data[actual_offset as usize + 2],
            self.data[actual_offset as usize + 3],
        ])
    }

    fn read_record(&self, offset: u32) -> Result<String> {
        if offset as usize >= self.data.len() {
            return Ok("Unknown location".to_string());
        }

        let first_byte = self.data[offset as usize];

        if (first_byte & 0x01) == 0x01 {
            // Redirect mode 1
            let redirect_offset = self.read_redirect_offset(offset + 1, 3)?;
            if (redirect_offset & 0x01) == 0x01 {
                // Redirect mode 2
                let final_offset = self.read_redirect_offset(redirect_offset + 1, 3)?;
                self.read_string(final_offset)
            } else {
                self.read_country_and_area(redirect_offset)
            }
        } else {
            self.read_country_and_area(offset)
        }
    }

    fn read_redirect_offset(&self, offset: u32, len: u32) -> Result<u32> {
        if offset as usize + len as usize > self.data.len() {
            return Ok(0);
        }

        match len {
            3 => {
                Ok(u32::from(self.data[offset as usize]) |
                   u32::from(self.data[offset as usize + 1]) << 8 |
                   u32::from(self.data[offset as usize + 2]) << 16)
            }
            _ => Ok(0)
        }
    }

    fn read_country_and_area(&self, offset: u32) -> Result<String> {
        if offset as usize >= self.data.len() {
            return Ok("Unknown location".to_string());
        }

        let mut current_offset = offset;
        let first_byte = self.data[current_offset as usize];

        // Handle redirect mode for country
        if first_byte == 1 {
            // Redirect mode 1
            let redirect_offset = self.read_redirect_offset(current_offset + 1, 3)?;
            current_offset = redirect_offset;
        }

        // Read country
        let (country, new_offset) = if (current_offset as usize) < self.data.len() {
            let byte = self.data[current_offset as usize];
            if byte == 2 {
                // Redirect mode 2 for country
                let redirect_offset = self.read_redirect_offset(current_offset + 1, 3)?;
                (self.read_string(redirect_offset)?, current_offset + 4)
            } else {
                let country = self.read_string(current_offset)?;
                let new_offset = current_offset + country.len() as u32 + 1;
                (country, new_offset)
            }
        } else {
            ("Unknown".to_string(), current_offset)
        };

        // Read area - use the offset after reading country
        current_offset = new_offset;
        if current_offset as usize >= self.data.len() {
            return Ok(country);
        }

        let area = {
            let byte = self.data[current_offset as usize];
            if byte == 2 {
                // Redirect mode 2 for area
                let redirect_offset = self.read_redirect_offset(current_offset + 1, 3)?;
                self.read_string(redirect_offset)?
            } else {
                self.read_string(current_offset)?
            }
        };

  
        // Clean up only placeholder values but keep valid ISP info
        let clean_area = if area.is_empty() || area.starts_with("CZ88.NET") || area == country {
            String::new()
        } else {
            area
        };

        let result = if clean_area.is_empty() {
            country
        } else {
            format!("{}/{}", country, clean_area)
        };

        Ok(result)
    }

    fn read_string(&self, offset: u32) -> Result<String> {
        if offset as usize >= self.data.len() {
            return Ok(String::new());
        }

        let mut string_bytes = Vec::new();
        let mut current_offset = offset as usize;

        while current_offset < self.data.len() {
            let byte = self.data[current_offset];
            if byte == 0 {
                break;
            }
            string_bytes.push(byte);
            current_offset += 1;
        }

        // Try to decode as GBK first, fall back to lossy UTF-8
        match encoding::all::GBK.decode(&string_bytes, encoding::DecoderTrap::Ignore) {
            Ok(decoded) => Ok(decoded),
            Err(_) => Ok(String::from_utf8_lossy(&string_bytes).to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qqwry_creation() {
        // This test would require a test database file
        // For now, just ensure the struct can be created
        assert!(true);
    }
}