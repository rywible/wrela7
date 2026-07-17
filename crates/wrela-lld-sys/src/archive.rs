const GLOBAL_HEADER: &[u8; 8] = b"!<arch>\n";
const MEMBER_HEADER_BYTES: usize = 60;

pub(crate) fn normalize_archive(bytes: &mut [u8]) -> Result<(), String> {
    if bytes.get(..GLOBAL_HEADER.len()) != Some(GLOBAL_HEADER) {
        return Err("archiver output has an invalid archive signature".to_owned());
    }
    let mut offset = GLOBAL_HEADER.len();
    let mut members = 0usize;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(MEMBER_HEADER_BYTES)
            .ok_or_else(|| "archive member header offset overflowed".to_owned())?;
        let header = bytes
            .get_mut(offset..header_end)
            .ok_or_else(|| "archiver output has a truncated member header".to_owned())?;
        if header.get(58..60) != Some(b"`\n") {
            return Err("archiver output has an invalid member header trailer".to_owned());
        }
        let member_bytes = parse_decimal(
            header
                .get(48..58)
                .ok_or_else(|| "archive member size field is absent".to_owned())?,
        )?;
        write_decimal(
            header
                .get_mut(16..28)
                .ok_or_else(|| "archive member timestamp field is absent".to_owned())?,
            0,
        )?;
        write_decimal(
            header
                .get_mut(28..34)
                .ok_or_else(|| "archive member uid field is absent".to_owned())?,
            0,
        )?;
        write_decimal(
            header
                .get_mut(34..40)
                .ok_or_else(|| "archive member gid field is absent".to_owned())?,
            0,
        )?;
        write_decimal(
            header
                .get_mut(40..48)
                .ok_or_else(|| "archive member mode field is absent".to_owned())?,
            100_644,
        )?;
        let data_end = header_end
            .checked_add(member_bytes)
            .ok_or_else(|| "archive member range overflowed".to_owned())?;
        if data_end > bytes.len() {
            return Err("archiver output has a truncated member body".to_owned());
        }
        offset = data_end;
        if member_bytes % 2 != 0 {
            let padding = bytes
                .get_mut(offset)
                .ok_or_else(|| "archiver output omits odd-member padding".to_owned())?;
            *padding = b'\n';
            offset = offset
                .checked_add(1)
                .ok_or_else(|| "archive padding offset overflowed".to_owned())?;
        }
        members = members
            .checked_add(1)
            .ok_or_else(|| "archive member count overflowed".to_owned())?;
    }
    if members == 0 || offset != bytes.len() {
        return Err("archiver output has no exact member sequence".to_owned());
    }
    Ok(())
}

fn parse_decimal(field: &[u8]) -> Result<usize, String> {
    let value = std::str::from_utf8(field)
        .map_err(|_| "archive member size is not ASCII".to_owned())?
        .trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("archive member size is not canonical decimal".to_owned());
    }
    value
        .parse()
        .map_err(|_| "archive member size overflows the host".to_owned())
}

fn write_decimal(field: &mut [u8], value: usize) -> Result<(), String> {
    let value = value.to_string();
    if value.len() > field.len() {
        return Err("normalized archive metadata exceeds its fixed field".to_owned());
    }
    field.fill(b' ');
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(timestamp: &str, uid: &str, gid: &str, mode: &str) -> Vec<u8> {
        let body = b"abc";
        let mut bytes = Vec::from(*GLOBAL_HEADER);
        let mut header = [b' '; MEMBER_HEADER_BYTES];
        header[..4].copy_from_slice(b"x.o/");
        field(&mut header[16..28], timestamp);
        field(&mut header[28..34], uid);
        field(&mut header[34..40], gid);
        field(&mut header[40..48], mode);
        field(&mut header[48..58], "3");
        header[58..].copy_from_slice(b"`\n");
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(body);
        bytes.push(0);
        bytes
    }

    fn field(output: &mut [u8], value: &str) {
        output[..value.len()].copy_from_slice(value.as_bytes());
    }

    #[test]
    fn normalization_removes_host_metadata_and_canonicalizes_padding() {
        let mut first = archive("1720000000", "501", "20", "100755");
        let mut second = archive("1720009999", "1000", "1000", "100600");
        normalize_archive(&mut first).expect("first archive");
        normalize_archive(&mut second).expect("second archive");
        assert_eq!(first, second);
        assert_eq!(&first[24..36], b"0           ");
    }

    #[test]
    fn normalization_rejects_truncated_and_noncanonical_archives() {
        let mut invalid = b"not ar".to_vec();
        assert!(normalize_archive(&mut invalid).is_err());
        let mut truncated = Vec::from(*GLOBAL_HEADER);
        truncated.extend_from_slice(b"member");
        assert!(normalize_archive(&mut truncated).is_err());
    }
}
