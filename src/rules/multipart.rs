use std::str;

#[derive(Debug, Clone)]
pub struct MultipartFinding {
    pub rule_id: &'static str,
    pub description: String,
    pub filename: String,
}

pub fn inspect_multipart(body: &[u8], boundary: &str) -> Vec<MultipartFinding> {
    let mut findings = Vec::new();
    let boundary_bytes = format!("--{}", boundary).into_bytes();
    
    // Find all boundaries
    let mut i = 0;
    while i < body.len() {
        // Find next boundary
        if let Some(pos) = find_subslice(&body[i..], &boundary_bytes) {
            let part_start = i + pos + boundary_bytes.len();
            i = part_start;
            
            // Find end of boundary line (skip \r\n or \n)
            let mut header_start = part_start;
            while header_start < body.len() && (body[header_start] == b'\r' || body[header_start] == b'\n') {
                header_start += 1;
            }
            
            // Find end of this part (next boundary)
            let next_boundary_pos = find_subslice(&body[header_start..], &boundary_bytes);
            let part_end = match next_boundary_pos {
                Some(p) => header_start + p,
                None => body.len(),
            };
            
            if header_start >= part_end {
                continue;
            }
            
            let part_data = &body[header_start..part_end];
            inspect_part(part_data, &mut findings);
        } else {
            break;
        }
    }
    
    findings
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn inspect_part(part_data: &[u8], findings: &mut Vec<MultipartFinding>) {
    // Find header-body separator (\r\n\r\n or \n\n)
    let header_end = find_subslice(part_data, b"\r\n\r\n")
        .map(|p| (p, p + 4))
        .or_else(|| find_subslice(part_data, b"\n\n").map(|p| (p, p + 2)));
        
    let (h_end_pos, body_start) = match header_end {
        Some((e, b)) => (e, b),
        None => return, // Malformed part
    };
    
    let header_bytes = &part_data[..h_end_pos];
    let part_body = &part_data[body_start..];
    
    let header_str = match str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };
    
    // Parse filename and content-type
    let mut filename = None;
    let mut content_type = None;
    
    for line in header_str.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("content-disposition:") {
            // Extract filename="..."
            if let Some(pos) = line_lower.find("filename=") {
                let start = pos + 9;
                let val_part = &line[start..];
                let trimmed = val_part.trim().trim_matches('"').trim_matches('\'');
                filename = Some(trimmed.to_string());
            }
        } else if line_lower.starts_with("content-type:") {
            let val = line["content-type:".len()..].trim();
            content_type = Some(val.to_string());
        }
    }
    
    if let Some(fname) = filename {
        // 1. Double extension check
        if check_double_extension(&fname) {
            findings.push(MultipartFinding {
                rule_id: "MULTIPART-DOUBLE-EXT",
                description: format!("Double extension detected in filename: {}", fname),
                filename: fname.clone(),
            });
        }
        
        // 2. Null byte check
        if check_null_byte(&fname) {
            findings.push(MultipartFinding {
                rule_id: "MULTIPART-NULL-BYTE",
                description: format!("Null byte detected in filename: {}", fname),
                filename: fname.clone(),
            });
        }
        
        // 3. MIME Mismatch / Polyglot check
        if let Some(ref ctype) = content_type {
            if check_mime_mismatch(part_body, ctype) {
                findings.push(MultipartFinding {
                    rule_id: "MULTIPART-MIME-MISMATCH",
                    description: format!("MIME type mismatch or polyglot file for content-type: {}", ctype),
                    filename: fname.clone(),
                });
            }
        }
        
        // 4. Executable content check in file body
        if check_executable_content(part_body) {
            findings.push(MultipartFinding {
                rule_id: "MULTIPART-EXEC-CONTENT",
                description: "Executable code patterns detected in uploaded file body".to_string(),
                filename: fname,
            });
        }
    }
}

fn check_double_extension(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() > 2 {
        for &ext in &parts[1..parts.len() - 1] {
            if matches!(
                ext,
                "php"
                    | "php3"
                    | "php4"
                    | "php5"
                    | "phtml"
                    | "phar"
                    | "jsp"
                    | "jspx"
                    | "jspa"
                    | "asp"
                    | "aspx"
                    | "ashx"
                    | "cer"
                    | "asa"
                    | "exe"
                    | "bat"
                    | "cmd"
                    | "sh"
                    | "bash"
                    | "py"
                    | "pl"
                    | "rb"
                    | "cgi"
            ) {
                return true;
            }
        }
    }
    false
}

fn check_null_byte(filename: &str) -> bool {
    filename.contains('\0') || filename.contains("%00") || filename.contains("\\x00")
}

fn check_mime_mismatch(body: &[u8], content_type: &str) -> bool {
    if body.is_empty() {
        return false;
    }
    
    let ctype_lower = content_type.to_lowercase();
    
    // Check magic bytes
    if ctype_lower.starts_with("image/png") {
        return body.len() < 4 || body[..4] != [0x89, 0x50, 0x4E, 0x47];
    } else if ctype_lower.starts_with("image/jpeg") || ctype_lower.starts_with("image/jpg") {
        return body.len() < 3 || body[..3] != [0xFF, 0xD8, 0xFF];
    } else if ctype_lower.starts_with("image/gif") {
        return body.len() < 4 || body[..4] != *b"GIF8";
    } else if ctype_lower.starts_with("application/pdf") {
        return body.len() < 4 || body[..4] != *b"%PDF";
    }
    
    false
}

fn check_executable_content(body: &[u8]) -> bool {
    // Scan for <?php, <%, #!/bin/sh, etc.
    let patterns: &[&[u8]] = &[
        b"<?php",
        b"<?=",
        b"<script>",
        b"#!/bin/sh",
        b"#!/bin/bash",
        b"#!/usr/bin/env",
        b"eval($_",
        b"system($_",
    ];
    
    for pat in patterns {
        if find_subslice(body, pat).is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_multipart_double_ext() {
        let boundary = "boundary123";
        let body = b"\
--boundary123\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"shell.php.jpg\"\r\n\
Content-Type: image/jpeg\r\n\r\n\
\xff\xd8\xffdummy-content\r\n\
--boundary123--\r\n";

        let findings = inspect_multipart(body, boundary);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MULTIPART-DOUBLE-EXT");
    }

    #[test]
    fn test_inspect_multipart_mime_mismatch() {
        let boundary = "boundary123";
        // Says image/png but body is plain text
        let body = b"\
--boundary123\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"photo.png\"\r\n\
Content-Type: image/png\r\n\r\n\
not-a-png-file\r\n\
--boundary123--\r\n";

        let findings = inspect_multipart(body, boundary);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MULTIPART-MIME-MISMATCH");
    }

    #[test]
    fn test_inspect_multipart_exec_content() {
        let boundary = "boundary123";
        let body = b"\
--boundary123\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\n\
Content-Type: image/jpeg\r\n\r\n\
\xff\xd8\xffdummy<?php eval($_POST['cmd']); ?>\r\n\
--boundary123--\r\n";

        let findings = inspect_multipart(body, boundary);
        assert!(findings.iter().any(|f| f.rule_id == "MULTIPART-EXEC-CONTENT"));
    }
}
