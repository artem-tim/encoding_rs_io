use std::io::{self, ErrorKind};
use encoding_rs::{Encoding, Encoder};

/// A builder for constructing a byte oriented transcoder from UTF-8 into any encoding supported by encoding_rs.
#[derive(Clone, Debug)]
pub struct EncodeWriterBytesBuilder {
    encoding: Option<&'static Encoding>
}

impl Default for EncodeWriterBytesBuilder {
    fn default() -> EncodeWriterBytesBuilder {
        EncodeWriterBytesBuilder::new()
    }
}

impl EncodeWriterBytesBuilder {
    /// Create a new encoder builder without any encoding
    pub fn new() -> EncodeWriterBytesBuilder {
        EncodeWriterBytesBuilder {
            encoding: None,
        }
    }

    /// Set an explicit encoding to be used by this encoder.
    /// By default, no explicit encoding is set.
    pub fn encoding(
        &mut self,
        encoding: Option<&'static Encoding>,
    ) -> &mut EncodeWriterBytesBuilder {
        self.encoding = encoding;
        self
    }

    /// Build a new encoder that wraps the given writer.
    pub fn build<W: io::Write>(&self, writer: W) -> EncodeWriterBytes<W, Vec<u8>> {
        self.build_with_buffer(writer, vec![0; 8 << 10]).unwrap()
    }

    pub fn build_with_buffer<W: io::Write, B: AsMut<[u8]>>(
        &self,
        writer: W,
        mut buffer: B,
    ) -> io::Result<EncodeWriterBytes<W, B>> {
        let buffer_length = buffer.as_mut().len();
        if buffer_length < 4 {
            let msg = format!(
                "EncodeWriterBytesBuilder: buffer of size {} is too small",
                buffer_length,
            );
            return Err(io::Error::new(io::ErrorKind::Other, msg));
        }

        let max_utf8_buffer_length: Option<usize> = match self.encoding {
            Some(enc) => {
                let decoder = enc.new_decoder();
                match decoder.max_utf8_buffer_length(buffer_length) {
                    Some(bytesize) => Some(bytesize),
                    None => {
                        let msg = format!(
                            "EncodeWriterBytesBuilder: input buffer of size {} overflows after worst case transcoding",
                            buffer_length,
                        );
                        return Err(io::Error::new(io::ErrorKind::Other, msg));
                    }
                }
            },
            None => None,
        };
        
        let encoder = self.encoding.map(|enc| enc.new_encoder());
        Ok(EncodeWriterBytes {
            writer,
            encoder,
            buf: buffer,
            pos: 0,
        })
    }
}
pub struct EncodeWriterBytes<W, B> {
    /// The underlying writer into which the encoded bytes are sent
    writer: W,
    /// The underlying text encoder. If None specified, will write the bytes unchanged
    encoder: Option<Encoder>,
    /// Internal buffer to store transcoded data
    buf: B,
    /// Current position in the buffer
    pos: usize,
}

impl<W: io::Write, B: AsMut<[u8]>> io::Write for EncodeWriterBytes<W, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.encoder.is_none() {
            self.writer.write(buf)
        } else {
            self.transcode(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        todo!()
    }
}

impl<W: io::Write, B: AsMut<[u8]>> EncodeWriterBytes<W, B> {
    /// Transcode `buf` from expected UTF8 before writing into specified writer.
    /// If Ok return the number of bytes written to `buf`.
    fn transcode(&mut self, buf: &[u8]) -> io::Result<usize> {
        let encoder = self.encoder.as_mut().unwrap();
        let (
            code_result,
            total_read,
            total_written,
            had_unmappables,
        ) = match String::from_utf8(buf.to_vec()) { // If performance is preferred over safety, unsafe from_utf8_unchecked is an option
            Ok(str) => {
                let char_indices_iter = str.char_indices();
                /*
                loop {
                    if let Some((new_pos, new_char)) = char_indices_iter.next() { // UTF-8 characters are variable length
                        let start_byte = self.pos + new_pos;
                        let end_byte = start_byte + new_char.len_utf8();
                        //self.buf[new_pos..end_byte] = 
                        //println!("ENCODED ({}-{}): {:?} {:?} {}", pos, pos+b.len_utf8(), encoder.0, encoder.1, encoder.2);
                        //encoder.encode_from_utf8(&str[start_byte..end_byte], self.buf.as_mut(), false)
                    } else {
                        // Buffer fully read. Keep internal buffer as it might not be full just yet before write, and continue processing
                        todo!()
                    }
                }
                */
                println!(": {}", &str);
                println!("BEFORE: {:?}", self.buf.as_mut());
                encoder.encode_from_utf8(&str, self.buf.as_mut(), false)
            },
            Err(_) => {
                return Err(io::Error::new(ErrorKind::Other, "Non-UTF8 input"));
            },
        };
        println!("AFTER: {:?}", self.buf.as_mut());
        println!("RESULT : {} / {} / {}", total_read, total_written, had_unmappables);
        match code_result {
            encoding_rs::CoderResult::InputEmpty => {
                // This case happens when there is nothing to input. Or when another call has been made after a call having last flag set to true
                println!(">>> INPUT EMPTY");
            },
            encoding_rs::CoderResult::OutputFull => {
                // This case happens when the ouput buffer is too small to fit transcoded bytes
                println!(">>> OUTPUT FULL");

            },
        }
        println!(" >>> RES: {:?} | READ : {}, WRITTEN : {}, HAS_UNMAP : {}", code_result, total_read, total_written, had_unmappables);
        self.writer.write(self.buf.as_mut())
    }
}


#[cfg(test)]
mod tests {
    use std::io::{Write, Read};

    use encoding_rs::{EUC_JP, UTF_16BE, SHIFT_JIS, ISO_2022_JP, Decoder};

    use super::EncodeWriterBytesBuilder;

    #[test]
    fn dec_enc_compare() {
        let t_utf8 = "ハロー世界";
        let t_iso_2022_jp = b"\x1B\x24\x42\x25\x4F\x25\x6D\x21\x3C\x40\x24\x33\x26\x1B\x28\x42";

        {
            let mut dec = ISO_2022_JP.new_decoder();
            let mut dst = [0 as u8; 6];
            let out = dec.decode_to_utf8(t_iso_2022_jp, &mut dst, false);
            println!("Partially decoded : {:?}", dst);
            println!("Result : {:?}", out);
        }

        {
            let mut enc = ISO_2022_JP.new_encoder();
            let mut dst = [0 as u8; 6];
            let out = enc.encode_from_utf8(t_utf8, &mut dst, false);
            println!("Partially encoded : {:?}", dst);
            println!("Result : {:?}", out);
        }
    }

    #[test]
    fn tmptest() {
        let t_utf8 = "ハロー世界";
        let t_sjis = b"\x83\x6E\x83\x8D\x81\x5B\x90\xA2\x8A\x45";
        let t_iso_2022_jp = b"\x1B\x24\x42\x25\x4F\x25\x6D\x21\x3C\x40\x24\x33\x26\x1B\x28\x42";

        let tmpbuf: [u8; 20] = [0;20];
        let srcbuf: Vec<u8> = t_iso_2022_jp.to_vec();
        let mut rdr = crate::DecodeReaderBytesBuilder::new()
            .encoding(Some(ISO_2022_JP))
            .build_with_buffer(&*srcbuf, tmpbuf)
            .unwrap();

        let mut outbuf = [0 as u8; 20];
        
        loop {
            if let Ok(readed) = rdr.read(&mut outbuf) {
                if readed != 0 {
                    println!("[READ] {}", readed);
                } else {
                    println!("[READ 0. END]");
                    break;
                }
            } else {
                break;
            }
        }
        //let out_bytes: Vec<u8> = std::io::Read::bytes(rdr).map(|res| res.unwrap()).collect();
        println!("[FINAL]: {:?}", outbuf);
        println!("[ORIG]: {:?}", srcbuf);
        println!("[EXPECTED]: {:?}", t_utf8.bytes());
    }

    #[test]
    fn trans_euc_jp() {
        ////
        let t_utf8 = String::from("ハロー世界");
        let t_iso_2022_jp = b"\x1B\x24\x42\x25\x4F\x25\x6D\x21\x3C\x40\x24\x33\x26\x1B\x28\x42";

        let mut outbuf: Vec<u8> = vec![];
        let buf: [u8; 10] = [0; 10];
        let mut encoder = EncodeWriterBytesBuilder::new()
            .encoding(Some(ISO_2022_JP))
            .build_with_buffer(&mut outbuf, buf)
            .unwrap();
        
        let total_written = encoder.write(t_utf8.as_bytes());
        println!(" >>> [RESULT] : {:?}", outbuf);
        println!(" >>> [EXPECTED] : {:?}", t_iso_2022_jp);
    }
}