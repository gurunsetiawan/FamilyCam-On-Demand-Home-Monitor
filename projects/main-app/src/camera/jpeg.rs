const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];
const MAX_BUFFER_BYTES: usize = 4 * 1024 * 1024;

pub struct JpegFrameAccumulator {
    buffer: Vec<u8>,
}

impl JpegFrameAccumulator {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        self.buffer.extend_from_slice(chunk);
        if self.buffer.len() > MAX_BUFFER_BYTES {
            let overflow = self.buffer.len() - MAX_BUFFER_BYTES;
            self.buffer.drain(0..overflow);
        }

        let mut latest_frame = None;
        loop {
            let Some(start) = find_marker(&self.buffer, &JPEG_SOI) else {
                self.buffer.clear();
                break;
            };

            let Some(end_rel) = find_marker(&self.buffer[start + 2..], &JPEG_EOI) else {
                if start > 0 {
                    self.buffer.drain(0..start);
                }
                break;
            };

            let end = start + 2 + end_rel + 2;
            latest_frame = Some(self.buffer[start..end].to_vec());
            self.buffer.drain(0..end);
        }

        latest_frame
    }
}

fn find_marker(buffer: &[u8], marker: &[u8; 2]) -> Option<usize> {
    buffer.windows(2).position(|w| w == marker)
}

#[cfg(test)]
mod tests {
    use super::JpegFrameAccumulator;

    fn fake_jpeg(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        out.extend_from_slice(payload);
        out.extend_from_slice(&[0xFF, 0xD9]);
        out
    }

    #[test]
    fn extracts_frame_from_single_chunk() {
        let mut acc = JpegFrameAccumulator::new();
        let frame = fake_jpeg(b"abc");
        let mut chunk = b"header".to_vec();
        chunk.extend_from_slice(&frame);
        chunk.extend_from_slice(b"tail");

        let out = acc.push_chunk(&chunk).expect("frame should be found");
        assert_eq!(out, frame);
    }

    #[test]
    fn extracts_frame_across_multiple_chunks() {
        let mut acc = JpegFrameAccumulator::new();
        let frame = fake_jpeg(b"hello-world");
        let split = 5;
        let first = &frame[..split];
        let second = &frame[split..];

        assert!(acc.push_chunk(first).is_none());
        let out = acc
            .push_chunk(second)
            .expect("frame should be reconstructed");
        assert_eq!(out, frame);
    }

    #[test]
    fn keeps_latest_frame_if_multiple_frames_present() {
        let mut acc = JpegFrameAccumulator::new();
        let frame1 = fake_jpeg(b"111");
        let frame2 = fake_jpeg(b"222");
        let mut chunk = frame1;
        chunk.extend_from_slice(&frame2);

        let out = acc.push_chunk(&chunk).expect("frame should be found");
        assert_eq!(out, frame2);
    }
}
