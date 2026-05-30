//! Minimal PDF 1.4 generator for the recovery phrase kit.
//!
//! Generates a single-page document with a title, body text (the 12 recovery
//! words), and optional key-value metadata lines. Uses raw PDF construction
//! with Helvetica (built-in, no embedding required).
//!
//! The output is a valid PDF 1.4 file that opens in any PDF viewer.

/// A positioned text element in the PDF.
pub struct PdfText {
    pub text: String,
    pub x: f32,
    pub y: f32,
    pub font_size: f32,
    pub bold: bool,
}

// ---------------------------------------------------------------------------
// PDF object builder
// ---------------------------------------------------------------------------

struct PdfBuilder {
    buf: Vec<u8>,
    offsets: Vec<usize>, // 0-indexed: offsets[0] = offset of object 1
}

impl PdfBuilder {
    fn new() -> Self {
        let mut buf = Vec::with_capacity(4096);
        // PDF header + binary comment (signals binary content to transports)
        buf.extend_from_slice(b"%PDF-1.4\n%\xFF\xFF\xFF\xFF\n");
        Self {
            buf,
            offsets: Vec::new(),
        }
    }

    /// Start a new indirect object. Returns the 1-based object number.
    fn begin_object(&mut self) -> usize {
        let obj_num = self.offsets.len() + 1;
        self.offsets.push(self.buf.len());
        let header = format!("{obj_num} 0 obj\n");
        self.buf.extend_from_slice(header.as_bytes());
        obj_num
    }

    fn write(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn write_str(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }

    fn end_object(&mut self) {
        self.buf.extend_from_slice(b"\nendobj\n");
    }

    /// Write the xref table, trailer, and %%EOF. Consumes the builder.
    fn finish(mut self, catalog_obj: usize) -> Vec<u8> {
        let xref_offset = self.buf.len();
        let num_objects = self.offsets.len() + 1; // +1 for the free object 0

        let mut xref = format!("xref\n0 {num_objects}\n");
        xref.push_str("0000000000 65535 f \n");
        for &offset in &self.offsets {
            xref.push_str(&format!("{:010} 00000 n \n", offset));
        }
        self.buf.extend_from_slice(xref.as_bytes());

        let trailer =
            format!("trailer\n<< /Size {num_objects} /Root {catalog_obj} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n");
        self.buf.extend_from_slice(trailer.as_bytes());
        self.buf
    }
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/// Escape special PDF string characters: backslash, parens.
fn pdf_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            _ => out.push(c),
        }
    }
    out
}

/// Approximate width of a string in Helvetica at the given font size.
/// Uses a simplified metric (average char width ~0.5 * font_size for regular,
/// ~0.53 for bold). Good enough for layout, not typesetting.
fn approx_text_width(text: &str, font_size: f32, bold: bool) -> f32 {
    let factor = if bold { 0.53 } else { 0.50 };
    text.len() as f32 * font_size * factor
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Page dimensions (US Letter in points).
const PAGE_WIDTH: f32 = 612.0;
const PAGE_HEIGHT: f32 = 792.0;
const MARGIN: f32 = 60.0;

/// Generate a single-page recovery kit PDF.
///
/// - `title`: large heading at the top (e.g. "Beebeeb Recovery Kit")
/// - `words`: the 12 recovery words (displayed in a numbered 2-column grid)
/// - `metadata`: key-value pairs displayed below the words (e.g. ("Email", "user@example.com"))
///
/// Returns the raw PDF bytes.
pub fn generate_recovery_pdf(title: &str, words: &[String], metadata: &[(&str, &str)]) -> Vec<u8> {
    let mut pdf = PdfBuilder::new();

    // --- Object 1: Catalog ---
    let catalog = pdf.begin_object();
    pdf.write_str("<< /Type /Catalog /Pages 2 0 R >>");
    pdf.end_object();

    // --- Object 2: Pages ---
    let _pages = pdf.begin_object();
    pdf.write_str("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    pdf.end_object();

    // --- Build content stream ---
    let content = build_content_stream(title, words, metadata);

    // --- Object 3: Page ---
    let _page = pdf.begin_object();
    pdf.write_str(&format!(
        "<< /Type /Page /Parent 2 0 R \
         /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] \
         /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> \
         /Contents 4 0 R >>"
    ));
    pdf.end_object();

    // --- Object 4: Content stream ---
    let _content_obj = pdf.begin_object();
    pdf.write_str(&format!("<< /Length {} >>\nstream\n", content.len()));
    pdf.write(content.as_bytes());
    pdf.write_str("\nendstream");
    pdf.end_object();

    // --- Object 5: Font (Helvetica) ---
    let _font_regular = pdf.begin_object();
    pdf.write_str("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    pdf.end_object();

    // --- Object 6: Font (Helvetica-Bold) ---
    let _font_bold = pdf.begin_object();
    pdf.write_str("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
    pdf.end_object();

    pdf.finish(catalog)
}

/// Build the text content stream for the recovery kit page.
fn build_content_stream(title: &str, words: &[String], metadata: &[(&str, &str)]) -> String {
    let mut stream = String::with_capacity(2048);
    let usable_width = PAGE_WIDTH - 2.0 * MARGIN;

    // --- Title ---
    let title_size: f32 = 22.0;
    let title_y = PAGE_HEIGHT - MARGIN - title_size;
    let title_width = approx_text_width(title, title_size, true);
    let title_x = MARGIN + (usable_width - title_width) / 2.0;

    stream.push_str("BT\n");
    stream.push_str(&format!(
        "/F2 {} Tf\n{} {} Td\n({}) Tj\n",
        fmt_f32(title_size),
        fmt_f32(title_x.max(MARGIN)),
        fmt_f32(title_y),
        pdf_escape(title)
    ));
    stream.push_str("ET\n");

    // --- Separator line ---
    let line_y = title_y - 14.0;
    stream.push_str(&format!(
        "0.85 0.85 0.85 RG\n0.5 w\n{} {} m {} {} l S\n",
        fmt_f32(MARGIN),
        fmt_f32(line_y),
        fmt_f32(PAGE_WIDTH - MARGIN),
        fmt_f32(line_y)
    ));

    // --- Subtitle ---
    let subtitle_size: f32 = 10.0;
    let subtitle_y = line_y - 20.0;
    stream.push_str("BT\n");
    stream.push_str(&format!(
        "0.4 0.4 0.4 rg\n/F1 {} Tf\n{} {} Td\n(Store this document in a safe place. These words are the only way to recover your account.) Tj\n",
        fmt_f32(subtitle_size),
        fmt_f32(MARGIN),
        fmt_f32(subtitle_y),
    ));
    stream.push_str("0 0 0 rg\n"); // reset color
    stream.push_str("ET\n");

    // --- Recovery words: 2-column numbered grid ---
    let words_start_y = subtitle_y - 30.0;
    let word_size: f32 = 13.0;
    let line_height: f32 = 22.0;
    let col_width = usable_width / 2.0;

    // words per column
    let rows = words.len().div_ceil(2);

    for (i, word) in words.iter().enumerate() {
        let col = i / rows;
        let row = i % rows;
        let x = MARGIN + col as f32 * col_width + 10.0;
        let y = words_start_y - row as f32 * line_height;

        // Number label (bold, grey)
        let num_label = format!("{:>2}.", i + 1);
        stream.push_str("BT\n");
        stream.push_str(&format!(
            "0.5 0.5 0.5 rg\n/F2 {} Tf\n{} {} Td\n({}) Tj\n",
            fmt_f32(word_size),
            fmt_f32(x),
            fmt_f32(y),
            pdf_escape(&num_label),
        ));
        stream.push_str("ET\n");

        // Word (regular, black)
        stream.push_str("BT\n");
        stream.push_str(&format!(
            "0 0 0 rg\n/F1 {} Tf\n{} {} Td\n({}) Tj\n",
            fmt_f32(word_size),
            fmt_f32(x + 30.0),
            fmt_f32(y),
            pdf_escape(word),
        ));
        stream.push_str("ET\n");
    }

    // --- Metadata key-value pairs ---
    if !metadata.is_empty() {
        let meta_start_y = words_start_y - rows as f32 * line_height - 30.0;
        let meta_size: f32 = 10.0;
        let meta_line_height: f32 = 16.0;

        // Separator
        stream.push_str(&format!(
            "0.85 0.85 0.85 RG\n0.5 w\n{} {} m {} {} l S\n",
            fmt_f32(MARGIN),
            fmt_f32(meta_start_y + 10.0),
            fmt_f32(PAGE_WIDTH - MARGIN),
            fmt_f32(meta_start_y + 10.0)
        ));

        for (i, (key, value)) in metadata.iter().enumerate() {
            let y = meta_start_y - i as f32 * meta_line_height;

            // Key (bold, grey)
            stream.push_str("BT\n");
            stream.push_str(&format!(
                "0.4 0.4 0.4 rg\n/F2 {} Tf\n{} {} Td\n({}) Tj\n",
                fmt_f32(meta_size),
                fmt_f32(MARGIN),
                fmt_f32(y),
                pdf_escape(key),
            ));
            stream.push_str("ET\n");

            // Value (regular, black)
            stream.push_str("BT\n");
            stream.push_str(&format!(
                "0 0 0 rg\n/F1 {} Tf\n{} {} Td\n({}) Tj\n",
                fmt_f32(meta_size),
                fmt_f32(MARGIN + 100.0),
                fmt_f32(y),
                pdf_escape(value),
            ));
            stream.push_str("ET\n");
        }

        // --- Footer ---
        let footer_y = meta_start_y - metadata.len() as f32 * meta_line_height - 30.0;
        stream.push_str("BT\n");
        stream.push_str(&format!(
            "0.6 0.6 0.6 rg\n/F1 8 Tf\n{} {} Td\n(Generated by Beebeeb — beebeeb.io) Tj\n",
            fmt_f32(MARGIN),
            fmt_f32(footer_y.max(MARGIN)),
        ));
        stream.push_str("0 0 0 rg\nET\n");
    }

    stream
}

/// Format an f32 for PDF operators — strips trailing zeros.
fn fmt_f32(n: f32) -> String {
    if !n.is_finite() {
        return "0".to_string();
    }
    let s = format!("{:.2}", n);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_starts_with_magic_bytes() {
        let words: Vec<String> = (1..=12).map(|i| format!("word{i}")).collect();
        let pdf = generate_recovery_pdf("Test Recovery Kit", &words, &[]);
        assert!(pdf.starts_with(b"%PDF-1.4"));
    }

    #[test]
    fn pdf_ends_with_eof() {
        let words: Vec<String> = vec!["abandon".into(); 12];
        let pdf = generate_recovery_pdf("Kit", &words, &[]);
        let tail = String::from_utf8_lossy(&pdf[pdf.len().saturating_sub(8)..]);
        assert!(tail.contains("%%EOF"));
    }

    #[test]
    fn pdf_contains_title() {
        let words: Vec<String> = vec!["test".into(); 12];
        let pdf = generate_recovery_pdf("Beebeeb Recovery Kit", &words, &[]);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("Beebeeb Recovery Kit"));
    }

    #[test]
    fn pdf_contains_words() {
        let words: Vec<String> = vec!["apple".into(), "banana".into(), "cherry".into()];
        let pdf = generate_recovery_pdf("Test", &words, &[]);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("apple"));
        assert!(text.contains("banana"));
        assert!(text.contains("cherry"));
    }

    #[test]
    fn pdf_contains_metadata() {
        let words: Vec<String> = vec!["test".into(); 12];
        let metadata = vec![("Email", "user@beebeeb.io"), ("Created", "2026-05-18")];
        let pdf = generate_recovery_pdf("Kit", &words, &metadata);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("user@beebeeb.io"));
        assert!(text.contains("2026-05-18"));
    }

    #[test]
    fn pdf_has_valid_xref_structure() {
        let words: Vec<String> = vec!["test".into(); 12];
        let pdf = generate_recovery_pdf("Kit", &words, &[]);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("xref"));
        assert!(text.contains("trailer"));
        assert!(text.contains("startxref"));
    }

    #[test]
    fn pdf_escapes_special_chars() {
        let words: Vec<String> = vec!["test(parens)\\backslash".into()];
        let pdf = generate_recovery_pdf("Title (with parens)", &words, &[]);
        let text = String::from_utf8_lossy(&pdf);
        // The raw parens in the word should be escaped
        assert!(text.contains("test\\(parens\\)\\\\backslash"));
    }

    #[test]
    fn pdf_empty_words() {
        let pdf = generate_recovery_pdf("Kit", &[], &[]);
        assert!(pdf.starts_with(b"%PDF-1.4"));
    }

    #[test]
    fn pdf_contains_all_six_objects() {
        let words: Vec<String> = vec!["test".into(); 12];
        let pdf = generate_recovery_pdf("Kit", &words, &[]);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("1 0 obj"));
        assert!(text.contains("2 0 obj"));
        assert!(text.contains("3 0 obj"));
        assert!(text.contains("4 0 obj"));
        assert!(text.contains("5 0 obj"));
        assert!(text.contains("6 0 obj"));
    }
}
