//! Renders the "SHULKER BOX" title shown at the top of the interactive
//! menu, as a small block-letter ASCII banner. Plain ASCII only (`#` and
//! space) — no Unicode box-drawing characters — so it renders correctly
//! even on terminals with a non-UTF-8 code page (e.g. the default Windows
//! `cmd.exe` console).

const GLYPH_HEIGHT: usize = 5;

fn glyph(c: char) -> [&'static str; GLYPH_HEIGHT] {
    match c.to_ascii_uppercase() {
        'S' => [" ### ", "#    ", " ### ", "    #", "#### "],
        'H' => ["#   #", "#   #", "#####", "#   #", "#   #"],
        'U' => ["#   #", "#   #", "#   #", "#   #", " ### "],
        'L' => ["#    ", "#    ", "#    ", "#    ", "#####"],
        'K' => ["#   #", "#  # ", "###  ", "#  # ", "#   #"],
        'E' => ["#####", "#    ", "###  ", "#    ", "#####"],
        'R' => ["#### ", "#   #", "#### ", "#  # ", "#   #"],
        'B' => ["#### ", "#   #", "#### ", "#   #", "#### "],
        'O' => [" ### ", "#   #", "#   #", "#   #", " ### "],
        'X' => ["#   #", " # # ", "  #  ", " # # ", "#   #"],
        _ => ["  ", "  ", "  ", "  ", "  "], // space / unknown
    }
}

/// Renders `word` as a double-sized block ASCII banner, one line per row.
pub fn render(word: &str) -> String {
    let mut rows: [String; GLYPH_HEIGHT] = Default::default();
    for c in word.chars() {
        let g = glyph(c);
        for i in 0..GLYPH_HEIGHT {
            for ch in g[i].chars() {
                rows[i].push(ch);
                rows[i].push(ch); // double width
            }
            rows[i].push_str("  "); // inter-letter gap
        }
    }
    let mut out = String::new();
    for row in &rows {
        // double height: print each row twice
        out.push_str(row);
        out.push('\n');
        out.push_str(row);
        out.push('\n');
    }
    out
}
