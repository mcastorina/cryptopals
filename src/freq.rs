// Performs a frequency analysis on the provided bytes, returning the aggregate score of how likely
// the data is to be English. The higher the score, the more likely.
pub fn analyze(data: &[u8]) -> f64 {
    // Count the number of occurrences of the most common English letters.
    let mut counts = [0; 13];
    for b in data {
        let c = *b as char;
        if let Some(idx) = "etaoin shrdlu".find(c.to_ascii_lowercase()) {
            counts[idx] += 1;
        }
    }

    // Aggregate into a single score by weighing each frequency.
    let weights = [
        0.13, 0.12, 0.11, 0.10, 0.09, 0.08, 0.07, 0.06, 0.05, 0.04, 0.03, 0.02, 0.01,
    ];
    let mut score = 0.0;
    for i in 0..13 {
        let freq = counts[i] as f64 / data.len() as f64;
        score += freq * weights[i];
    }
    score
}
