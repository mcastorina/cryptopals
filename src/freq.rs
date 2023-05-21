use std::borrow::Borrow;

pub trait FreqAnalyzerExt: Iterator {
    fn ascii_freq_score(self) -> f64
    where
        Self: Sized,
        <Self as Iterator>::Item: Borrow<u8>,
    {
        // Count the number of occurrences of the most common English letters.
        let mut counts = [0; 13];
        let mut len = 0;
        for b in self {
            let c = *b.borrow() as char;
            if !c.is_ascii() {
                return 0.0;
            }
            if let Some(idx) = "etaoin shrdlu".find(c.to_ascii_lowercase()) {
                counts[idx] += 1;
            }
            len += 1;
        }

        // Aggregate into a single score by weighing each frequency.
        let weights = [
            0.13, 0.12, 0.11, 0.10, 0.09, 0.08, 0.07, 0.06, 0.05, 0.04, 0.03, 0.02, 0.01,
        ];
        let mut score = 0.0;
        for i in 0..13 {
            let freq = counts[i] as f64 / len as f64;
            score += freq * weights[i];
        }
        score
    }
}

impl<I: Iterator> FreqAnalyzerExt for I {}

// Performs a frequency analysis on the provided bytes, returning the aggregate score of how likely
// the data is to be English. The higher the score, the more likely.
pub fn analyze(data: &[u8]) -> f64 {
    data.iter().ascii_freq_score()
}

// Search through an iterator of items, returning the highest ranked vector.
pub fn search<T>(data: T) -> Option<(f64, Vec<u8>)>
where
    T: IntoIterator,
    <T as IntoIterator>::Item: IntoIterator,
    <<T as IntoIterator>::Item as IntoIterator>::Item: Borrow<u8>,
{
    data.into_iter()
        .map(|d| d.into_iter().map(|b| *b.borrow()).collect::<Vec<_>>())
        .map(|d| (analyze(&d), d))
        .max_by(|(a, _), (b, _)| a.total_cmp(b))
}
