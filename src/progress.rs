use indicatif::{ProgressBar, ProgressStyle};

pub fn create_progress_bar(total_ports: u64) -> ProgressBar {
    let progress_bar = ProgressBar::new(total_ports);

    let style = ProgressStyle::with_template(
        "{spinner:.cyan} [{elapsed_precise}] \
         [{bar:40.cyan/blue}] \
         {pos}/{len} ports ({percent}%) \
         ETA {eta_precise}",
    )
    .expect("invalid progress-bar template")
    .progress_chars("█▓░");

    progress_bar.set_style(style);

    progress_bar
}
