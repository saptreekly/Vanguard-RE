use std::path::PathBuf;

use anyhow::{Context, Result};

use vanguard_re::containment::collect_samples;
use vanguard_re::investigate::{investigate, InvestigateOptions, InvestigationReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Menu,
    InvestigateForm,
    Running,
    Results,
    About,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Path,
    Password,
    Deep,
    Run,
}

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub menu_index: usize,
    pub form_path: String,
    pub form_password: String,
    pub form_deep: String,
    pub form_field: FormField,
    pub status: String,
    pub error: String,
    pub report: Option<InvestigationReport>,
    pub results_index: usize,
    pub results_scroll: usize,
    pub deep_index: Option<usize>,
    pub pending_run: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Menu,
            should_quit: false,
            menu_index: 0,
            form_path: String::new(),
            form_password: "infected".into(),
            form_deep: "3".into(),
            form_field: FormField::Path,
            status: String::new(),
            error: String::new(),
            report: None,
            results_index: 0,
            results_scroll: 0,
            deep_index: None,
            pending_run: false,
        }
    }

    pub fn menu_items() -> &'static [&'static str] {
        &[
            "Investigate sample / ZIP",
            "About & containment",
            "Quit",
        ]
    }

    pub fn menu_len(&self) -> usize {
        Self::menu_items().len()
    }

    pub fn menu_up(&mut self) {
        if self.menu_index == 0 {
            self.menu_index = self.menu_len() - 1;
        } else {
            self.menu_index -= 1;
        }
    }

    pub fn menu_down(&mut self) {
        self.menu_index = (self.menu_index + 1) % self.menu_len();
    }

    pub fn menu_select(&mut self) {
        match self.menu_index {
            0 => {
                self.screen = Screen::InvestigateForm;
                self.form_field = FormField::Path;
                self.status.clear();
                self.error.clear();
            }
            1 => {
                self.screen = Screen::About;
            }
            _ => {
                self.should_quit = true;
            }
        }
    }

    pub fn back_to_menu(&mut self) {
        self.screen = Screen::Menu;
        self.deep_index = None;
        self.error.clear();
        self.status.clear();
        self.pending_run = false;
    }

    pub fn form_next_field(&mut self) {
        self.form_field = match self.form_field {
            FormField::Path => FormField::Password,
            FormField::Password => FormField::Deep,
            FormField::Deep => FormField::Run,
            FormField::Run => FormField::Path,
        };
    }

    pub fn form_prev_field(&mut self) {
        self.form_field = match self.form_field {
            FormField::Path => FormField::Run,
            FormField::Password => FormField::Path,
            FormField::Deep => FormField::Password,
            FormField::Run => FormField::Deep,
        };
    }

    pub fn form_focused_run(&self) -> bool {
        self.form_field == FormField::Run
    }

    pub fn form_input(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        match self.form_field {
            FormField::Path => self.form_path.push(c),
            FormField::Password => self.form_password.push(c),
            FormField::Deep => {
                if c.is_ascii_digit() {
                    self.form_deep.push(c);
                }
            }
            FormField::Run => {}
        }
    }

    pub fn form_backspace(&mut self) {
        match self.form_field {
            FormField::Path => {
                self.form_path.pop();
            }
            FormField::Password => {
                self.form_password.pop();
            }
            FormField::Deep => {
                self.form_deep.pop();
            }
            FormField::Run => {}
        }
    }

    pub fn start_investigation(&mut self) -> Result<()> {
        let path = self.form_path.trim().trim_matches('"').to_string();
        if path.is_empty() {
            self.error = "Enter a path to a sample or passworded ZIP".into();
            self.screen = Screen::Error;
            return Ok(());
        }
        let pb = PathBuf::from(&path);
        if !pb.exists() {
            self.error = format!("Path not found:\n{path}");
            self.screen = Screen::Error;
            return Ok(());
        }

        self.status = {
            let name = PathBuf::from(&path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(path.as_str())
                .to_string();
            format!("quarantining {name}")
        };
        self.screen = Screen::Running;
        self.pending_run = true;
        self.error.clear();
        Ok(())
    }

    /// Called from the event loop while on Running — executes the heavy work once.
    pub fn finish_if_ready(&mut self) {
        if !self.pending_run {
            return;
        }
        self.pending_run = false;

        let path = PathBuf::from(self.form_path.trim().trim_matches('"'));
        let password = {
            let p = self.form_password.trim();
            if p.is_empty() {
                None
            } else {
                Some(p.to_string())
            }
        };
        let deep: usize = self.form_deep.trim().parse().unwrap_or(3).clamp(1, 20);

        match run_investigation(&path, password.as_deref(), deep) {
            Ok(report) => {
                self.report = Some(report);
                self.results_index = 0;
                self.results_scroll = 0;
                self.deep_index = None;
                self.screen = Screen::Results;
                self.status.clear();
            }
            Err(e) => {
                self.error = format!("{e:#}");
                self.screen = Screen::Error;
            }
        }
    }

    pub fn results_up(&mut self) {
        if let Some(idx) = self.deep_index {
            if idx > 0 {
                self.deep_index = Some(idx - 1);
            }
            return;
        }
        if self.results_index > 0 {
            self.results_index -= 1;
        }
    }

    pub fn results_down(&mut self) {
        if let Some(idx) = self.deep_index {
            if let Some(r) = &self.report {
                if idx + 1 < r.deep_dives.len() {
                    self.deep_index = Some(idx + 1);
                }
            }
            return;
        }
        if let Some(r) = &self.report {
            if self.results_index + 1 < r.ranking.len() {
                self.results_index += 1;
            }
        }
    }

    pub fn results_page(&mut self, delta: isize) {
        if self.deep_index.is_some() {
            return;
        }
        let len = self.report.as_ref().map(|r| r.ranking.len()).unwrap_or(0);
        if len == 0 {
            return;
        }
        let next = self.results_index as isize + delta;
        self.results_index = next.clamp(0, (len - 1) as isize) as usize;
    }

    pub fn open_deep_dive(&mut self) {
        if self.deep_index.is_some() {
            return;
        }
        let Some(report) = &self.report else {
            return;
        };
        // Map ranking selection to a deep-dive if that sample was deep-dived
        let selected = report.ranking.get(self.results_index).map(|(p, _, _)| p.clone());
        let Some(path) = selected else {
            return;
        };
        if let Some(i) = report.deep_dives.iter().position(|d| d.path == path) {
            self.deep_index = Some(i);
        } else if !report.deep_dives.is_empty() {
            // Fall back to first deep-dive
            self.deep_index = Some(0);
        }
    }

    pub fn back_to_results_list(&mut self) {
        self.deep_index = None;
    }
}

fn run_investigation(
    path: &PathBuf,
    password: Option<&str>,
    deep: usize,
) -> Result<InvestigationReport> {
    let samples = collect_samples(path, false, password)
        .with_context(|| format!("collect {}", path.display()))?;
    investigate(
        &path.display().to_string(),
        &samples,
        InvestigateOptions {
            deep,
            disasm_count: 48,
            yara_rules: None,
            min_deep_score: 70,
        },
    )
}
