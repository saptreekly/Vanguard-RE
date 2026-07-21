use std::path::PathBuf;

use anyhow::{Context, Result};

use vanguard_re::containment::collect_samples;
use vanguard_re::disasm::FlowKind;
use vanguard_re::investigate::{InvestigateOptions, InvestigationReport, investigate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Menu,
    InvestigateForm,
    Running,
    Results,
    DisasmExplorer,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmFocus {
    Functions,
    Listing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeepDiveTab {
    #[default]
    Findings,
    Imports,
}

#[derive(Debug, Clone)]
pub struct DisasmNav {
    pub dive_index: usize,
    pub fn_index: usize,
    /// Cursor within the current function's instruction span (0-based).
    pub insn_cursor: usize,
    pub focus: DisasmFocus,
    /// Stack of (fn_index, insn_cursor) for "back" after follow-call.
    pub stack: Vec<(usize, usize)>,
    /// When set, function list shows only this cluster id.
    pub cluster_filter: Option<u8>,
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
    pub deep_tab: DeepDiveTab,
    pub pending_run: bool,
    pub disasm_nav: Option<DisasmNav>,
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
            deep_tab: DeepDiveTab::Findings,
            pending_run: false,
            disasm_nav: None,
        }
    }

    pub fn menu_items() -> &'static [&'static str] {
        &["Investigate sample / ZIP", "About & containment", "Quit"]
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
        self.deep_tab = DeepDiveTab::Findings;
        self.disasm_nav = None;
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
                self.deep_tab = DeepDiveTab::Findings;
                self.disasm_nav = None;
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
            // Already in deep-dive — open the function explorer.
            self.open_disasm_explorer();
            return;
        }
        let Some(report) = &self.report else {
            return;
        };
        let selected = report
            .ranking
            .get(self.results_index)
            .map(|(p, _, _)| p.clone());
        let Some(path) = selected else {
            return;
        };
        if let Some(i) = report.deep_dives.iter().position(|d| d.path == path) {
            self.deep_index = Some(i);
        } else if !report.deep_dives.is_empty() {
            self.deep_index = Some(0);
        }
        self.deep_tab = DeepDiveTab::Findings;
    }

    pub fn back_to_results_list(&mut self) {
        self.deep_index = None;
        self.deep_tab = DeepDiveTab::Findings;
        self.disasm_nav = None;
    }

    pub fn cycle_deep_dive_tab(&mut self, backwards: bool) {
        if self.deep_index.is_none() {
            return;
        }
        self.deep_tab = match (self.deep_tab, backwards) {
            (DeepDiveTab::Findings, false) | (DeepDiveTab::Findings, true) => DeepDiveTab::Imports,
            (DeepDiveTab::Imports, false) | (DeepDiveTab::Imports, true) => DeepDiveTab::Findings,
        };
    }

    pub fn open_disasm_explorer(&mut self) {
        let Some(di) = self.deep_index else {
            return;
        };
        let Some(report) = &self.report else {
            return;
        };
        let Some(dive) = report.deep_dives.get(di) else {
            return;
        };
        let Some(d) = &dive.disasm else {
            return;
        };
        if d.instructions.is_empty() {
            return;
        }
        // Functions are already sorted by interest — jump to the hottest.
        let fn_index = if d.functions.is_empty() {
            0
        } else {
            vanguard_re::disasm::most_interesting_fn(&d.functions)
        };
        self.disasm_nav = Some(DisasmNav {
            dive_index: di,
            fn_index,
            insn_cursor: 0,
            focus: DisasmFocus::Listing,
            stack: Vec::new(),
            cluster_filter: None,
        });
        self.screen = Screen::DisasmExplorer;
    }

    pub fn disasm_cycle_cluster_filter(&mut self) {
        let Some(report) = &self.report else {
            return;
        };
        let Some(nav) = &self.disasm_nav else {
            return;
        };
        let Some(dive) = report.deep_dives.get(nav.dive_index) else {
            return;
        };
        let Some(d) = &dive.disasm else {
            return;
        };
        if d.clusters.is_empty() {
            return;
        }
        let next = match nav.cluster_filter {
            None => Some(d.clusters[0].id),
            Some(cur) => {
                let pos = d.clusters.iter().position(|c| c.id == cur);
                match pos {
                    Some(i) if i + 1 < d.clusters.len() => Some(d.clusters[i + 1].id),
                    _ => None, // wrap to all
                }
            }
        };
        if let Some(nav) = &mut self.disasm_nav {
            nav.cluster_filter = next;
            // Snap selection into the filtered set.
        }
        self.disasm_snap_to_filter();
    }

    fn disasm_snap_to_filter(&mut self) {
        let Some(report) = &self.report else {
            return;
        };
        let Some(nav) = &self.disasm_nav else {
            return;
        };
        let filter = nav.cluster_filter;
        let fi = nav.fn_index;
        let Some(dive) = report.deep_dives.get(nav.dive_index) else {
            return;
        };
        let Some(d) = &dive.disasm else {
            return;
        };
        let visible: Vec<usize> = d
            .functions
            .iter()
            .enumerate()
            .filter(|(_, f)| filter.map_or(true, |c| f.cluster_id == c))
            .map(|(i, _)| i)
            .collect();
        if visible.is_empty() {
            return;
        }
        if !visible.contains(&fi) {
            if let Some(nav) = &mut self.disasm_nav {
                nav.fn_index = visible[0];
                nav.insn_cursor = 0;
            }
        }
    }

    pub fn disasm_toggle_focus(&mut self) {
        if let Some(nav) = &mut self.disasm_nav {
            nav.focus = match nav.focus {
                DisasmFocus::Functions => DisasmFocus::Listing,
                DisasmFocus::Listing => DisasmFocus::Functions,
            };
        }
    }

    pub fn disasm_move(&mut self, delta: isize) {
        let Some(nav) = &self.disasm_nav else {
            return;
        };
        let focus = nav.focus;
        let fn_index = nav.fn_index;
        let insn_cursor = nav.insn_cursor;
        let dive_index = nav.dive_index;

        let Some(report) = &self.report else {
            return;
        };
        let Some(dive) = report.deep_dives.get(dive_index) else {
            return;
        };
        let Some(d) = &dive.disasm else {
            return;
        };

        match focus {
            DisasmFocus::Functions => {
                let filter = nav.cluster_filter;
                let visible: Vec<usize> = d
                    .functions
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| filter.map_or(true, |c| f.cluster_id == c))
                    .map(|(i, _)| i)
                    .collect();
                if visible.is_empty() {
                    return;
                }
                let pos = visible.iter().position(|&i| i == fn_index).unwrap_or(0);
                let next_pos =
                    (pos as isize + delta).clamp(0, (visible.len() - 1) as isize) as usize;
                if let Some(nav) = &mut self.disasm_nav {
                    nav.fn_index = visible[next_pos];
                    nav.insn_cursor = 0;
                }
            }
            DisasmFocus::Listing => {
                let span = if let Some(f) = d.functions.get(fn_index) {
                    f.insn_end.saturating_sub(f.insn_start) + 1
                } else {
                    d.instructions.len()
                };
                if span == 0 {
                    return;
                }
                let next = (insn_cursor as isize + delta).clamp(0, (span - 1) as isize) as usize;
                if let Some(nav) = &mut self.disasm_nav {
                    nav.insn_cursor = next;
                }
            }
        }
    }

    pub fn disasm_next_function(&mut self, delta: isize) {
        let Some(report) = &self.report else {
            return;
        };
        let Some(nav) = &self.disasm_nav else {
            return;
        };
        let Some(dive) = report.deep_dives.get(nav.dive_index) else {
            return;
        };
        let Some(d) = &dive.disasm else {
            return;
        };
        let filter = nav.cluster_filter;
        let visible: Vec<usize> = d
            .functions
            .iter()
            .enumerate()
            .filter(|(_, f)| filter.map_or(true, |c| f.cluster_id == c))
            .map(|(i, _)| i)
            .collect();
        if visible.is_empty() {
            return;
        }
        let pos = visible.iter().position(|&i| i == nav.fn_index).unwrap_or(0);
        let next_pos = (pos as isize + delta).clamp(0, (visible.len() - 1) as isize) as usize;
        if let Some(nav) = &mut self.disasm_nav {
            nav.fn_index = visible[next_pos];
            nav.insn_cursor = 0;
        }
    }

    pub fn disasm_follow_call(&mut self) {
        let Some(nav) = self.disasm_nav.clone() else {
            return;
        };
        let Some(report) = &self.report else {
            return;
        };
        let Some(dive) = report.deep_dives.get(nav.dive_index) else {
            return;
        };
        let Some(d) = &dive.disasm else {
            return;
        };

        let line = if let Some(f) = d.functions.get(nav.fn_index) {
            let idx = f.insn_start + nav.insn_cursor;
            d.instructions.get(idx)
        } else {
            d.instructions.get(nav.insn_cursor)
        };
        let Some(line) = line else {
            return;
        };
        if line.flow != FlowKind::Call {
            return;
        }
        let Some(target) = line.branch_target else {
            return;
        };
        let Some(fi) = d.functions.iter().position(|f| f.start == target) else {
            return;
        };

        if let Some(nav) = &mut self.disasm_nav {
            nav.stack.push((nav.fn_index, nav.insn_cursor));
            nav.fn_index = fi;
            nav.insn_cursor = 0;
            nav.focus = DisasmFocus::Listing;
        }
    }

    pub fn disasm_nav_back(&mut self) {
        if let Some(nav) = &mut self.disasm_nav {
            if let Some((fi, cur)) = nav.stack.pop() {
                nav.fn_index = fi;
                nav.insn_cursor = cur;
                nav.focus = DisasmFocus::Listing;
            } else {
                self.disasm_nav = None;
                self.screen = Screen::Results;
            }
        }
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
            disasm_count: 512,
            yara_rules: None,
            min_deep_score: 70,
        },
    )
}
