//! Interactive TUI — launched by bare `vanguard` with no arguments.

mod app;
mod ui;

use std::io::{stdout, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::{App, Screen};

pub fn run() -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin())
        || !std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        anyhow::bail!(
            "TUI needs an interactive terminal.\n\
             Open a real terminal and run:  vanguard"
        );
    }

    let mut terminal = setup()?;
    let result = run_app(&mut terminal);
    restore()?;
    result
}

fn setup() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("enable raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen).context("enter alternate screen")?;
    let backend = CrosstermBackend::new(out);
    Terminal::new(backend).context("create terminal")
}

fn restore() -> Result<()> {
    disable_raw_mode().ok();
    execute!(stdout(), LeaveAlternateScreen).ok();
    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    let mut app = App::new();

    loop {
        // Show the "Working…" frame, then run the investigation on the next tick.
        if app.screen == Screen::Running && app.pending_run {
            terminal.draw(|frame| ui::draw(frame, &app))?;
            app.finish_if_ready();
            // Hard-clear so Results cannot inherit leftover Working… cells.
            terminal.clear()?;
            continue;
        }

        terminal.draw(|frame| ui::draw(frame, &app))?;

        if !event::poll(Duration::from_millis(80))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        // Global quit
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            break;
        }

        match app.screen {
            Screen::Menu => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Up | KeyCode::Char('k') => app.menu_up(),
                KeyCode::Down | KeyCode::Char('j') => app.menu_down(),
                KeyCode::Enter => app.menu_select(),
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    let n = c.to_digit(10).unwrap_or(0) as usize;
                    if n >= 1 && n <= app.menu_len() {
                        app.menu_index = n - 1;
                        app.menu_select();
                    }
                }
                _ => {}
            },
            Screen::InvestigateForm => match key.code {
                KeyCode::Esc => app.back_to_menu(),
                KeyCode::Tab | KeyCode::BackTab => app.form_next_field(),
                KeyCode::Up => app.form_prev_field(),
                KeyCode::Down => app.form_next_field(),
                KeyCode::Enter => {
                    if app.form_focused_run() {
                        app.start_investigation()?;
                    } else {
                        app.form_next_field();
                    }
                }
                KeyCode::Backspace => app.form_backspace(),
                KeyCode::Char(c) => app.form_input(c),
                _ => {}
            },
            Screen::Running => {}
            Screen::Results => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => app.back_to_menu(),
                KeyCode::Up | KeyCode::Char('k') => app.results_up(),
                KeyCode::Down | KeyCode::Char('j') => app.results_down(),
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => app.open_deep_dive(),
                KeyCode::Char('b') => app.back_to_results_list(),
                KeyCode::PageUp => app.results_page(-10),
                KeyCode::PageDown => app.results_page(10),
                _ => {}
            },
            Screen::About => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.back_to_menu(),
                _ => {}
            },
            Screen::Error => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.back_to_menu(),
                _ => {}
            },
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}
