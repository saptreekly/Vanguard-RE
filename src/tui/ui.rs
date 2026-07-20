use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use vanguard_re::containment::containment_policy;
use vanguard_re::investigate::short_name;

use super::app::{App, FormField, Screen};

const ACCENT: Color = Color::Cyan;
const WARN: Color = Color::Yellow;
const BAD: Color = Color::Red;
const MUTED: Color = Color::DarkGray;
const FG: Color = Color::Gray;

fn title_block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ))
}

pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    // Always wipe the previous frame — ratatui only redraws dirty cells, so
    // the Working… modal otherwise ghosts through Results/help chrome.
    frame.render_widget(Clear, area);
    match app.screen {
        Screen::Menu => draw_menu(frame, app, area),
        Screen::InvestigateForm => draw_form(frame, app, area),
        Screen::Running => draw_running(frame, app, area),
        Screen::Results => draw_results(frame, app, area),
        Screen::About => draw_about(frame, area),
        Screen::Error => draw_error(frame, app, area),
    }
}

fn draw_menu(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "VANGUARD-RE",
            Style::default()
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "static malware triage · in-memory quarantine · nothing executed",
            Style::default().fg(MUTED),
        )),
        Line::from(""),
    ])
    .block(title_block("menu"))
    .alignment(Alignment::Center);
    frame.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = App::menu_items()
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let selected = i == app.menu_index;
            let prefix = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(FG)
            };
            ListItem::new(Line::from(Span::styled(
                format!("{prefix}{}. {label}", i + 1),
                style,
            )))
        })
        .collect();

    let list = List::new(items).block(title_block("actions"));
    frame.render_widget(list, chunks[1]);

    let help = Paragraph::new(Line::from(vec![
        Span::styled("↑↓/jk", Style::default().fg(ACCENT)),
        Span::styled(" move  ", Style::default().fg(MUTED)),
        Span::styled("enter", Style::default().fg(ACCENT)),
        Span::styled(" select  ", Style::default().fg(MUTED)),
        Span::styled("q", Style::default().fg(ACCENT)),
        Span::styled(" quit", Style::default().fg(MUTED)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)));
    frame.render_widget(help, chunks[2]);
}

fn draw_form(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new("Investigate — decrypt ZIPs into RAM, triage, YARA, deep-dive")
        .style(Style::default().fg(FG))
        .block(title_block("investigate"));
    frame.render_widget(header, chunks[0]);

    frame.render_widget(
        field(
            "path",
            &app.form_path,
            app.form_field == FormField::Path,
            false,
        ),
        chunks[1],
    );
    frame.render_widget(
        field(
            "password",
            &app.form_password,
            app.form_field == FormField::Password,
            true,
        ),
        chunks[2],
    );
    frame.render_widget(
        field(
            "deep-dives",
            &app.form_deep,
            app.form_field == FormField::Deep,
            false,
        ),
        chunks[3],
    );

    let run_style = if app.form_field == FormField::Run {
        Style::default()
            .fg(Color::Black)
            .bg(ACCENT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(ACCENT)
    };
    let run = Paragraph::new(Line::from(Span::styled(
        "  ▶  Run investigation  ",
        run_style,
    )))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(
        if app.form_field == FormField::Run {
            ACCENT
        } else {
            MUTED
        },
    )));
    frame.render_widget(run, chunks[4]);

    let tip = Paragraph::new(vec![
        Line::from(Span::styled(
            "Tip: paste a full path to a .zip or binary. Default password is “infected”.",
            Style::default().fg(MUTED),
        )),
        Line::from(Span::styled(
            "Samples stay in memory — never written as executables, never run.",
            Style::default().fg(MUTED),
        )),
    ])
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)));
    frame.render_widget(tip, chunks[5]);

    let help = Paragraph::new(Line::from(vec![
        Span::styled("tab", Style::default().fg(ACCENT)),
        Span::styled(" fields  ", Style::default().fg(MUTED)),
        Span::styled("enter", Style::default().fg(ACCENT)),
        Span::styled(" run  ", Style::default().fg(MUTED)),
        Span::styled("esc", Style::default().fg(ACCENT)),
        Span::styled(" menu", Style::default().fg(MUTED)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)));
    frame.render_widget(help, chunks[6]);
}

fn field<'a>(label: &'a str, value: &'a str, focused: bool, secret: bool) -> Paragraph<'a> {
    let display = if secret && !value.is_empty() {
        "•".repeat(value.chars().count().min(32))
    } else if value.is_empty() {
        String::from("…")
    } else {
        value.to_string()
    };
    let border = if focused { ACCENT } else { MUTED };
    let style = if focused {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(FG)
    };
    Paragraph::new(Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(MUTED)),
        Span::styled(display, style),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border)),
    )
}

fn draw_running(frame: &mut Frame<'_>, app: &App, area: Rect) {
    // Full-screen working view (no floating modal) so nothing can leak under Results.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Length(9),
            Constraint::Percentage(35),
        ])
        .split(area);
    let msg = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "Working…",
            Style::default()
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(app.status.clone(), Style::default().fg(FG))),
        Line::from(""),
        Line::from(Span::styled(
            "static only — nothing executed",
            Style::default().fg(MUTED),
        )),
    ])
    .alignment(Alignment::Center)
    .wrap(Wrap { trim: true })
    .block(title_block("quarantine"));
    frame.render_widget(msg, chunks[1]);
}

fn draw_results(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let Some(report) = &app.report else {
        return;
    };

    if let Some(di) = app.deep_index {
        draw_deep_dive(frame, app, area, di);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(6),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let source = report
        .source
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&report.source);
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("source ", Style::default().fg(MUTED)),
            Span::styled(source, Style::default().fg(Color::White)),
            Span::styled(
                format!("  ·  {} samples", report.sample_count),
                Style::default().fg(MUTED),
            ),
        ]),
        Line::from(Span::styled(
            "static / in-memory · nothing executed",
            Style::default().fg(MUTED),
        )),
    ])
    .block(title_block("results"));
    frame.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = if report.ranking.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  No samples could be ranked.",
            Style::default().fg(WARN),
        )))]
    } else {
        report
        .ranking
        .iter()
        .enumerate()
        .map(|(i, (path, score, label))| {
            let selected = i == app.results_index;
            let name = short_name(path);
            let score_style = if *score >= 90 {
                Style::default().fg(BAD).add_modifier(Modifier::BOLD)
            } else if *score >= 70 {
                Style::default().fg(WARN)
            } else {
                Style::default().fg(FG)
            };
            let row = Line::from(vec![
                Span::styled(
                    format!("#{:<2} ", i + 1),
                    if selected {
                        Style::default().fg(Color::Black)
                    } else {
                        Style::default().fg(MUTED)
                    },
                ),
                Span::styled(format!("{score:>3} "), score_style),
                Span::styled(
                    format!("{name:<34} "),
                    if selected {
                        Style::default()
                            .fg(Color::Black)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
                Span::styled(
                    label.clone(),
                    if selected {
                        Style::default().fg(Color::Black)
                    } else {
                        Style::default().fg(MUTED)
                    },
                ),
            ]);
            let style = if selected {
                Style::default().bg(ACCENT)
            } else {
                Style::default()
            };
            ListItem::new(row).style(style)
        })
        .collect()
    };

    let list = List::new(items).block(title_block("ranking  ·  enter = deep-dive"));
    frame.render_widget(list, chunks[1]);

    // Side summary: YARA + ImpHash siblings
    let mut summary_lines = Vec::new();
    summary_lines.push(Line::from(Span::styled(
        "YARA",
        Style::default()
            .fg(ACCENT)
            .add_modifier(Modifier::BOLD),
    )));
    if report.yara_by_sample.is_empty() {
        summary_lines.push(Line::from(Span::styled(
            "  (no builtin hits)",
            Style::default().fg(MUTED),
        )));
    } else {
        for (path, hits) in report.yara_by_sample.iter().take(6) {
            let rules: Vec<_> = hits.iter().map(|h| h.rule.as_str()).collect();
            summary_lines.push(Line::from(Span::styled(
                format!("  {}  {}", short_name(path), rules.join(", ")),
                Style::default().fg(FG),
            )));
        }
    }
    summary_lines.push(Line::from(""));
    summary_lines.push(Line::from(Span::styled(
        "IMPHASH SIBLINGS",
        Style::default()
            .fg(ACCENT)
            .add_modifier(Modifier::BOLD),
    )));
    let siblings: Vec<_> = report
        .imphash_clusters
        .iter()
        .filter(|c| c.members.len() > 1)
        .collect();
    if siblings.is_empty() {
        summary_lines.push(Line::from(Span::styled(
            "  (none in this pack)",
            Style::default().fg(MUTED),
        )));
    } else {
        for c in siblings.iter().take(4) {
            summary_lines.push(Line::from(Span::styled(
                format!("  {}  ×{}", c.imphash, c.members.len()),
                Style::default().fg(FG),
            )));
            summary_lines.push(Line::from(Span::styled(
                format!("    {}", c.members.join(" · ")),
                Style::default().fg(MUTED),
            )));
        }
    }

    let summary = Paragraph::new(summary_lines)
        .wrap(Wrap { trim: true })
        .block(title_block("signals"));
    frame.render_widget(summary, chunks[2]);

    let help = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(ACCENT)),
        Span::styled(" select  ", Style::default().fg(MUTED)),
        Span::styled("enter", Style::default().fg(ACCENT)),
        Span::styled(" deep-dive  ", Style::default().fg(MUTED)),
        Span::styled("esc", Style::default().fg(ACCENT)),
        Span::styled(" menu", Style::default().fg(MUTED)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)));
    frame.render_widget(help, chunks[3]);
}

fn draw_deep_dive(frame: &mut Frame<'_>, app: &App, area: Rect, di: usize) {
    let Some(report) = &app.report else {
        return;
    };
    let Some(dive) = report.deep_dives.get(di) else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Percentage(30),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let meta = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!("DEEP-DIVE {}/{}  ", di + 1, report.deep_dives.len()),
                Style::default().fg(BAD).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                short_name(&dive.path),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {}/100", dive.score),
                if dive.score >= 90 {
                    Style::default().fg(BAD).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(WARN)
                },
            ),
        ]),
        Line::from(Span::styled(
            format!("sha256  {}", dive.sha256),
            Style::default().fg(MUTED),
        )),
        Line::from(Span::styled(
            format!("behaviors  {}", dive.reason.replace(", ", " · ")),
            Style::default().fg(FG),
        )),
        Line::from(Span::styled(
            format!(
                "yara  {}",
                dive.yara
                    .iter()
                    .map(|y| y.rule.as_str())
                    .collect::<Vec<_>>()
                    .join(" · ")
            ),
            Style::default().fg(FG),
        )),
    ])
    .block(title_block("detail"));
    frame.render_widget(meta, chunks[0]);

    let mut string_lines = vec![Line::from(Span::styled(
        "strings",
        Style::default()
            .fg(ACCENT)
            .add_modifier(Modifier::BOLD),
    ))];
    if dive.interesting_strings.is_empty() {
        string_lines.push(Line::from(Span::styled(
            "  (none flagged)",
            Style::default().fg(MUTED),
        )));
    } else {
        for s in dive.interesting_strings.iter().take(12) {
            let val = if s.value.len() > 70 {
                format!("{}…", &s.value[..70])
            } else {
                s.value.clone()
            };
            string_lines.push(Line::from(Span::styled(
                format!("  {:>8x}  {val}", s.offset),
                Style::default().fg(FG),
            )));
        }
    }
    frame.render_widget(
        Paragraph::new(string_lines).block(title_block("interesting strings")),
        chunks[1],
    );

    let mut disasm_lines = Vec::new();
    if let Some(d) = &dive.disasm {
        disasm_lines.push(Line::from(Span::styled(
            format!("disasm  {} @ {:#x}", d.architecture, d.start_address),
            Style::default()
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )));
        let mut pad = 0usize;
        for line in d.instructions.iter().take(40) {
            let t = line.text.to_ascii_lowercase();
            let is_pad = t == "add [eax],al" || t == "add [rax],al" || t == "nop";
            if is_pad && !line.anti_debug {
                pad += 1;
                if pad >= 3 {
                    break;
                }
                continue;
            }
            pad = 0;
            let mut spans = vec![
                Span::styled(
                    format!("  {:#010x}  ", line.address),
                    Style::default().fg(MUTED),
                ),
                Span::styled(format!("{:<14}  ", truncate(&line.bytes, 14)), Style::default().fg(MUTED)),
                Span::styled(line.text.clone(), Style::default().fg(Color::White)),
            ];
            if line.anti_debug {
                spans.push(Span::styled(
                    "  anti-debug",
                    Style::default().fg(BAD).add_modifier(Modifier::BOLD),
                ));
            }
            disasm_lines.push(Line::from(spans));
        }
    } else {
        disasm_lines.push(Line::from(Span::styled(
            "  (disasm unavailable)",
            Style::default().fg(MUTED),
        )));
    }
    frame.render_widget(
        Paragraph::new(disasm_lines).block(title_block("entry disassembly")),
        chunks[2],
    );

    let help = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(ACCENT)),
        Span::styled(" next deep-dive  ", Style::default().fg(MUTED)),
        Span::styled("b", Style::default().fg(ACCENT)),
        Span::styled(" back to ranking  ", Style::default().fg(MUTED)),
        Span::styled("esc", Style::default().fg(ACCENT)),
        Span::styled(" menu", Style::default().fg(MUTED)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)));
    frame.render_widget(help, chunks[3]);
}

fn draw_about(frame: &mut Frame<'_>, area: Rect) {
    let policy = containment_policy();
    let lines = vec![
        Line::from(Span::styled(
            "Vanguard-RE",
            Style::default()
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "Speed · Accuracy · Exploit Immunity",
            Style::default().fg(MUTED),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("containment mode     {}", policy.mode),
            Style::default().fg(FG),
        )),
        Line::from(Span::styled(
            format!("executes samples     {}", policy.executes_samples),
            Style::default().fg(FG),
        )),
        Line::from(Span::styled(
            format!("writes samples disk  {}", policy.writes_samples_to_disk),
            Style::default().fg(FG),
        )),
        Line::from(""),
    ]
    .into_iter()
    .chain(policy.notes.iter().map(|n| {
        Line::from(Span::styled(
            format!("• {n}"),
            Style::default().fg(MUTED),
        ))
    }))
    .chain([
        Line::from(""),
        Line::from(Span::styled(
            "esc / enter — back to menu",
            Style::default().fg(MUTED),
        )),
    ])
    .collect::<Vec<_>>();

    let widget = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(title_block("about"));
    frame.render_widget(widget, area);
}

fn draw_error(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = centered(area, 70, 12);
    let msg = Paragraph::new(vec![
        Line::from(Span::styled(
            "Error",
            Style::default().fg(BAD).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(&app.error, Style::default().fg(FG))),
        Line::from(""),
        Line::from(Span::styled(
            "enter / esc — back",
            Style::default().fg(MUTED),
        )),
    ])
    .wrap(Wrap { trim: false })
    .block(title_block("error"));
    frame.render_widget(msg, block);
}

fn centered(area: Rect, percent_x: u16, height: u16) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height.min(90)) / 2),
            Constraint::Length(height),
            Constraint::Percentage((100 - height.min(90)) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup[1])[1]
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
