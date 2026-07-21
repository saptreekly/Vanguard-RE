use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use vanguard_re::containment::{containment_policy, EmbeddedArchive};
use vanguard_re::disasm::TokenKind;
use vanguard_re::investigate::short_name;
use vanguard_re::secrets::SecretCandidate;

use super::app::{App, DisasmFocus, FormField, Screen};

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
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
}

fn pane_block(title: &str, focused: bool) -> Block<'static> {
    let color = if focused { ACCENT } else { MUTED };
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
}

/// One-line key legend rendered inside a muted border.
fn help_bar(pairs: &[(&str, &str)]) -> Paragraph<'static> {
    let mut spans = Vec::with_capacity(pairs.len() * 2);
    for (i, (key, desc)) in pairs.iter().enumerate() {
        spans.push(Span::styled(
            (*key).to_string(),
            Style::default().fg(ACCENT),
        ));
        let tail = if i + 1 == pairs.len() {
            format!(" {desc}")
        } else {
            format!(" {desc}   ")
        };
        spans.push(Span::styled(tail, Style::default().fg(MUTED)));
    }
    Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(MUTED)),
    )
}

fn token_style(kind: TokenKind) -> Style {
    match kind {
        TokenKind::Mnemonic => Style::default().fg(Color::LightYellow),
        TokenKind::Register => Style::default().fg(Color::LightCyan),
        TokenKind::Number => Style::default().fg(Color::LightMagenta),
        TokenKind::Keyword => Style::default().fg(Color::Green),
        TokenKind::Punct => Style::default().fg(FG),
        TokenKind::Address => Style::default().fg(Color::LightGreen),
        TokenKind::Text => Style::default().fg(Color::White),
    }
}

/// Instruction text as colored spans (red override for anti-debug lines).
fn insn_spans(
    tokens: &[(String, TokenKind)],
    anti_debug: bool,
) -> Vec<Span<'static>> {
    if anti_debug {
        return vec![Span::styled(
            tokens.iter().map(|(t, _)| t.as_str()).collect::<String>(),
            Style::default().fg(BAD),
        )];
    }
    tokens
        .iter()
        .map(|(t, k)| Span::styled(t.clone(), token_style(*k)))
        .collect()
}

fn score_style(score: u8) -> Style {
    if score >= 90 {
        Style::default().fg(BAD).add_modifier(Modifier::BOLD)
    } else if score >= 70 {
        Style::default().fg(WARN)
    } else {
        Style::default().fg(FG)
    }
}

/// Scroll window of `visible` rows keeping `cursor` centred where possible.
fn window(len: usize, cursor: usize, visible: usize) -> std::ops::Range<usize> {
    if len == 0 || visible == 0 {
        return 0..0;
    }
    let visible = visible.min(len);
    let start = cursor
        .saturating_sub(visible / 2)
        .min(len - visible);
    start..start + visible
}

/// Centre a column of at most `max_w` cells inside `area`.
fn centered_col(area: Rect, max_w: u16) -> Rect {
    let w = area.width.min(max_w);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y,
        width: w,
        height: area.height,
    }
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
        Screen::DisasmExplorer => draw_disasm_explorer(frame, app, area),
        Screen::About => draw_about(frame, area),
        Screen::Error => draw_error(frame, app, area),
    }
}

fn draw_menu(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let col = centered_col(area, 66);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(col);

    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "VANGUARD-RE",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
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
            let prefix = if selected { " ▸ " } else { "   " };
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

    frame.render_widget(
        help_bar(&[("↑↓/jk", "move"), ("enter", "select"), ("1-9", "jump"), ("q", "quit")]),
        chunks[2],
    );
}

fn draw_form(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let col = centered_col(area, 80);
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
        .split(col);

    let header = Paragraph::new("Investigate — decrypt ZIPs into RAM, triage, signatures, deep-dive")
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
            "deep-dives (1-20)",
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
    .wrap(Wrap { trim: true })
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)));
    frame.render_widget(tip, chunks[5]);

    frame.render_widget(
        help_bar(&[
            ("tab/↑↓", "fields"),
            ("enter", "run"),
            ("esc", "menu"),
        ]),
        chunks[6],
    );
}

fn field<'a>(label: &'a str, value: &'a str, focused: bool, secret: bool) -> Paragraph<'a> {
    let display = if secret && !value.is_empty() {
        "•".repeat(value.chars().count().min(32))
    } else if value.is_empty() && !focused {
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
    let mut spans = vec![
        Span::styled(format!("{label}: "), Style::default().fg(MUTED)),
        Span::styled(display, style),
    ];
    if focused {
        spans.push(Span::styled(
            "▏",
            Style::default().fg(ACCENT).add_modifier(Modifier::SLOW_BLINK),
        ));
    }
    Paragraph::new(Line::from(spans)).block(
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
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
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
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    let source = report
        .source
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&report.source);
    let top_score = report.ranking.first().map(|(_, s, _)| *s).unwrap_or(0);
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("source ", Style::default().fg(MUTED)),
            Span::styled(source, Style::default().fg(Color::White)),
            Span::styled(
                format!("  ·  {} samples", report.sample_count),
                Style::default().fg(MUTED),
            ),
            Span::styled("  ·  top score ", Style::default().fg(MUTED)),
            Span::styled(format!("{top_score}/100"), score_style(top_score)),
        ]),
        Line::from(Span::styled(
            "static / in-memory · nothing executed",
            Style::default().fg(MUTED),
        )),
    ])
    .block(title_block("results"));
    frame.render_widget(header, chunks[0]);

    // Signal summary is built first so the narrow layout can size its panel.
    let sig_width = if area.width >= 110 {
        (area.width as usize * 42 / 100).saturating_sub(2)
    } else {
        (area.width as usize).saturating_sub(2)
    };
    let summary_lines = signal_lines(report, sig_width);

    let (rank_area, sig_area) = if area.width >= 110 {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(chunks[1]);
        (cols[0], cols[1])
    } else {
        let sig_h = (summary_lines.len() as u16 + 2).clamp(8, 14);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(6), Constraint::Length(sig_h)])
            .split(chunks[1]);
        (rows[0], rows[1])
    };

    draw_ranking(frame, app, report, rank_area);

    let summary = Paragraph::new(summary_lines)
        .wrap(Wrap { trim: false })
        .block(title_block("signals"));
    frame.render_widget(summary, sig_area);

    frame.render_widget(
        help_bar(&[
            ("↑↓", "select"),
            ("g/G", "top/bottom"),
            ("enter", "deep-dive"),
            ("d", "disasm"),
            ("esc", "menu"),
        ]),
        chunks[2],
    );
}

fn draw_ranking(
    frame: &mut Frame<'_>,
    app: &App,
    report: &vanguard_re::investigate::InvestigationReport,
    area: Rect,
) {
    let len = report.ranking.len();
    let inner_w = (area.width as usize).saturating_sub(2);
    let visible_h = (area.height as usize).saturating_sub(2);

    // Columns: "#nn " (4) + "sss " (4) + name + " " + label(rest)
    let name_w = (inner_w * 45 / 100).clamp(16, 42);
    let label_w = inner_w.saturating_sub(4 + 4 + name_w + 1);

    let items: Vec<ListItem> = if report.ranking.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "  No samples could be ranked.",
            Style::default().fg(WARN),
        )))]
    } else {
        window(len, app.results_index, visible_h)
            .map(|i| {
                let (path, score, label) = &report.ranking[i];
                let selected = i == app.results_index;
                let name = truncate(&short_name(path), name_w);
                let row = Line::from(vec![
                    Span::styled(
                        format!("#{:<3}", i + 1),
                        if selected {
                            Style::default().fg(Color::Black)
                        } else {
                            Style::default().fg(MUTED)
                        },
                    ),
                    Span::styled(format!("{score:>3} "), score_style(*score)),
                    Span::styled(
                        format!("{name:<name_w$} "),
                        if selected {
                            Style::default()
                                .fg(Color::Black)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::White)
                        },
                    ),
                    Span::styled(
                        truncate(label, label_w),
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

    let title = if len == 0 {
        "ranking".to_string()
    } else {
        format!("ranking {}/{}  ·  enter = deep-dive", app.results_index + 1, len)
    };
    frame.render_widget(List::new(items).block(title_block(&title)), area);
}

fn signal_lines(
    report: &vanguard_re::investigate::InvestigationReport,
    width: usize,
) -> Vec<Line<'static>> {
    let section = |t: &str| {
        Line::from(Span::styled(
            t.to_string(),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
    };
    let mut lines = Vec::new();

    lines.push(section("CAPABILITIES  (top sample)"));
    if let Some(t) = report.triage.first() {
        if t.threat.capabilities.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (none on top sample)",
                Style::default().fg(MUTED),
            )));
        } else {
            for cap in t.threat.capabilities.iter().take(8) {
                lines.push(Line::from(Span::styled(
                    truncate(
                        &format!("  {:>3}  {:<14}  {}", cap.confidence, cap.id, cap.label),
                        width,
                    ),
                    Style::default().fg(FG),
                )));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(section("SIGNATURES"));
    if report.yara_by_sample.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no builtin hits)",
            Style::default().fg(MUTED),
        )));
    } else {
        for (path, hits) in report.yara_by_sample.iter().take(6) {
            let rules: Vec<_> = hits.iter().map(|h| h.rule.as_str()).collect();
            lines.push(Line::from(Span::styled(
                truncate(
                    &format!("  {}  {}", short_name(path), rules.join(", ")),
                    width,
                ),
                Style::default().fg(FG),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(section("IMPHASH SIBLINGS"));
    let siblings: Vec<_> = report
        .imphash_clusters
        .iter()
        .filter(|c| c.members.len() > 1)
        .collect();
    if siblings.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (none in this pack)",
            Style::default().fg(MUTED),
        )));
    } else {
        for c in siblings.iter().take(4) {
            lines.push(Line::from(Span::styled(
                truncate(&format!("  {}  ×{}", c.imphash, c.members.len()), width),
                Style::default().fg(FG),
            )));
            lines.push(Line::from(Span::styled(
                truncate(&format!("    {}", c.members.join(" · ")), width),
                Style::default().fg(MUTED),
            )));
        }
    }
    lines
}

fn ioc_lines(
    iocs: &[vanguard_re::iocs::NetworkIoc],
    shown: usize,
    width: usize,
) -> Vec<Line<'static>> {
    if iocs.is_empty() {
        return vec![Line::from(Span::styled(
            "  (no network indicators)",
            Style::default().fg(MUTED),
        ))];
    }
    iocs.iter()
        .take(shown)
        .map(|ioc| {
            let kind_style = if ioc.private {
                Style::default().fg(MUTED)
            } else if ioc.confidence >= 85 {
                Style::default().fg(BAD).add_modifier(Modifier::BOLD)
            } else if ioc.confidence >= 60 {
                Style::default().fg(WARN)
            } else {
                Style::default().fg(FG)
            };
            let tag = if ioc.private {
                format!("{}·priv", ioc.kind.label())
            } else {
                ioc.kind.label().to_string()
            };
            let val_w = width.saturating_sub(11);
            Line::from(vec![
                Span::styled(format!(" {tag:<8} "), kind_style),
                Span::styled(
                    truncate(&ioc.value, val_w),
                    if ioc.private {
                        Style::default().fg(MUTED)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
            ])
        })
        .collect()
}

fn draw_deep_dive(frame: &mut Frame<'_>, app: &App, area: Rect, di: usize) {
    let Some(report) = &app.report else {
        return;
    };
    let Some(dive) = report.deep_dives.get(di) else {
        return;
    };

    let inner_w = (area.width as usize).saturating_sub(2);

    // —— detail: sample identity (left) + threat signals (right) ——
    let triage = report.triage.iter().find(|t| t.path == dive.path);
    let left_w = (area.width as usize * 46 / 100).saturating_sub(2);

    let kv = |k: &str, v: String, vs: Style| {
        Line::from(vec![
            Span::styled(format!("{k:<8} "), Style::default().fg(MUTED)),
            Span::styled(v, vs),
        ])
    };
    let left_val_w = left_w.saturating_sub(9);
    let mut left_lines = vec![Line::from(Span::styled(
        truncate(&short_name(&dive.path), left_w),
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    ))];
    if let Some(t) = triage {
        left_lines.push(kv(
            "file",
            format!(
                "{} · {} · {}",
                t.binary.format,
                t.binary.architecture,
                human_size(t.size)
            ),
            Style::default().fg(FG),
        ));
    }
    left_lines.push(kv(
        "sha256",
        fit_hash(&dive.sha256, left_val_w),
        Style::default().fg(FG),
    ));
    if let Some(h) = triage.and_then(|t| t.hashes.imphash.as_deref()) {
        left_lines.push(kv(
            "imphash",
            fit_hash(h, left_val_w),
            Style::default().fg(FG),
        ));
    }
    if let Some(t) = triage {
        for hint in t.packer_hints.iter().take(2) {
            left_lines.push(kv(
                "packer",
                truncate(hint, left_val_w),
                Style::default().fg(WARN),
            ));
        }
    }

    // Right column: "<label>  ━━━━━━━─── nnn" rows sharing one label width.
    let right_w = inner_w.saturating_sub(left_w + 2);
    let label_w = right_w.saturating_sub(17).clamp(14, 24);
    let gauge = |label: &str, value: u8, denom: &str, style: Style| {
        Line::from(vec![
            Span::styled(
                format!("{:<label_w$} ", truncate(label, label_w)),
                Style::default().fg(Color::White),
            ),
            Span::styled(conf_bar(value, 10), style),
            Span::styled(format!(" {value:>3}{denom}"), style),
        ])
    };

    let mut right_lines = vec![gauge(
        "risk",
        dive.score,
        "/100",
        score_style(dive.score).add_modifier(Modifier::BOLD),
    )];
    if dive.capabilities.is_empty() {
        right_lines.push(Line::from(Span::styled(
            "(no capability tags)",
            Style::default().fg(MUTED),
        )));
    } else {
        for cap in dive.capabilities.iter().take(6) {
            let bar_style = if cap.confidence >= 80 {
                Style::default().fg(BAD)
            } else if cap.confidence >= 50 {
                Style::default().fg(WARN)
            } else {
                Style::default().fg(FG)
            };
            right_lines.push(gauge(&cap.label, cap.confidence, "", bar_style));
        }
    }
    right_lines.push(Line::from(""));

    // Consistent "label   value" summary rows sharing a fixed label column.
    const SW: usize = 11;
    let val_w = right_w.saturating_sub(SW);
    let summary_row = |label: &str, value: String, style: Style| {
        Line::from(vec![
            Span::styled(format!("{label:<SW$}"), Style::default().fg(MUTED)),
            Span::styled(truncate(&value, val_w), style),
        ])
    };
    let none = |s: &str| (s.to_string(), Style::default().fg(MUTED));

    let behaviors: Vec<&str> = triage
        .map(|t| t.threat.behaviors.iter().map(|b| b.name.as_str()).collect())
        .unwrap_or_default();
    let (bv, bs) = if behaviors.is_empty() {
        none("(none observed)")
    } else {
        (behaviors.join(" · "), Style::default().fg(FG))
    };
    right_lines.push(summary_row("behaviors", bv, bs));

    let (yv, ys) = if dive.yara.is_empty() {
        none("(no builtin hits)")
    } else {
        (
            dive.yara.iter().map(|y| y.rule.as_str()).collect::<Vec<_>>().join(" · "),
            Style::default().fg(WARN),
        )
    };
    right_lines.push(summary_row("sigs", yv, ys));

    let (cv, cs) = if dive.crypto.is_empty() {
        none("(none detected)")
    } else {
        (
            dive.crypto.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(" · "),
            Style::default().fg(Color::LightGreen),
        )
    };
    right_lines.push(summary_row("crypto", cv, cs));

    // Techniques were previously shown atop the (now removed) disasm panel.
    let (tv, ts) = match &dive.disasm {
        Some(d) if !d.insights.is_empty() => (
            d.insights.iter().map(|i| i.id.as_str()).collect::<Vec<_>>().join(" · "),
            Style::default().fg(BAD),
        ),
        Some(_) => none("(none flagged)"),
        None => none("(disasm unavailable)"),
    };
    right_lines.push(summary_row("techniques", tv, ts));

    // Each row is pre-truncated to one line, so the panel height is exact.
    let meta_h = (left_lines.len().max(right_lines.len()) as u16 + 2).clamp(8, 14);

    // —— optional content-sized rows: possible secrets, embedded archives ——
    let sec_lines = secret_lines(&dive.secrets, inner_w);
    let sec_h: u16 = if sec_lines.is_empty() {
        0
    } else {
        (sec_lines.len() as u16 + 2).min(9)
    };
    let emb_lines = embedded_archive_lines(&dive.embedded_archives, inner_w);
    let emb_h: u16 = if emb_lines.is_empty() {
        0
    } else {
        (emb_lines.len() as u16 + 2).min(14)
    };

    // Layout: identity/signals · strings+IOCs (fills) · [secrets] · [embedded]
    //         · disasm hint · help. Optional rows collapse when empty.
    let mut constraints = vec![Constraint::Length(meta_h), Constraint::Min(6)];
    let content_idx = 1usize;
    let mut next = 2usize;
    let sec_idx = if sec_h > 0 {
        constraints.push(Constraint::Length(sec_h));
        let i = next;
        next += 1;
        Some(i)
    } else {
        None
    };
    let emb_idx = if emb_h > 0 {
        constraints.push(Constraint::Length(emb_h));
        let i = next;
        next += 1;
        Some(i)
    } else {
        None
    };
    constraints.push(Constraint::Length(1));
    let hint_idx = next;
    next += 1;
    constraints.push(Constraint::Length(3));
    let help_idx = next;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let detail_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(chunks[0]);
    frame.render_widget(
        Paragraph::new(left_lines).block(title_block(&format!(
            "sample  ·  deep-dive {}/{}",
            di + 1,
            report.deep_dives.len()
        ))),
        detail_cols[0],
    );
    frame.render_widget(
        Paragraph::new(right_lines).block(title_block("threat signals")),
        detail_cols[1],
    );

    // —— interesting strings + network IOCs fill the freed vertical space ——
    let row_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[content_idx]);
    let str_w = (row_cols[0].width as usize).saturating_sub(2);
    let ioc_w = (row_cols[1].width as usize).saturating_sub(2);
    let list_cap = (chunks[content_idx].height as usize).saturating_sub(2);
    let shown_strings = dive.interesting_strings.len().min(list_cap);
    let shown_iocs = dive.network_iocs.len().min(list_cap);

    let mut string_lines = Vec::new();
    if dive.interesting_strings.is_empty() {
        string_lines.push(Line::from(Span::styled(
            "  (none flagged)",
            Style::default().fg(MUTED),
        )));
    } else {
        for s in dive.interesting_strings.iter().take(shown_strings) {
            string_lines.push(Line::from(vec![
                Span::styled(format!(" {:>7x}  ", s.offset), Style::default().fg(MUTED)),
                Span::styled(
                    truncate(&s.value, str_w.saturating_sub(11)),
                    Style::default().fg(FG),
                ),
            ]));
        }
    }
    frame.render_widget(
        Paragraph::new(string_lines).block(title_block(&format!(
            "interesting strings ({}/{})",
            shown_strings,
            dive.interesting_strings.len()
        ))),
        row_cols[0],
    );

    frame.render_widget(
        Paragraph::new(ioc_lines(&dive.network_iocs, shown_iocs, ioc_w))
            .block(title_block(&format!(
                "network IOCs ({}/{})",
                shown_iocs,
                dive.network_iocs.len()
            ))),
        row_cols[1],
    );

    if let Some(idx) = sec_idx {
        frame.render_widget(
            Paragraph::new(sec_lines).block(title_block(&format!(
                "possible secrets ({})  ·  heuristic — verify manually",
                dive.secrets.len()
            ))),
            chunks[idx],
        );
    }

    if let Some(idx) = emb_idx {
        let count = dive.embedded_archives.len();
        frame.render_widget(
            Paragraph::new(emb_lines).block(title_block(&format!(
                "embedded archives ({count})  ·  carved from sample bytes"
            ))),
            chunks[idx],
        );
    }

    // —— disasm moved to its own explorer; leave a one-line pointer ——
    let disasm_hint = match &dive.disasm {
        Some(d) => format!(
            "  disassembly  ·  {} @ {:#x}  ·  {} functions  ·  press d / enter to explore",
            d.architecture,
            d.start_address,
            d.functions.len()
        ),
        None => "  disassembly  ·  (unavailable for this sample)".to_string(),
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate(&disasm_hint, inner_w),
            Style::default().fg(ACCENT),
        ))),
        chunks[hint_idx],
    );

    frame.render_widget(
        help_bar(&[
            ("↑↓", "next deep-dive"),
            ("d/enter", "function map"),
            ("b/esc", "ranking"),
        ]),
        chunks[help_idx],
    );
}

/// Build the possible-secrets panel: ranked, shape-based credential guesses.
fn secret_lines(secrets: &[SecretCandidate], width: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    for s in secrets.iter().take(7) {
        let style = if s.score >= 80 {
            Style::default().fg(BAD).add_modifier(Modifier::BOLD)
        } else if s.score >= 65 {
            Style::default().fg(WARN)
        } else {
            Style::default().fg(FG)
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<6}", s.kind.label()), style),
            Span::styled(
                format!("{:<width$}", truncate(&s.value, width.saturating_sub(14)), width = width.saturating_sub(14)),
                Style::default().fg(Color::White),
            ),
            Span::styled(format!("  {:>3}", s.score), Style::default().fg(MUTED)),
        ]));
    }
    lines
}

/// Build the embedded-archive panel: a header per carved ZIP plus a bounded
/// member listing. Encrypted-but-undecryptable payloads (WannaCry's `.wnry`
/// bundle) are flagged in red because their presence alone is diagnostic.
fn embedded_archive_lines(archives: &[EmbeddedArchive], width: usize) -> Vec<Line<'static>> {
    const MAX_LINES: usize = 12;
    let mut lines: Vec<Line<'static>> = Vec::new();
    if archives.is_empty() {
        return lines;
    }

    let total_members: usize = archives.iter().map(|a| a.member_count()).sum();
    let mut shown_members = 0usize;

    'outer: for a in archives {
        let enc = a.encrypted_count();
        let header = format!(
            "{} @ {:#x} · {} files · {} enc · {} · {} extracted",
            a.label,
            a.offset,
            a.member_count(),
            enc,
            human_size(a.total_size()),
            a.extracted,
        );
        let hstyle = if a.recovered_password.is_some() {
            Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)
        } else if enc > 0 && a.extracted == 0 {
            Style::default().fg(BAD).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        };
        lines.push(Line::from(Span::styled(truncate(&header, width), hstyle)));

        // A cracked inner password is a headline finding — show it verbatim.
        if let Some(pw) = &a.recovered_password {
            lines.push(Line::from(vec![
                Span::styled("  password recovered  ", Style::default().fg(MUTED)),
                Span::styled(
                    truncate(pw, width.saturating_sub(22)),
                    Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }

        for m in &a.members {
            // Reserve the final line for a "+N more" summary when truncating.
            if lines.len() >= MAX_LINES - 1 && shown_members < total_members {
                break 'outer;
            }
            let lower = m.name.to_ascii_lowercase();
            let name_style = if lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".sys")
            {
                Style::default().fg(WARN)
            } else {
                Style::default().fg(FG)
            };
            let name = truncate(&m.name, width.saturating_sub(22));
            lines.push(Line::from(vec![
                Span::styled(
                    if m.encrypted { "  enc " } else { "      " }.to_string(),
                    if m.encrypted {
                        Style::default().fg(BAD)
                    } else {
                        Style::default().fg(MUTED)
                    },
                ),
                Span::styled(format!("{name:<width$}", width = width.saturating_sub(22)), name_style),
                Span::styled(
                    format!("  {:>9}", human_size(m.size)),
                    Style::default().fg(MUTED),
                ),
            ]));
            shown_members += 1;
        }
    }

    if shown_members < total_members {
        lines.push(Line::from(Span::styled(
            format!("  … +{} more", total_members - shown_members),
            Style::default().fg(MUTED),
        )));
    }
    lines
}

fn draw_disasm_explorer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    use vanguard_re::disasm::FlowKind;

    let Some(nav) = &app.disasm_nav else {
        return;
    };
    let Some(report) = &app.report else {
        return;
    };
    let Some(dive) = report.deep_dives.get(nav.dive_index) else {
        return;
    };
    let Some(d) = &dive.disasm else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let cur = d.functions.get(nav.fn_index);
    let cur_name = cur.map(|f| f.name.as_str()).unwrap_or("listing");
    let cur_interest = cur.map(|f| f.interest).unwrap_or(0);
    let filter_note = match nav.cluster_filter {
        Some(id) => d
            .clusters
            .iter()
            .find(|c| c.id == id)
            .map(|c| format!("filter c{id}:{}", c.label))
            .unwrap_or_else(|| format!("filter c{id}")),
        None => format!("{} clusters", d.clusters.len()),
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            short_name(&dive.path),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" ▸ ", Style::default().fg(MUTED)),
        Span::styled(
            cur_name.to_string(),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "  ★{cur_interest}  ·  {} funcs  ·  {filter_note}  ·  {}",
                d.functions.len(),
                d.architecture
            ),
            Style::default().fg(MUTED),
        ),
    ]))
    .block(title_block("function map"));
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(32), Constraint::Percentage(68)])
        .split(chunks[1]);

    draw_fn_pane(frame, nav, d, body[0]);

    // —— instruction listing ——
    let (span_start, span_end) = if let Some(f) = d.functions.get(nav.fn_index) {
        (f.insn_start, f.insn_end)
    } else {
        (0, d.instructions.len().saturating_sub(1))
    };
    let visible_h = body[1].height.saturating_sub(2) as usize;
    let cursor = nav.insn_cursor;
    let total = span_end.saturating_sub(span_start) + 1;

    let mut listing_lines: Vec<Line> = Vec::new();
    for rel in window(total, cursor, visible_h) {
        let idx = span_start + rel;
        let Some(line) = d.instructions.get(idx) else {
            break;
        };
        let selected = rel == cursor;
        let marker = if selected { "→ " } else { "  " };

        if line.is_function_start && rel != cursor {
            let fname = d
                .functions
                .iter()
                .find(|f| f.start == line.address)
                .map(|f| f.name.as_str())
                .unwrap_or("sub");
            listing_lines.push(Line::from(Span::styled(
                format!("  ; ---- {fname} ----"),
                Style::default().fg(MUTED),
            )));
        }

        let target_note = match line.branch_target {
            Some(t) => match vanguard_re::disasm::function_name_at(&d.functions, t) {
                Some(name) => format!("  → {name}"),
                None => format!("  → {t:#x}"),
            },
            None => String::new(),
        };
        let flag = if line.anti_debug {
            "  !"
        } else if line.flow == FlowKind::Call {
            "  call"
        } else if line.flow == FlowKind::Return {
            "  ret"
        } else {
            ""
        };

        let prefix = format!(
            "{marker}{:#010x}  {:<12}  ",
            line.address,
            truncate(&line.bytes, 12),
        );
        // Selected rows keep a solid highlight for readability; everything
        // else gets per-token syntax colors.
        if selected {
            let row_style = if nav.focus == DisasmFocus::Listing {
                Style::default().fg(Color::Black).bg(ACCENT)
            } else {
                Style::default().fg(ACCENT)
            };
            listing_lines.push(Line::from(Span::styled(
                format!("{prefix}{}{target_note}{flag}", line.text),
                row_style,
            )));
        } else {
            let mut spans = vec![Span::styled(prefix, Style::default().fg(MUTED))];
            spans.extend(insn_spans(&line.tokens, line.anti_debug));
            if !target_note.is_empty() {
                spans.push(Span::styled(
                    target_note,
                    Style::default().fg(Color::LightGreen),
                ));
            }
            if !flag.is_empty() {
                let flag_style = if line.anti_debug {
                    Style::default().fg(BAD).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(MUTED)
                };
                spans.push(Span::styled(flag.to_string(), flag_style));
            }
            listing_lines.push(Line::from(spans));
        }
    }

    let listing_title = format!("listing {}/{}  ·  enter = follow call", cursor + 1, total);
    frame.render_widget(
        Paragraph::new(listing_lines).block(pane_block(
            &listing_title,
            nav.focus == DisasmFocus::Listing,
        )),
        body[1],
    );

    frame.render_widget(
        help_bar(&[
            ("↑↓", "step"),
            ("g/G", "top/bottom"),
            ("tab", "pane"),
            ("enter", "follow"),
            ("u", "back"),
            ("[]", "fn"),
            ("c", "cluster"),
            ("esc", "close"),
        ]),
        chunks[2],
    );
}

fn draw_fn_pane(
    frame: &mut Frame<'_>,
    nav: &super::app::DisasmNav,
    d: &vanguard_re::disasm::DisasmReport,
    area: Rect,
) {
    let focused = nav.focus == DisasmFocus::Functions;
    let inner_w = (area.width as usize).saturating_sub(2);
    let visible_h = (area.height as usize).saturating_sub(2);
    // Row: "▸ " + "★nnn " + "c# " + name + " " + addr(~10)
    let name_w = inner_w.saturating_sub(22).clamp(8, 30);

    if d.functions.is_empty() {
        frame.render_widget(
            List::new(vec![ListItem::new(Line::from(Span::styled(
                "  (linear listing only)",
                Style::default().fg(MUTED),
            )))])
            .block(pane_block("functions", focused)),
            area,
        );
        return;
    }

    let visible: Vec<usize> = d
        .functions
        .iter()
        .enumerate()
        .filter(|(_, f)| nav.cluster_filter.map_or(true, |c| f.cluster_id == c))
        .map(|(i, _)| i)
        .collect();
    let sel_pos = visible
        .iter()
        .position(|&i| i == nav.fn_index)
        .unwrap_or(0);

    let items: Vec<ListItem> = window(visible.len(), sel_pos, visible_h)
        .map(|pos| {
            let i = visible[pos];
            let f = &d.functions[i];
            let selected = i == nav.fn_index;
            let prefix = if selected { "▸ " } else { "  " };
            let label = format!(
                "{prefix}★{:<3} c{} {:<name_w$} {:#x}",
                f.interest,
                f.cluster_id,
                truncate(&f.name, name_w),
                f.start,
            );
            let style = if selected && focused {
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else if f.interest >= 70 {
                Style::default().fg(WARN)
            } else {
                Style::default().fg(FG)
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    let title = format!("functions {}/{}", sel_pos + 1, visible.len());
    frame.render_widget(List::new(items).block(pane_block(&title, focused)), area);
}

fn draw_about(frame: &mut Frame<'_>, area: Rect) {
    let col = centered_col(area, 80);
    let policy = containment_policy();
    let lines = vec![
        Line::from(Span::styled(
            "Vanguard-RE",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
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
    frame.render_widget(widget, col);
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

/// `━━━━━━━───`-style confidence/score bar. Thin line glyphs stay readable
/// and never merge into a solid blob across adjacent rows like `█` does.
fn conf_bar(value: u8, width: usize) -> String {
    let filled = (value as usize * width).div_ceil(100).min(width);
    format!("{}{}", "━".repeat(filled), "─".repeat(width - filled))
}

/// Fit a hex hash on one line: head…tail when too long (hex is ASCII-safe).
fn fit_hash(h: &str, max: usize) -> String {
    if h.len() <= max || max < 16 {
        h.to_string()
    } else {
        format!("{}…{}", &h[..max.saturating_sub(9)], &h[h.len() - 8..])
    }
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// Char-safe truncation with an ellipsis (never slices mid-UTF-8).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}
