use crate::frontend::render::util;
use crate::frontend::tui_app::TuiApp;
use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear};

/// Render route selection popup dialog.
pub fn render(f: &mut Frame<'_>, app: &TuiApp) {
    let hop = match app.selected_hop() {
        Some(h) => h,
        None => return,
    };

    let addrs: Vec<_> = hop.addrs().collect();
    let counts: Vec<_> = hop.addrs_with_counts().collect();
    let ttl = hop.ttl();
    let selected = app.route_select_cursor;

    let mut lines: Vec<Line<'_>> = Vec::new();
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("  Hop TTL={}  选择路由 (Enter确认, Esc取消)", ttl),
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::raw(""));

    for (idx, &addr) in addrs.iter().enumerate() {
        let is_cursor = idx == selected;
        let addr_str = addr.to_string();

        let count = counts.get(idx).map_or(0, |item| *item.1);
        let total = hop.total_sent();
        let pct = if total > 0 {
            count as f64 / total as f64 * 100.0
        } else {
            0.0
        };

        let marker = if is_cursor { " ▶ " } else { "   " };
        let style = if is_cursor {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        lines.push(Line::from(vec![
            Span::styled(marker, style),
            Span::styled(format!("{:<18}", addr_str), style),
            Span::styled(format!("{:>5.1}%", pct), style),
            Span::styled(format!("  ({} packets)", count), style),
        ]));
    }

    lines.push(Line::raw(""));

    let block = Block::default()
        .title(format!(" 路由选择 - {} 条路径 ", addrs.len()))
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black));

    let control = ratatui::widgets::Paragraph::new(lines)
        .block(block.clone())
        .alignment(Alignment::Left);

    let area = util::centered_rect(60, 40, f.area());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(control, area);
}
