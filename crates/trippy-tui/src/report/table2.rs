// ---------------------------------------------------------------------------
// run_report_table2: 交互式表格报告（ratatui 渲染 + 键盘事件循环）
// ---------------------------------------------------------------------------

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Row, Table as RatatuiTable};
use std::collections::HashMap;
use std::io;
use trippy_core::State;

/// 弹窗选择模式
enum PopupMode {
    None,
    /// (hop 行索引, 弹窗内光标位置)
    RouteSelect(usize, usize),
}

struct InteractiveState<'a, R: Resolver> {
    trace: &'a State,
    resolver: &'a R,
    geoip_lookup: &'a GeoIpLookup,
    cursor: usize,
    popup: PopupMode,
    quit: bool,
    /// 每跳的选择：hop_idx -> addr_idx
    selections: HashMap<usize, usize>,
}

impl<'a, R: Resolver> InteractiveState<'a, R> {
    fn new(trace: &'a State, resolver: &'a R, geoip_lookup: &'a GeoIpLookup) -> Self {
        Self {
            trace,
            resolver,
            geoip_lookup,
            cursor: 0,
            popup: PopupMode::None,
            quit: false,
            selections: HashMap::new(),
        }
    }

    fn hops(&self) -> &[trippy_core::Hop] {
        self.trace.hops()
    }

    fn selected_hop(&self) -> Option<&trippy_core::Hop> {
        let hops = self.hops();
        if self.cursor < hops.len() {
            Some(&hops[self.cursor])
        } else {
            None
        }
    }

    /// 判断某跳某地址是否可见（基于所有 selections 过滤）
    fn is_addr_visible(&self, hop_idx: usize, addr_idx: usize) -> bool {
        let hops = self.hops();
        if hop_idx >= hops.len() {
            return false;
        }
        let hop = &hops[hop_idx];
        let addrs: Vec<_> = hop.addrs().collect();
        if addr_idx >= addrs.len() {
            return false;
        }

        // 此跳有选择：所有地址都显示（选中的在渲染时高亮）
        if self.selections.contains_key(&hop_idx) {
            return true;
        }

        // 找最近的上游选择（严格小于 hop_idx）
        let upstream_sel = self
            .selections
            .iter()
            .filter(|(k, _)| **k < hop_idx)
            .max_by_key(|(k, _)| *k);

        if let Some((up_idx, up_addr_idx)) = upstream_sel {
            let up_idx = *up_idx;
            let up_addr_idx = *up_addr_idx;
            let up_hop = &hops[up_idx];
            let up_addrs: Vec<_> = up_hop.addrs().collect();
            if up_addr_idx >= up_addrs.len() {
                return true;
            }
            let up_count = up_hop
                .addrs_with_counts()
                .nth(up_addr_idx)
                .map(|(_, c)| *c)
                .unwrap_or(0);

            // 找此跳中计数最接近上游的地址索引
            let mut best_idx = 0;
            let mut best_diff = usize::MAX;
            for (idx, (_, c)) in hop.addrs_with_counts().enumerate() {
                let diff = (*c as isize - up_count as isize).unsigned_abs();
                if diff < best_diff {
                    best_diff = diff;
                    best_idx = idx;
                }
            }
            addr_idx == best_idx
        } else {
            true
        }
    }

    /// 此跳是否有选择
    fn has_selection(&self, hop_idx: usize) -> bool {
        self.selections.contains_key(&hop_idx)
    }

    fn confirm_popup(&mut self) {
        if let PopupMode::RouteSelect(hop_idx, popup_cursor) = self.popup {
            let hops = self.hops();
            if hop_idx >= hops.len() {
                self.popup = PopupMode::None;
                return;
            }
            let addr_count = hops[hop_idx].addr_count();
            if addr_count == 0 {
                self.popup = PopupMode::None;
                return;
            }
            let selected = popup_cursor.min(addr_count - 1);

            // 如果已选择同一条路由，取消选择
            if self.selections.get(&hop_idx) == Some(&selected) {
                self.selections.remove(&hop_idx);
            } else {
                self.selections.insert(hop_idx, selected);
            }
            self.popup = PopupMode::None;
        }
    }

    fn clear_all_selections(&mut self) {
        self.selections.clear();
    }
}

fn run_report_table2<R: Resolver>(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &R,
    _preset: &str,
    geoip_lookup: &GeoIpLookup,
) -> anyhow::Result<()> {
    let trace = super::wait_for_round(&info.data, report_cycles)?;
    let mut state = InteractiveState::new(&trace, resolver, geoip_lookup);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = (|| -> anyhow::Result<()> {
        loop {
            terminal.draw(|f| render(f, &state))?;
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    let hop_count = state.hops().len();
                    match &state.popup {
                        PopupMode::None => match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                state.quit = true;
                            }
                            KeyCode::Up => {
                                if state.cursor > 0 {
                                    state.cursor -= 1;
                                }
                            }
                            KeyCode::Down => {
                                if hop_count > 0 && state.cursor < hop_count - 1 {
                                    state.cursor += 1;
                                }
                            }
                            KeyCode::Enter => {
                                let hop = &state.hops()[state.cursor];
                                if hop.addr_count() > 1 {
                                    state.popup = PopupMode::RouteSelect(state.cursor, 0);
                                }
                            }
                            _ => {}
                        },
                        PopupMode::RouteSelect(hop_idx, _) => {
                            let hop_idx = *hop_idx;
                            let count = state.hops()[hop_idx].addr_count();
                            match key.code {
                                KeyCode::Esc => {
                                    state.clear_all_selections();
                                    state.popup = PopupMode::None;
                                }
                                KeyCode::Enter => {
                                    state.confirm_popup();
                                }
                                KeyCode::Up => {
                                    if let PopupMode::RouteSelect(_, ref mut c) = state.popup {
                                        *c = if *c > 0 {
                                            *c - 1
                                        } else {
                                            count.saturating_sub(1)
                                        };
                                    }
                                }
                                KeyCode::Down => {
                                    if let PopupMode::RouteSelect(_, ref mut c) = state.popup {
                                        if count > 0 {
                                            *c = (*c + 1) % count;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            if state.quit {
                break;
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn render<R: Resolver>(f: &mut ratatui::Frame<'_>, state: &InteractiveState<'_, R>) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(area);
    render_table(f, state, chunks[0]);
    render_status_bar(f, state, chunks[1]);
    if let PopupMode::RouteSelect(hop_idx, cursor) = &state.popup {
        render_popup(f, state, *hop_idx, *cursor);
    }
}

fn render_table<R: Resolver>(
    f: &mut ratatui::Frame<'_>,
    state: &InteractiveState<'_, R>,
    area: ratatui::layout::Rect,
) {
    let header_cells = [
        "Hop", "IPs", "Addrs", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StdDev",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);
    let mut rows = Vec::new();
    let hops = state.hops();
    let mut hop_num: usize = 0;

    for hop_idx in 0..hops.len() {
        let hop = &hops[hop_idx];
        let addrs: Vec<_> = hop.addrs().collect();
        let is_cursor = hop_idx == state.cursor;
        let has_sel = state.has_selection(hop_idx);

        // 找第一个可见地址索引
        let first_visible = (0..addrs.len()).find(|&a| state.is_addr_visible(hop_idx, a));
        if first_visible.is_none() {
            continue;
        }
        hop_num += 1;

        for addr_idx in 0..addrs.len() {
            if !state.is_addr_visible(hop_idx, addr_idx) {
                continue;
            }
            let addr = *addrs[addr_idx];
            let is_selected_addr = has_sel && state.selections.get(&hop_idx) == Some(&addr_idx);

            let row_style = if is_cursor {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            let addr_style = if is_selected_addr {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let ttl_str = if Some(addr_idx) == first_visible {
                hop_num.to_string()
            } else {
                String::new()
            };
            let addr_info = if let Ok(Some(geo)) = state.geoip_lookup.lookup(addr) {
                geo.raw().unwrap_or_default().to_string()
            } else {
                state.resolver.reverse_lookup(addr).to_string()
            };
            rows.push(
                Row::new(vec![
                    Cell::from(ttl_str),
                    Cell::from(addr.to_string()).style(addr_style),
                    Cell::from(addr_info).style(addr_style),
                    Cell::from(format!("{:.1}", hop.loss_pct())),
                    Cell::from(hop.total_sent().to_string()),
                    Cell::from(hop.total_recv().to_string()),
                    Cell::from(
                        hop.last_ms()
                            .map_or_else(|| "???".into(), |v| format!("{v:.1}")),
                    ),
                    Cell::from(format!("{:.1}", hop.avg_ms())),
                    Cell::from(
                        hop.best_ms()
                            .map_or_else(|| "???".into(), |v| format!("{v:.1}")),
                    ),
                    Cell::from(
                        hop.worst_ms()
                            .map_or_else(|| "???".into(), |v| format!("{v:.1}")),
                    ),
                    Cell::from(format!("{:.1}", hop.stddev_ms())),
                ])
                .style(row_style),
            );
        }
    }

    let table = RatatuiTable::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(18),
            Constraint::Length(30),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(7),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Trace Route"));
    f.render_widget(table, area);
}

fn render_popup<R: Resolver>(
    f: &mut ratatui::Frame<'_>,
    state: &InteractiveState<'_, R>,
    hop_idx: usize,
    cursor: usize,
) {
    let hop = &state.hops()[hop_idx];
    let addrs: Vec<_> = hop.addrs().collect();
    let ttl = hop.ttl();
    let current_sel = state.selections.get(&hop_idx).copied();

    let mut lines: Vec<Line<'_>> = Vec::new();
    lines.push(Line::from(Span::styled(
        format!(" TTL {}: 选择路由", ttl),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::raw(""));
    for (idx, addr_ref) in addrs.iter().enumerate() {
        let addr = **addr_ref;
        let is_cursor = idx == cursor;
        let is_current = current_sel == Some(idx);
        let addr_info = if let Ok(Some(geo)) = state.geoip_lookup.lookup(addr) {
            geo.raw().unwrap_or_default().to_string()
        } else {
            state.resolver.reverse_lookup(addr).to_string()
        };
        let marker = if is_cursor {
            "▶ "
        } else if is_current {
            "✓ "
        } else {
            "  "
        };
        let style = if is_cursor {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else if is_current {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        lines.push(Line::from(vec![
            Span::styled(marker, style),
            Span::styled(format!("{:<18}", addr.to_string()), style),
            Span::styled(addr_info, style),
        ]));
    }
    lines.push(Line::raw(""));
    let hint = if current_sel.is_some() {
        " ↑↓:切换  Enter:取消选择  Esc:清除全部"
    } else {
        " ↑↓:切换  Enter:确认  Esc:清除全部"
    };
    lines.push(Line::from(Span::styled(
        hint,
        Style::default().fg(Color::DarkGray),
    )));
    let block = Block::default()
        .title(" 路由选择 ")
        .title_alignment(ratatui::layout::Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black));
    let paragraph = ratatui::widgets::Paragraph::new(lines).block(block.clone());
    let popup_w = 60u16;
    let popup_h = (addrs.len() as u16 + 6).min(f.area().height.saturating_sub(4));
    let area = centered_rect(popup_w, popup_h, f.area());
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(paragraph, area);
}

fn centered_rect(w: u16, h: u16, r: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((r.height.saturating_sub(h)) / 2),
            Constraint::Length(h),
            Constraint::Length((r.height.saturating_sub(h)) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((r.width.saturating_sub(w)) / 2),
            Constraint::Length(w),
            Constraint::Length((r.width.saturating_sub(w)) / 2),
        ])
        .split(v[1])[1]
}

fn render_status_bar<R: Resolver>(
    f: &mut ratatui::Frame<'_>,
    state: &InteractiveState<'_, R>,
    area: ratatui::layout::Rect,
) {
    let sel_count = state.selections.len();
    let hint = if matches!(state.popup, PopupMode::None) {
        let hop = state.selected_hop();
        let multi = hop.map_or(false, |h| h.addr_count() > 1);
        let base = if multi {
            " ↑↓:移动  Enter:选择路由  q:退出"
        } else {
            " ↑↓:移动  q:退出"
        };
        if sel_count > 0 {
            format!("{}  [已选{}跳]", base, sel_count)
        } else {
            base.to_string()
        }
    } else {
        String::new()
    };
    f.render_widget(
        Line::from(Span::styled(hint, Style::default().fg(Color::Yellow))),
        area,
    );
}
