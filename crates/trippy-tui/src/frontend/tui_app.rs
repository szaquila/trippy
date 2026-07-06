use crate::app::TraceInfo;
use crate::frontend::config::TuiConfig;
use crate::frontend::render::settings::{SETTINGS_TAB_COLUMNS, settings_tabs};
use crate::geoip::GeoIpLookup;
use itertools::Itertools;
use ratatui::widgets::TableState;
use std::time::SystemTime;
use trippy_core::FlowId;
use trippy_core::Hop;
use trippy_core::State;
use trippy_dns::{DnsResolver, ResolveMethod};

pub struct TuiApp {
    pub selected_tracer_data: State,
    pub trace_info: Vec<TraceInfo>,
    pub tui_config: TuiConfig,
    /// The state of the hop table.
    pub table_state: TableState,
    /// The state of the settings table.
    pub setting_table_state: TableState,
    /// The selected trace.
    pub trace_selected: usize,
    /// The selected tab in the settings dialog.
    pub settings_tab_selected: usize,
    /// The index of the current address to show for the selected hop.
    ///
    /// Only used in detail mode.
    pub selected_hop_address: usize,
    /// The `FlowId` of the selected flow.
    ///
    /// FlowId(0) represents the unified flow for the trace.
    pub selected_flow: FlowId,
    /// Ordered flow ids with counts.
    pub flow_counts: Vec<(FlowId, usize)>,
    /// The index of the first visible flow in the flows chart.
    pub flows_start_index: usize,
    pub resolver: DnsResolver,
    pub geoip_lookup: GeoIpLookup,
    pub show_help: bool,
    pub show_settings: bool,
    pub show_route_select: bool,
    pub route_select_cursor: usize,
    /// 每跳的路由选择：hop ttl -> addr_idx
    pub route_selections: std::collections::HashMap<u8, usize>,
    /// 隐藏的地址集合：(ttl, addr_idx) — 后台验证未通过的地址
    pub hidden_addrs: std::collections::HashSet<(u8, usize)>,
    /// 异步验证是否正在进行
    pub verifying_routes: bool,
    /// 接收后台验证结果的 channel
    verify_result_rx: Option<std::sync::mpsc::Receiver<Vec<(u8, usize)>>>,
    pub show_hop_details: bool,
    pub show_flows: bool,
    pub show_chart: bool,
    pub show_map: bool,
    pub frozen_start: Option<SystemTime>,
    pub zoom_factor: usize,
}

impl TuiApp {
    pub fn new(
        tui_config: TuiConfig,
        resolver: DnsResolver,
        geoip_lookup: GeoIpLookup,
        trace_info: Vec<TraceInfo>,
    ) -> Self {
        Self {
            selected_tracer_data: State::default(),
            trace_info,
            tui_config,
            table_state: TableState::default(),
            setting_table_state: TableState::default(),
            trace_selected: 0,
            settings_tab_selected: 0,
            selected_hop_address: 0,
            selected_flow: State::default_flow_id(),
            flow_counts: vec![],
            flows_start_index: 0,
            resolver,
            geoip_lookup,
            show_help: false,
            show_settings: false,
            show_route_select: false,
            route_select_cursor: 0,
            route_selections: std::collections::HashMap::new(),
            hidden_addrs: std::collections::HashSet::new(),
            verifying_routes: false,
            verify_result_rx: None,
            show_hop_details: false,
            show_flows: false,
            show_chart: false,
            show_map: false,
            frozen_start: None,
            zoom_factor: 1,
        }
    }

    pub const fn tracer_data(&self) -> &State {
        &self.selected_tracer_data
    }

    pub fn snapshot_trace_data(&mut self) {
        self.selected_tracer_data = self.trace_info[self.trace_selected].data.snapshot();
    }

    pub fn clear_trace_data(&self) {
        self.trace_info[self.trace_selected].data.clear();
    }

    pub fn selected_hop_or_target(&self) -> &Hop {
        self.table_state.selected().map_or_else(
            || self.tracer_data().target_hop(self.selected_flow),
            |s| &self.tracer_data().hops_for_flow(self.selected_flow)[s],
        )
    }

    pub fn selected_hop(&self) -> Option<&Hop> {
        self.table_state
            .selected()
            .map(|s| &self.tracer_data().hops_for_flow(self.selected_flow)[s])
    }

    pub fn tracer_config(&self) -> &TraceInfo {
        &self.trace_info[self.trace_selected]
    }

    pub fn clamp_selected_hop(&mut self) {
        let hop_count = self.tracer_data().hops_for_flow(self.selected_flow).len();
        if let Some(selected) = self.table_state.selected()
            && selected > hop_count - 1
        {
            self.table_state.select(Some(hop_count - 1));
        }
    }

    pub fn update_order_flow_counts(&mut self) {
        pub fn order_flows(
            &(flow_id1, count1): &(FlowId, usize),
            &(flow_id2, count2): &(FlowId, usize),
        ) -> std::cmp::Ordering {
            match count1.cmp(&count2) {
                std::cmp::Ordering::Equal => flow_id2.cmp(&flow_id1),
                ord => ord,
            }
        }
        self.flow_counts = self
            .tracer_data()
            .flows()
            .iter()
            .map(|&(_, flow_id)| {
                let count = self.tracer_data().round_count(flow_id);
                (flow_id, count)
            })
            .sorted_by(order_flows)
            .rev()
            .take(self.selected_tracer_data.max_flows())
            .collect::<Vec<_>>();
    }

    pub fn next_hop(&mut self) {
        let hop_count = self.tracer_data().hops_for_flow(self.selected_flow).len();
        if hop_count == 0 {
            return;
        }
        let max_index = hop_count.saturating_sub(1);
        let i = match self.table_state.selected() {
            Some(i) => {
                if i < max_index {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_hop_address = 0;
    }

    pub fn previous_hop(&mut self) {
        let hop_count = self.tracer_data().hops_for_flow(self.selected_flow).len();
        if hop_count == 0 {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i > 0 {
                    i - 1
                } else {
                    i
                }
            }
            None => hop_count.saturating_sub(1),
        };
        self.table_state.select(Some(i));
        self.selected_hop_address = 0;
    }

    pub fn next_trace(&mut self) {
        if self.trace_info.len() > 1 && self.trace_selected < self.trace_info.len() - 1 {
            self.trace_selected += 1;
            self.clear();
        }
    }

    pub fn previous_trace(&mut self) {
        if self.trace_info.len() > 1 && self.trace_selected > 0 {
            self.trace_selected -= 1;
            self.clear();
        }
    }

    pub fn next_hop_address(&mut self) {
        if let Some(hop) = self.selected_hop()
            && self.selected_hop_address < hop.addr_count() - 1
        {
            self.selected_hop_address += 1;
        }
    }

    pub fn previous_hop_address(&mut self) {
        if self.selected_hop().is_some() && self.selected_hop_address > 0 {
            self.selected_hop_address -= 1;
        }
    }

    pub fn flow_count(&self) -> usize {
        self.selected_tracer_data.flows().len()
    }

    pub fn next_flow(&mut self) {
        if self.show_flows {
            let (cur_index, _) = self
                .flow_counts
                .iter()
                .find_position(|(flow_id, _)| *flow_id == self.selected_flow)
                .unwrap();
            if cur_index < self.flow_counts.len() - 1 {
                self.selected_flow = self.flow_counts[cur_index + 1].0;
            }
        }
    }

    pub fn previous_flow(&mut self) {
        if self.show_flows {
            let (cur_index, _) = self
                .flow_counts
                .iter()
                .find_position(|(flow_id, _)| *flow_id == self.selected_flow)
                .unwrap();
            if cur_index > 0 {
                self.selected_flow = self.flow_counts[cur_index - 1].0;
            }
        }
    }

    pub fn next_settings_tab(&mut self) {
        if self.settings_tab_selected < settings_tabs().len() - 1 {
            self.settings_tab_selected += 1;
        }
        self.setting_table_state.select(Some(0));
    }

    pub fn previous_settings_tab(&mut self) {
        if self.settings_tab_selected > 0 {
            self.settings_tab_selected -= 1;
        }
        self.setting_table_state.select(Some(0));
    }

    pub fn next_settings_item(&mut self) {
        let count = self.get_settings_items_count();
        let max_index = count.saturating_sub(1);
        let i = match self.setting_table_state.selected() {
            Some(i) => {
                if i < max_index {
                    i + 1
                } else {
                    i
                }
            }
            None => 0,
        };
        self.setting_table_state.select(Some(i));
    }

    pub fn previous_settings_item(&mut self) {
        let count = self.get_settings_items_count();
        let i = match self.setting_table_state.selected() {
            Some(i) => {
                if i > 0 {
                    i - 1
                } else {
                    i
                }
            }
            None => count.saturating_sub(1),
        };
        self.setting_table_state.select(Some(i));
    }

    fn get_settings_items_count(&self) -> usize {
        if self.settings_tab_selected == SETTINGS_TAB_COLUMNS {
            self.tui_config.tui_columns.all_columns_count()
        } else {
            settings_tabs()[self.settings_tab_selected].1
        }
    }

    pub fn toggle_column_visibility(&mut self) {
        if self.settings_tab_selected == SETTINGS_TAB_COLUMNS
            && let Some(selected) = self.setting_table_state.selected()
        {
            self.tui_config.tui_columns.toggle(selected);
        }
    }

    pub fn move_column_down(&mut self) {
        if self.settings_tab_selected == SETTINGS_TAB_COLUMNS {
            let count = self.tui_config.tui_columns.all_columns_count();
            if let Some(selected) = self.setting_table_state.selected()
                && selected < count - 1
            {
                self.tui_config.tui_columns.move_down(selected);
                self.setting_table_state.select(Some(selected + 1));
            }
        }
    }

    pub fn move_column_up(&mut self) {
        if self.settings_tab_selected == SETTINGS_TAB_COLUMNS
            && let Some(selected) = self.setting_table_state.selected()
            && selected > 0
        {
            self.tui_config.tui_columns.move_up(selected);
            self.setting_table_state.select(Some(selected - 1));
        }
    }

    pub fn clear(&mut self) {
        self.table_state.select(None);
        self.selected_hop_address = 0;
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    pub fn toggle_settings(&mut self) {
        self.show_settings = !self.show_settings;
    }

    pub fn toggle_route_select(&mut self) {
        if self.show_route_select {
            self.show_route_select = false;
        } else {
            self.route_select_cursor = 0;
            self.show_route_select = true;
        }
    }

    pub fn route_select_up(&mut self) {
        if self.route_select_cursor > 0 {
            self.route_select_cursor -= 1;
        }
    }

    pub fn route_select_down(&mut self) {
        if let Some(hop) = self.selected_hop() {
            let max = hop.addr_count();
            if max > 0 && self.route_select_cursor < max - 1 {
                self.route_select_cursor += 1;
            }
        }
    }

    pub fn confirm_route_select(&mut self) {
        if let Some(hop) = self.selected_hop() {
            let ttl = hop.ttl();
            let addr_count = hop.addr_count();
            if addr_count == 0 { self.show_route_select = false; return; }
            let selected = self.route_select_cursor.min(addr_count - 1);
            if self.route_selections.get(&ttl) == Some(&selected) {
                // 取消选择此跳
                self.route_selections.remove(&ttl);
            } else {
                self.route_selections.insert(ttl, selected);
            }
            // 选中后：把此跳之后所有地址标记为隐藏，等待后台验证
            self.hide_post_selection_addrs(ttl);
        }
        self.show_route_select = false;
        self.start_verify_routes();
    }

    pub fn clear_all_route_selections(&mut self) {
        self.route_selections.clear();
        self.hidden_addrs.clear();
    }

    /// 选中某跳后，把此跳之后到目的之前的所有地址标记为隐藏
    fn hide_post_selection_addrs(&mut self, selected_ttl: u8) {
        self.hidden_addrs.clear();
        let hops: Vec<(u8, usize)> = self.tracer_data()
            .hops_for_flow(self.selected_flow)
            .iter()
            .map(|h| (h.ttl(), h.addr_count()))
            .collect();
        let max_ttl = hops.iter().map(|&(t, _)| t).max().unwrap_or(0);
        for (ttl, addr_count) in hops {
            if ttl <= selected_ttl || ttl == max_ttl { continue; }
            for addr_idx in 0..addr_count {
                self.hidden_addrs.insert((ttl, addr_idx));
            }
        }
    }

    /// 启动后台验证线程
    pub fn start_verify_routes(&mut self) {
        if self.verifying_routes { return; }
        if self.route_selections.is_empty() || self.hidden_addrs.is_empty() {
            return;
        }

        // 先收集所有需要的数据（owned），再修改 self
        let hops_owned: Vec<(u8, usize, Vec<(usize, usize)>)> = {
            let hops = self.tracer_data().hops_for_flow(self.selected_flow);
            hops.iter().map(|h| {
                let addrs: Vec<(usize, usize)> = h.addrs_with_counts()
                    .enumerate()
                    .map(|(i, (_, &c))| (i, c))
                    .collect();
                (h.ttl(), h.addr_count(), addrs)
            }).collect()
        };
        let sels = self.route_selections.clone();
        let hidden = self.hidden_addrs.clone();

        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let result = crate::route_verify::verify_from_data(&hops_owned, &sels, &hidden);
            let _ = tx.send(result);
        });

        self.verifying_routes = true;
        self.verify_result_rx = Some(rx);
    }

    /// 非阻塞接收验证结果，将验证通过的地址从隐藏集合移除
    pub fn try_recv_verify_result(&mut self) {
        if let Some(rx) = &self.verify_result_rx {
            match rx.try_recv() {
                Ok(verified) => {
                    for (ttl, addr_idx) in verified {
                        self.hidden_addrs.remove(&(ttl, addr_idx));
                    }
                    self.verifying_routes = false;
                    self.verify_result_rx = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.verifying_routes = false;
                    self.verify_result_rx = None;
                }
            }
        }
    }

    /// 地址是否可见（不在隐藏集合中）
    pub fn is_addr_visible(&self, ttl: u8, addr_idx: usize) -> bool {
        !self.hidden_addrs.contains(&(ttl, addr_idx))
    }

    /// 获取某个 hop 的选中地址索引
    #[allow(dead_code)]
    pub fn route_selected_addr(&self, ttl: u8) -> Option<usize> {
        self.route_selections.get(&ttl).copied()
    }

    pub fn show_settings_columns(&mut self, column_index: usize) {
        self.show_settings = true;
        if self.settings_tab_selected != column_index {
            self.settings_tab_selected = column_index;
            self.setting_table_state.select(Some(0));
        }
    }

    pub fn toggle_hop_details(&mut self) {
        if self.show_hop_details {
            self.tui_config.max_addrs = None;
        } else {
            self.tui_config.max_addrs = Some(1);
        }
        self.show_hop_details = !self.show_hop_details;
    }

    pub fn toggle_freeze(&mut self) {
        self.frozen_start = match self.frozen_start {
            None => Some(SystemTime::now()),
            Some(_) => None,
        };
    }

    pub fn toggle_chart(&mut self) {
        self.show_chart = !self.show_chart;
        self.show_map = false;
    }

    pub fn toggle_map(&mut self) {
        self.show_map = !self.show_map;
        self.show_chart = false;
    }

    pub fn toggle_flows(&mut self) {
        if self.trace_info.len() == 1 && self.selected_tracer_data.max_flows() > 1 {
            if self.show_flows {
                self.selected_flow = FlowId(0);
                self.show_flows = false;
                self.selected_hop_address = 0;
                self.flows_start_index = 0;
            } else if self.flow_count() > 0 {
                self.selected_flow = FlowId(1);
                self.show_flows = true;
                self.selected_hop_address = 0;
                self.flows_start_index = 0;
            }
        }
    }

    pub fn expand_privacy(&mut self) {
        let hop_count = self.tracer_data().hops_for_flow(self.selected_flow).len();
        if let Some(privacy_max_ttl) = self.tui_config.privacy_max_ttl {
            if usize::from(privacy_max_ttl) < hop_count {
                self.tui_config.privacy_max_ttl = Some(privacy_max_ttl + 1);
            }
        } else {
            self.tui_config.privacy_max_ttl = Some(0);
        }
    }

    pub fn contract_privacy(&mut self) {
        if let Some(privacy_max_ttl) = self.tui_config.privacy_max_ttl {
            if privacy_max_ttl > 0 {
                self.tui_config.privacy_max_ttl = Some(privacy_max_ttl - 1);
            } else {
                self.tui_config.privacy_max_ttl = None;
            }
        }
    }

    pub fn toggle_asinfo(&mut self) {
        match self.resolver.config().resolve_method {
            ResolveMethod::Resolv | ResolveMethod::Google | ResolveMethod::Cloudflare => {
                self.tui_config.lookup_as_info = !self.tui_config.lookup_as_info;
                self.resolver.flush();
            }
            ResolveMethod::System => {}
        }
    }

    pub fn expand_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            None => Some(1),
            Some(i) if Some(i) < self.max_hosts() => Some(i + 1),
            Some(i) => Some(i),
        }
    }

    pub fn contract_hosts(&mut self) {
        self.tui_config.max_addrs = match self.tui_config.max_addrs {
            Some(i) if i > 1 => Some(i - 1),
            _ => None,
        }
    }

    pub fn zoom_in(&mut self) {
        if self.zoom_factor < MAX_ZOOM_FACTOR {
            self.zoom_factor += 1;
        }
    }

    pub fn zoom_out(&mut self) {
        if self.zoom_factor > 1 {
            self.zoom_factor -= 1;
        }
    }

    pub fn expand_hosts_max(&mut self) {
        self.tui_config.max_addrs = self.max_hosts();
    }

    pub fn contract_hosts_min(&mut self) {
        self.tui_config.max_addrs = Some(1);
    }

    /// The maximum number of hosts per hop for the currently selected trace.
    pub fn max_hosts(&self) -> Option<u8> {
        self.selected_tracer_data
            .hops_for_flow(self.selected_flow)
            .iter()
            .map(|h| h.addrs().count())
            .max()
            .and_then(|i| u8::try_from(i).ok())
    }
}

const MAX_ZOOM_FACTOR: usize = 16;
