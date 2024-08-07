use comfy_table::{
	presets::{ASCII_MARKDOWN, UTF8_FULL},
	ContentArrangement,
	Table,
};
use itertools::Itertools;
use trippy_core::State;
use trippy_dns::Resolver;
use xdb::{search_by_ip, searcher_load};

use crate::app::TraceInfo;

/// Generate a markdown table report of trace data.
pub fn report_md<R: Resolver>(
	info: &TraceInfo,
	report_cycles: usize,
	resolver: &R,
) -> anyhow::Result<()> {
	run_report_table(info, report_cycles, resolver, ASCII_MARKDOWN)
}

/// Generate a pretty table report of trace data.
pub fn report_pretty<R: Resolver>(
	info: &TraceInfo,
	report_cycles: usize,
	resolver: &R,
) -> anyhow::Result<()> {
	run_report_table(info, report_cycles, resolver, UTF8_FULL)
}

fn run_report_table<R: Resolver>(
	info: &TraceInfo,
	report_cycles: usize,
	resolver: &R,
	preset: &str,
) -> anyhow::Result<()> {
	let trace = super::wait_for_round(&info.data, report_cycles)?;
	let columns = vec![
		"Hop", "IPs", "Addrs", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StdDev",
	];
	let mut table = Table::new();
	table
		.load_preset(preset)
		.set_content_arrangement(ContentArrangement::Dynamic)
		.set_header(columns);
	searcher_load();
	for hop in trace.hops(State::default_flow_id()) {
		let ttl = hop.ttl().to_string();
		let ips = hop.addrs().join("\n");
		let ip = if ips.is_empty() {
			String::from("???")
		} else {
			ips
		};
		let hosts = hop
			.addrs()
			.map(|ip| {
				if let Ok(ips) = search_by_ip(*ip) {
					// let ips = ips.split('|').collect::<Vec<&str>>();
					// let city_data = GeoIpCity {
					// 	latitude: Some(0.0),
					// 	longitude: Some(0.0),
					// 	accuracy_radius: Some(0),
					// 	city: Some(ips[0].to_string()),
					// 	subdivision: Some(ips[2].to_string()),
					// 	subdivision_code: Some(ips[2].to_string()),
					// 	country: Some(ips[3].to_string()),
					// 	country_code: Some(ips[3].to_string()),
					// 	continent: Some(ips[4].to_string()),
					// }
					ips
				} else {
					resolver.reverse_lookup(*ip).to_string()
				}
			})
			.join("\n");
		let host = if hosts.is_empty() {
			String::from("???")
		} else {
			hosts
		};
		let sent = hop.total_sent().to_string();
		let recv = hop.total_recv().to_string();
		let last = hop
			.last_ms()
			.map_or_else(|| String::from("???"), |last| format!("{last:.1}"));
		let best = hop
			.best_ms()
			.map_or_else(|| String::from("???"), |best| format!("{best:.1}"));
		let worst = hop
			.worst_ms()
			.map_or_else(|| String::from("???"), |worst| format!("{worst:.1}"));
		let stddev = format!("{:.1}", hop.stddev_ms());
		let avg = format!("{:.1}", hop.avg_ms());
		let loss_pct = format!("{:.1}", hop.loss_pct());
		table.add_row(vec![
			&ttl, &ip, &host, &loss_pct, &sent, &recv, &last, &avg, &best, &worst, &stddev,
		]);
	}
	println!("{table}");
	Ok(())
}
