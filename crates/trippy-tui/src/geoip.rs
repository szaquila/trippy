use std::{cell::RefCell, collections::HashMap, net::IpAddr, path::Path, rc::Rc, str::FromStr};

use anyhow::Context;
use itertools::Itertools;
use maxminddb::Reader;
use xdb::{search_by_ip, searcher_init, searcher_load};

#[derive(Debug, Clone, Default)]
pub struct GeoIpCity {
	pub latitude: Option<f64>,
	pub longitude: Option<f64>,
	pub accuracy_radius: Option<u16>,
	pub city: Option<String>,
	pub subdivision: Option<String>,
	pub subdivision_code: Option<String>,
	pub country: Option<String>,
	pub country_code: Option<String>,
	pub continent: Option<String>,
}

impl GeoIpCity {
	pub fn short_name(&self) -> String {
		[
			self.city.as_ref(),
			self.subdivision_code.as_ref(),
			self.country_code.as_ref(),
		]
		.into_iter()
		.flatten()
		.join("")
		.replacen("0", "", 3)
	}

	pub fn long_name(&self) -> String {
		if let Some(ref s) = self.subdivision {
			if s.eq("北京") || s.eq("上海") || s.eq("天津") || s.eq("重庆") {
				return [
					self.city.as_ref(),
					self.country.as_ref(),
					self.continent.as_ref()
				]
				.into_iter()
				.flatten()
				.join("")
				.replacen("0", "", 3);
			}
		}
		[
			self.city.as_ref(),
			self.subdivision.as_ref(),
			self.country.as_ref(),
			self.continent.as_ref(),
		]
		.into_iter()
		.flatten()
		.join("")
		.replacen("0", "", 3)
	}

	pub fn location(&self) -> String {
		format!(
			"{}, {} (~{}km)",
			self.latitude.unwrap_or_default(),
			self.longitude.unwrap_or_default(),
			self.accuracy_radius.unwrap_or_default(),
		)
	}

	pub const fn coordinates(&self) -> Option<(f64, f64, u16)> {
		match (self.latitude, self.longitude, self.accuracy_radius) {
			(Some(lat), Some(long), Some(radius)) => Some((lat, long, radius)),
			_ => None,
		}
	}
}

mod ipinfo {
	use serde::{Deserialize, Serialize};
	use serde_with::serde_as;

	/// ipinfo.io's mmdb database format.
	///
	/// Support both the "IP to Geolocation Extended" and "IP to Country + ASN" database formats.
	///
	/// IP to Geolocation Extended Database:
	/// See <https://ipinfo.io/developers/ip-to-geolocation-extended/>
	///
	/// IP to Country + ASN Database;
	/// See <https://ipinfo.io/developers/ip-to-country-asn-database/>
	#[serde_as]
	#[derive(Debug, Serialize, Deserialize)]
	pub struct IpInfoGeoIp {
		/// "42.48948"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub latitude: Option<String>,
		/// "-83.14465"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub longitude: Option<String>,
		/// "500"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub radius: Option<String>,
		/// "Royal Oak"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub city: Option<String>,
		/// "Michigan"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub region: Option<String>,
		/// "48067"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub postal_code: Option<String>,
		/// "US"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub country: Option<String>,
		/// "Japan"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub country_name: Option<String>,
		/// "Asia"
		#[serde(default)]
		#[serde_as(as = "serde_with::NoneAsEmptyString")]
		pub continent_name: Option<String>,
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		#[test]
		fn test_empty() {
			let json = "{}";
			let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
			assert_eq!(None, value.latitude);
			assert_eq!(None, value.longitude);
			assert_eq!(None, value.radius);
			assert_eq!(None, value.city);
			assert_eq!(None, value.region);
			assert_eq!(None, value.postal_code);
			assert_eq!(None, value.country.as_deref());
			assert_eq!(None, value.country_name.as_deref());
			assert_eq!(None, value.continent_name.as_deref());
		}

		#[test]
		fn test_country_asn_db_format() {
			let json = r#"
                {
                    "start_ip": "40.96.54.192",
                    "end_ip": "40.96.54.255",
                    "country": "JP",
                    "country_name": "Japan",
                    "continent": "AS",
                    "continent_name": "Asia",
                    "asn": "AS8075",
                    "as_name": "Microsoft Corporation",
                    "as_domain": "microsoft.com"
                }
                "#;
			let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
			assert_eq!(None, value.latitude);
			assert_eq!(None, value.longitude);
			assert_eq!(None, value.radius);
			assert_eq!(None, value.city);
			assert_eq!(None, value.region);
			assert_eq!(None, value.postal_code);
			assert_eq!(Some("JP"), value.country.as_deref());
			assert_eq!(Some("Japan"), value.country_name.as_deref());
			assert_eq!(Some("Asia"), value.continent_name.as_deref());
		}

		#[test]
		fn test_extended_db_format() {
			let json = r#"
                {
                    "start_ip": "60.127.10.249",
                    "end_ip": "60.127.10.249",
                    "join_key": "60.127.0.0",
                    "city": "Yokohama",
                    "region": "Kanagawa",
                    "country": "JP",
                    "latitude": "35.43333",
                    "longitude": "139.65",
                    "postal_code": "220-8588",
                    "timezone": "Asia/Tokyo",
                    "geoname_id": "1848354",
                    "radius": "500"
                }
                "#;
			let value: IpInfoGeoIp = serde_json::from_str(json).unwrap();
			assert_eq!(Some("35.43333"), value.latitude.as_deref());
			assert_eq!(Some("139.65"), value.longitude.as_deref());
			assert_eq!(Some("500"), value.radius.as_deref());
			assert_eq!(Some("Yokohama"), value.city.as_deref());
			assert_eq!(Some("Kanagawa"), value.region.as_deref());
			assert_eq!(Some("220-8588"), value.postal_code.as_deref());
			assert_eq!(Some("JP"), value.country.as_deref());
			assert_eq!(None, value.country_name.as_deref());
			assert_eq!(None, value.continent_name.as_deref());
		}
	}
}

impl From<ipinfo::IpInfoGeoIp> for GeoIpCity {
	fn from(value: ipinfo::IpInfoGeoIp) -> Self {
		Self {
			latitude: value.latitude.and_then(|val| f64::from_str(&val).ok()),
			longitude: value.longitude.and_then(|val| f64::from_str(&val).ok()),
			accuracy_radius: value.radius.and_then(|val| u16::from_str(&val).ok()),
			city: value.city,
			subdivision: value.region,
			subdivision_code: value.postal_code,
			country: value.country_name,
			country_code: value.country,
			continent: value.continent_name,
		}
	}
}

impl From<maxminddb::geoip2::City<'_>> for GeoIpCity {
	fn from(value: maxminddb::geoip2::City<'_>) -> Self {
		let city = value
			.city
			.as_ref()
			.and_then(|city| city.names.as_ref())
			.and_then(|names| names.get(LOCALE))
			.map(ToString::to_string);
		let subdivision = value
			.subdivisions
			.as_ref()
			.and_then(|c| c.first())
			.and_then(|c| c.names.as_ref())
			.and_then(|names| names.get(LOCALE))
			.map(ToString::to_string);
		let subdivision_code = value
			.subdivisions
			.as_ref()
			.and_then(|c| c.first())
			.and_then(|c| c.iso_code.as_ref())
			.map(ToString::to_string);
		let country = value
			.country
			.as_ref()
			.and_then(|country| country.names.as_ref())
			.and_then(|names| names.get(LOCALE))
			.map(ToString::to_string);
		let country_code = value
			.country
			.as_ref()
			.and_then(|country| country.iso_code.as_ref())
			.map(ToString::to_string);
		let continent = value
			.continent
			.as_ref()
			.and_then(|continent| continent.names.as_ref())
			.and_then(|names| names.get(LOCALE))
			.map(ToString::to_string);
		let latitude = value
			.location
			.as_ref()
			.and_then(|location| location.latitude);
		let longitude = value
			.location
			.as_ref()
			.and_then(|location| location.longitude);
		let accuracy_radius = value
			.location
			.as_ref()
			.and_then(|location| location.accuracy_radius);
		Self {
			latitude,
			longitude,
			accuracy_radius,
			city,
			subdivision,
			subdivision_code,
			country,
			country_code,
			continent,
		}
	}
}

/// The default locale.
const LOCALE: &str = "en";

/// Alias for a cache of `GeoIp` data.
type Cache = RefCell<HashMap<IpAddr, Rc<GeoIpCity>>>;

/// Lookup `GeoIpCity` data form an `IpAddr`.
#[derive(Debug)]
pub struct GeoIpLookup {
	reader: Option<Reader<Vec<u8>>>,
	cache: Cache,
	xdb: bool,
}

impl GeoIpLookup {
	/// Create a new `GeoIpLookup` from a `MaxMind` DB file.
	pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
		if path.as_ref().extension().unwrap() == "xdb" {
			let path_str = String::from(path.as_ref().to_str().unwrap());
			searcher_init(Some(path_str));
			Ok(Self {
				reader: None,
				cache: RefCell::new(HashMap::new()),
				xdb: true,
			})
		} else {
			let reader = maxminddb::Reader::open_readfile(path.as_ref())
				.context(format!("{}", path.as_ref().display()))?;
			Ok(Self {
				reader: Some(reader),
				cache: RefCell::new(HashMap::new()),
				xdb: false,
			})
		}
	}

	/// Create a `GeoIpLookup` that returns `None` for all `IpAddr` lookups.
	pub fn empty() -> Self {
		if searcher_load() {
			Self {
				reader: None,
				cache: RefCell::new(HashMap::new()),
				xdb: true,
			}
		} else {
			Self {
				reader: None,
				cache: RefCell::new(HashMap::new()),
				xdb: false,
			}
		}
	}

	/// Lookup an `GeoIpCity` for an `IpAddr`.
	///
	/// If an entry is found it is cached and returned, otherwise None is returned.
	pub fn lookup(&self, addr: IpAddr) -> anyhow::Result<Option<Rc<GeoIpCity>>> {
		if let Some(reader) = &self.reader {
			if let Some(geo) = self.cache.borrow().get(&addr) {
				return Ok(Some(geo.clone()));
			}
			let city_data = if reader.metadata.database_type.starts_with("ipinfo") {
				GeoIpCity::from(reader.lookup::<ipinfo::IpInfoGeoIp>(addr)?)
			} else {
				GeoIpCity::from(reader.lookup::<maxminddb::geoip2::City<'_>>(addr)?)
			};
			let geo = self.cache.borrow_mut().insert(addr, Rc::new(city_data));
			Ok(geo)
		} else if self.xdb && addr.is_ipv4() {
			if let IpAddr::V4(ip) = addr {
				if let Ok(ips) = search_by_ip(ip) {
					let ips = ips.split('|').collect::<Vec<&str>>();
					let city_data = GeoIpCity {
						latitude: Some(0.0),
						longitude: Some(0.0),
						accuracy_radius: Some(0),
						city: Some(ips[0].to_string()),
						subdivision: Some(ips[2].to_string()),
						subdivision_code: Some(ips[2].to_string()),
						country: Some(ips[3].to_string()),
						country_code: Some(ips[3].to_string()),
						continent: Some(ips[4].to_string()),
					};
					let geo = self.cache.borrow_mut().insert(addr, Rc::new(city_data));
					Ok(geo)
				} else {
					Ok(None)
				}
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}
}
