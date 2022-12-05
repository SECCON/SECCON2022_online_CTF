#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use egui::{FontFamily, FontId, TextStyle};
use egui_extras::image;

fn main() {
    let options = eframe::NativeOptions {
        drag_and_drop_support: false,
        initial_window_size: Some(egui::vec2(800.0, 360.0)),
        resizable: false,
        ..Default::default()
    };
    eframe::run_native(
        "eguite - SECCON 2022 Quals",
        options,
        Box::new(|cc| Box::new(Crackme::new(cc))),
    );
}

struct Crackme {
    logo: image::RetainedImage,
    flag: String,
    message: String,
}

impl Crackme {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        use FontFamily::Monospace;

        let mut style = (*cc.egui_ctx.style()).clone();
        style.text_styles = [
            (TextStyle::Heading, FontId::new(25.0, Monospace)),
            (TextStyle::Body, FontId::new(32.0, Monospace)),
            (TextStyle::Button, FontId::new(32.0, Monospace)),
        ].into();
        style.visuals.override_text_color = Some(egui::Color32::WHITE);
        cc.egui_ctx.set_style(style);

        Self {
            logo: image::RetainedImage::from_image_bytes(
                "seccon.png",
                include_bytes!("seccon.png")
            ).unwrap(),
            flag: "".to_owned(),
            message: "".to_owned()
        }
    }

    fn onclick(&mut self) -> bool {
        if self.flag.len() == 43
            && self.flag.starts_with("SECCON{")
            && self.flag.ends_with("}")
            && self.flag.chars().nth(19).unwrap() == '-'
            && self.flag.chars().nth(26).unwrap() == '-'
            && self.flag.chars().nth(33).unwrap() == '-'
        {
            let a = u64::from_str_radix(
                &self.flag.chars().skip(7).take(12).collect::<String>(), 16
            ).unwrap_or(0);
            let b = u64::from_str_radix(
                &self.flag.chars().skip(20).take(6).collect::<String>(), 16
            ).unwrap_or(0);
            let c = u64::from_str_radix(
                &self.flag.chars().skip(27).take(6).collect::<String>(), 16
            ).unwrap_or(0);
            let d = u64::from_str_radix(
                &self.flag.chars().skip(34).take(8).collect::<String>(), 16
            ).unwrap_or(0);

            if a + b == 152980493131626 
                && b + c == 15172161
                && c + d == 4199291551
                && d + a == 152984677251016
                && b ^ c ^ d == 4184371021
            {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl eframe::App for Crackme {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(16.);
            ui.with_layout(
                egui::Layout::top_down_justified(egui::Align::Center), |ui| {
                    self.logo.show(ui);
                }
            );

            ui.add_space(16.);
            ui.with_layout(
                egui::Layout::top_down_justified(egui::Align::Center), |ui| {
                    ui.label("ENTER LICENSE");
                    ui.add_space(8.);
                    ui.text_edit_singleline(&mut self.flag);
                    ui.add_space(8.);
                    if ui.button("CHECK").clicked() {
                        self.message = if self.onclick() {
                            "Successfully validated!".to_string()
                        } else {
                            "Invalid license...".to_string()
                        }
                    }
                    ui.add_space(8.);
                    ui.label(format!("{}", self.message));
                }
            );
        });
    }
}
