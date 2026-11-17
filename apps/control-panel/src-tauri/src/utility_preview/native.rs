//! Native tray/window shell for the development utility preview.

use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{
    AppHandle, Context, Manager, PhysicalPosition, PhysicalSize, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder, WindowEvent, Wry,
};

const WINDOW_LABEL: &str = "utility";
const TRAY_ID: &str = "utility-preview";
const MENU_SHOW: &str = "show-controls";
const MENU_QUIT: &str = "quit-preview";

/// Design starting point from the recommended plan (logical pixels).
const PREFERRED_WIDTH: f64 = 380.0;
const PREFERRED_HEIGHT: f64 = 500.0;
/// Minimum before the content scrolls; still resizable for large text.
const MIN_WIDTH: f64 = 320.0;
const MIN_HEIGHT: f64 = 360.0;
/// Gap kept between the window and the work-area edge (logical pixels).
const EDGE_MARGIN: f64 = 12.0;

/// Starts the development tray preview.
///
/// Limitations (documented rather than faked):
/// - The window is placed in a corner of the primary monitor's work area
///   (bottom-right on Windows, top-right on macOS), not anchored to the tray
///   icon's actual rectangle, and is not re-clamped after monitor/DPI changes.
/// - No single-instance enforcement: a second launch creates a second tray
///   icon and window. Production will use a single-instance mechanism.
/// - Outside activation does not dismiss the native window; close/Esc in the
///   page and the tray menu are the dismissal paths.
/// - The tray icon uses the bundled app icon; it does not encode
///   paused/sharing/attention because no agent state exists.
///
/// # Panics
///
/// Panics if Tauri cannot initialize its native application runtime.
pub(crate) fn run(mut context: Context<Wry>) {
    // The legacy console window from tauri.conf.json must not be created.
    context.config_mut().app.windows.clear();

    tauri::Builder::default()
        .setup(|app| {
            // Menu-bar utility: no Dock icon. Windows uses skip_taskbar below.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let window = build_window(app.handle())?;
            build_tray(app.handle())?;
            show_controls(&window);
            Ok(())
        })
        .run(context)
        .expect("utility preview runtime failed");
}

fn build_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let window = WebviewWindowBuilder::new(
        app,
        WINDOW_LABEL,
        WebviewUrl::App("index.html?surface=utility".into()),
    )
    .title("Software KVM · Utility preview (development)")
    .inner_size(PREFERRED_WIDTH, PREFERRED_HEIGHT)
    .min_inner_size(MIN_WIDTH, MIN_HEIGHT)
    .resizable(true)
    .skip_taskbar(true)
    .visible(false)
    .build()?;

    place_in_work_area(&window);

    // Close hides; the tray reopens the same single window.
    let hide_target = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            let _ = hide_target.hide();
        }
    });
    Ok(window)
}

fn build_tray(app: &AppHandle) -> tauri::Result<TrayIcon> {
    let header = MenuItem::with_id(
        app,
        "preview-header",
        "Development preview · owns no input",
        false,
        None::<&str>,
    )?;
    let show = MenuItem::with_id(app, MENU_SHOW, "Show controls", true, None::<&str>)?;
    let pause = MenuItem::with_id(
        app,
        "pause-unavailable",
        "Pause / Resume unavailable · agent API not integrated",
        false,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, MENU_QUIT, "Quit preview", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &header,
            &PredefinedMenuItem::separator(app)?,
            &show,
            &pause,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Software KVM utility preview (development, no agent)")
        .menu(&menu)
        .on_menu_event(|app, event| on_menu_event(app, &event));
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    // Windows convention: left click opens the utility, right click the menu.
    // macOS menu-bar convention keeps the menu on click.
    #[cfg(windows)]
    {
        builder = builder
            .show_menu_on_left_click(false)
            .on_tray_icon_event(|tray, event| {
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    if let Some(window) = tray.app_handle().get_webview_window(WINDOW_LABEL) {
                        show_controls(&window);
                    }
                }
            });
    }
    builder.build(app)
}

fn on_menu_event(app: &AppHandle, event: &MenuEvent) {
    match event.id().as_ref() {
        MENU_SHOW => {
            if let Some(window) = app.get_webview_window(WINDOW_LABEL) {
                show_controls(&window);
            }
        }
        // Exits only this process. No sharing/cleanup is claimed because this
        // mode never acquired input or started a runtime.
        MENU_QUIT => app.exit(0),
        _ => {}
    }
}

fn show_controls(window: &WebviewWindow) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

fn place_in_work_area(window: &WebviewWindow) {
    let Ok(Some(monitor)) = window.primary_monitor() else {
        return; // Keep the OS default position; documented limitation.
    };
    let area = monitor.work_area();
    let work = WorkArea {
        x: area.position.x,
        y: area.position.y,
        width: area.size.width,
        height: area.size.height,
    };
    let corner = if cfg!(target_os = "macos") {
        Corner::TopRight
    } else {
        Corner::BottomRight
    };
    let placement = compute_placement(work, monitor.scale_factor(), corner);
    let _ = window.set_size(PhysicalSize::new(placement.width, placement.height));
    let _ = window.set_position(PhysicalPosition::new(placement.x, placement.y));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkArea {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corner {
    TopRight,
    BottomRight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Placement {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

/// Fits the preferred size inside the work area (physical pixels) with a
/// margin, shrinking on small or high-scale displays, and anchors it to a
/// corner. The result never extends outside the work area.
fn compute_placement(work: WorkArea, scale_factor: f64, corner: Corner) -> Placement {
    let scale = if scale_factor.is_finite() && scale_factor > 0.0 {
        scale_factor
    } else {
        1.0
    };
    let margin = to_physical(EDGE_MARGIN, scale);
    // Drop the margin entirely if the work area cannot afford it.
    let margin_x = if work.width > margin.saturating_mul(2) {
        margin
    } else {
        0
    };
    let margin_y = if work.height > margin.saturating_mul(2) {
        margin
    } else {
        0
    };
    let width = to_physical(PREFERRED_WIDTH, scale)
        .min(work.width - margin_x * 2)
        .max(1);
    let height = to_physical(PREFERRED_HEIGHT, scale)
        .min(work.height - margin_y * 2)
        .max(1);

    let right = i64::from(work.x) + i64::from(work.width) - i64::from(margin_x);
    let x = right - i64::from(width);
    let y = match corner {
        Corner::TopRight => i64::from(work.y) + i64::from(margin_y),
        Corner::BottomRight => {
            i64::from(work.y) + i64::from(work.height) - i64::from(margin_y) - i64::from(height)
        }
    };
    Placement {
        x: clamp_i32(x),
        y: clamp_i32(y),
        width,
        height,
    }
}

fn to_physical(logical: f64, scale: f64) -> u32 {
    let value = (logical * scale).round();
    if value <= 0.0 {
        0
    } else if value >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        // In range and non-negative by the checks above.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let physical = value as u32;
        physical
    }
}

fn clamp_i32(value: i64) -> i32 {
    i32::try_from(value).unwrap_or(if value < 0 { i32::MIN } else { i32::MAX })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FHD: WorkArea = WorkArea {
        x: 0,
        y: 0,
        width: 1920,
        height: 1040,
    };

    fn inside(work: WorkArea, p: Placement) -> bool {
        i64::from(p.x) >= i64::from(work.x)
            && i64::from(p.y) >= i64::from(work.y)
            && i64::from(p.x) + i64::from(p.width) <= i64::from(work.x) + i64::from(work.width)
            && i64::from(p.y) + i64::from(p.height) <= i64::from(work.y) + i64::from(work.height)
    }

    #[test]
    fn preferred_size_bottom_right_at_scale_one() {
        let p = compute_placement(FHD, 1.0, Corner::BottomRight);
        assert_eq!(
            p,
            Placement {
                x: 1920 - 12 - 380,
                y: 1040 - 12 - 500,
                width: 380,
                height: 500
            }
        );
    }

    #[test]
    fn top_right_respects_offset_work_area() {
        // macOS: menu bar pushes the work area down; secondary monitor offset.
        let work = WorkArea {
            x: -2880,
            y: 50,
            width: 2880,
            height: 1750,
        };
        let p = compute_placement(work, 2.0, Corner::TopRight);
        assert_eq!(p.width, 760);
        assert_eq!(p.height, 1000);
        assert_eq!(p.y, 50 + 24);
        assert_eq!(p.x, -24 - 760);
        assert!(inside(work, p));
    }

    #[test]
    fn shrinks_to_small_or_high_scale_work_area() {
        let work = WorkArea {
            x: 0,
            y: 0,
            width: 1280,
            height: 680,
        };
        let p = compute_placement(work, 1.75, Corner::BottomRight);
        assert!(p.height < 875, "height clamped below scaled preferred size");
        assert!(inside(work, p));
    }

    #[test]
    fn degenerate_inputs_stay_inside() {
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY, 1.0, 3.0] {
            for work in [
                WorkArea {
                    x: 0,
                    y: 0,
                    width: 10,
                    height: 10,
                },
                WorkArea {
                    x: 5,
                    y: 5,
                    width: 1,
                    height: 1,
                },
                FHD,
            ] {
                for corner in [Corner::TopRight, Corner::BottomRight] {
                    let p = compute_placement(work, scale, corner);
                    assert!(inside(work, p), "{work:?} {scale} {corner:?} -> {p:?}");
                }
            }
        }
    }
}
