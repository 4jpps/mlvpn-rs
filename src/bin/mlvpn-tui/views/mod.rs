//! One module per top-level view, plus the shared body dispatcher.

pub mod debug;
pub mod links;
pub mod overview;
pub mod reliability;
pub mod system;
pub mod traffic;

use crate::model::{SharedState, Tab, Ui};
use crate::theme::muted;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

/// Screen-size class. Compact drops borders, secondary columns and
/// secondary panels so a small SSH window or tmux pane still shows the
/// health state and the links.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Density {
    Compact,
    Normal,
}

impl Density {
    pub fn for_area(area: Rect) -> Density {
        if area.width < 80 || area.height < 20 {
            Density::Compact
        } else {
            Density::Normal
        }
    }
}

pub fn panel(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "))
}

pub fn waiting(f: &mut Frame, area: Rect, title: &str) {
    f.render_widget(
        Paragraph::new(Line::from(Span::styled("waiting for data...", muted())))
            .block(panel(title)),
        area,
    );
}

pub fn draw_body(f: &mut Frame, area: Rect, state: &SharedState, ui: &Ui, density: Density) {
    if ui.tab == Tab::Debug {
        return debug::draw(f, area, state, ui, density);
    }
    let Some(snap) = &state.snapshot else {
        return waiting(f, area, ui.tab.title());
    };
    match ui.tab {
        Tab::Overview => overview::draw(f, area, state, snap, density),
        Tab::Links => links::draw(f, area, snap, ui, density),
        Tab::Traffic => traffic::draw(f, area, state, snap, density),
        Tab::Reliability => reliability::draw(f, area, snap, density),
        Tab::System => system::draw(f, area, snap, density),
        Tab::Debug => unreachable!("handled above"),
    }
}
