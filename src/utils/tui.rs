use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::io::{self, Write};
use colored::Colorize;

pub struct TuiApp {
    input: String,
    all_suggestions: Vec<String>,
    filtered_suggestions: Vec<String>,
    show_suggestions: bool,
    selected_index: usize,
    history: Vec<String>,
    history_index: Option<usize>,
    current_input: String, // 保存当前输入内容
    scroll_offset: usize,  // 建议列表的滚动偏移
}

impl TuiApp {
    pub fn with_history(commands: Vec<String>, history: Vec<String>) -> Self {
        Self {
            input: String::new(),
            all_suggestions: commands,
            filtered_suggestions: Vec::new(),
            show_suggestions: false,
            selected_index: 0,
            history,
            history_index: None,
            current_input: String::new(),
            scroll_offset: 0,
        }
    }

    pub fn run(&mut self) -> Result<Option<String>> {
        // Try to enable raw mode, but fall back to basic input if it fails
        let raw_mode_enabled = enable_raw_mode().is_ok();

        let result = if raw_mode_enabled {
            print!("❯ ");
            io::stdout().flush()?;
            self.run_input_loop()
        } else {
            self.run_basic_input_loop()
        };

        if raw_mode_enabled {
            let _ = disable_raw_mode();
        }
        println!();

        result
    }

    fn run_input_loop(&mut self) -> Result<Option<String>> {
        use crossterm::event::{Event, KeyCode, KeyEventKind};

        loop {
            if let Event::Key(key) = event::read()? {
                match key.kind {
                    KeyEventKind::Press => {
                        match key.code {
                            KeyCode::Enter => {
                                if self.show_suggestions && !self.filtered_suggestions.is_empty() {
                                    if let Some(selected) = self.filtered_suggestions.get(self.selected_index) {
                                        self.input = selected.clone();
                                    }
                                }
                                if !self.input.is_empty() {
                                    return Ok(Some(self.input.clone()));
                                }
                            }
                            KeyCode::Tab => {
                                if !self.filtered_suggestions.is_empty() {
                                    self.input = self.filtered_suggestions[self.selected_index].clone();
                                    self.show_suggestions = false;
                                    self.refresh_input();
                                }
                            }
                            KeyCode::Char('/') => {
                                self.show_suggestions = true;
                                self.filtered_suggestions = self.all_suggestions.clone();
                                self.selected_index = 0;
                                self.refresh_suggestions();
                            }
                            KeyCode::Up => {
                                if self.show_suggestions {
                                    if self.selected_index > 0 {
                                        self.selected_index -= 1;
                                        if self.selected_index < self.scroll_offset {
                                            self.scroll_offset = self.selected_index;
                                        }
                                        self.refresh_suggestions();
                                    }
                                } else if !self.history.is_empty() {
                                    if let Some(idx) = self.history_index {
                                        if idx > 0 {
                                            self.history_index = Some(idx - 1);
                                            self.input = self.history[self.history_index.unwrap()].clone();
                                            self.refresh_input();
                                        }
                                    } else {
                                        self.history_index = Some(self.history.len() - 1);
                                        self.input = self.history.last().unwrap().clone();
                                        self.refresh_input();
                                    }
                                }
                            }
                            KeyCode::Down => {
                                if self.show_suggestions {
                                    if self.selected_index < self.filtered_suggestions.len().saturating_sub(1) {
                                        self.selected_index += 1;
                                        if self.selected_index >= self.scroll_offset + 5 {
                                            self.scroll_offset = self.selected_index - 4;
                                        }
                                        self.refresh_suggestions();
                                    }
                                } else if self.history_index.is_some() {
                                    if self.history_index.unwrap() < self.history.len() - 1 {
                                        self.history_index = Some(self.history_index.unwrap() + 1);
                                        self.input = self.history[self.history_index.unwrap()].clone();
                                        self.refresh_input();
                                    } else {
                                        self.history_index = None;
                                        self.input = self.current_input.clone();
                                        self.refresh_input();
                                    }
                                }
                            }
                            KeyCode::Esc => {
                                self.show_suggestions = false;
                                self.filtered_suggestions.clear();
                                self.refresh_input();
                            }
                            KeyCode::Char(c) => {
                                self.input.push(c);
                                self.current_input = self.input.clone();
                                self.history_index = None;
                                self.update_suggestions();
                                self.refresh_input();
                            }
                            KeyCode::Backspace => {
                                if !self.input.is_empty() {
                                    self.input.pop();
                                    self.current_input = self.input.clone();
                                    self.history_index = None;
                                    self.update_suggestions();
                                    self.refresh_input();
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn update_suggestions(&mut self) {
        if self.input.is_empty() {
            self.filtered_suggestions.clear();
            return;
        }

        self.filtered_suggestions = self.all_suggestions
            .iter()
            .filter(|cmd| cmd.to_lowercase().contains(&self.input.to_lowercase()))
            .cloned()
            .collect();

        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    fn refresh_input(&mut self) {
        print!("\r❯ {}", self.input);
        print!(" \x1b[K"); // Clear to end of line
        io::stdout().flush().unwrap();
    }

    fn refresh_suggestions(&mut self) {
        if self.show_suggestions && !self.filtered_suggestions.is_empty() {
            print!("\n");

            let start = self.scroll_offset;
            let end = (start + 5).min(self.filtered_suggestions.len());

            for i in start..end {
                let suggestion = &self.filtered_suggestions[i];
                if i == self.selected_index {
                    print!("> {}\n", suggestion.green().bold());
                } else {
                    print!("  {}\n", suggestion);
                }
            }

            // Move cursor back to input line
            print!("\x1b[{}A", end - start + 1);
            print!("\r❯ {}", self.input);
            print!(" \x1b[K");
            io::stdout().flush().unwrap();
        }
    }

    fn run_basic_input_loop(&mut self) -> Result<Option<String>> {
        use std::io::{self, Write};

        print!("❯ ");
        io::stdout().flush()?;

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;

        let input = line.trim().to_string();
        if input.is_empty() {
            Ok(None)
        } else {
            Ok(Some(input))
        }
    }
}