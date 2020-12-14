use crate::dmarcreport::DMARCAggregateReport;
use std::collections::HashMap;
use std::vec::Vec;

pub struct WeeklyRecord {
    pub readable_date: String,
    pub printable_data: HashMap<String, PrintableData>,
    pub dmarc_reports: Vec<DMARCAggregateReport>,
}

pub struct PrintableData {
    pub good: i64,
    pub bad: i64,
}
