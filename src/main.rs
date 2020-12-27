extern crate clap;
use chrono::Datelike;
use chrono::{Duration, Local, NaiveDate, NaiveDateTime};
use clap::{App, Arg};
use log::LevelFilter;
use log::{debug, error, info, trace};
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::exit;
use std::vec::Vec;

pub use dmarcreport::*;
pub mod dmarcreport;

use records::*;
pub mod records;

fn main() -> std::io::Result<()> {
    let matches = App::new("Tiny DMARC Report Generator")
        .version("0.0.1")
        .about("Scans all DMARC XML reports in a folder and generates a simple HTML report")
        .arg(
            Arg::with_name("INPUTDIR")
                .short("i")
                .long("inputDir")
                .value_name("INPUTDIR")
                .help("Sets the directory containing the DMARC reports")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("OUTPUTFILE")
                .short("f")
                .long("outputFile")
                .help("Sets the output file to write to")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("FORMAT")
                .short("o")
                .long("outputFormat")
                .help("Sets the output file format")
                .required(false)
                .takes_value(true)
                .possible_values(&["html", "txt", "json"])
                .default_value("txt"),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity (-vvv is trace)"),
        )
        .get_matches();

    let input_dir = matches.value_of("INPUTDIR").unwrap();
    let mut output_file = "";
    if let Some(output_file_match) = matches.value_of("OUTPUTFILE") {
        output_file = output_file_match;
    }
    let output_format = matches.value_of("FORMAT").unwrap();
    let verbose_level = matches.occurrences_of("v");

    let log_level;
    match verbose_level {
        0 => {
            log_level = LevelFilter::Warn;
        }
        1 => {
            log_level = LevelFilter::Info;
        }
        2 => {
            log_level = LevelFilter::Debug;
        }
        3 => {
            log_level = LevelFilter::Trace;
        }
        _ => {
            log_level = LevelFilter::Trace;
        }
    }

    match SimpleLogger::new().with_level(log_level).init() {
        Ok(()) => {}
        Err(e) => println!("Failed to initialise logger: {:?}", e),
    }

    let all_data;
    match read_report_files(input_dir) {
        Ok(all_data_read) => {
            all_data = all_data_read;
            info!("Processed {:?} files", all_data.len());
        }
        Err(e) => {
            error!("Something went wrong: {:?}", e);
            exit(1);
        }
    };

    let processed_data;
    match process_reports(all_data) {
        Ok(processed_data_read) => {
            processed_data = processed_data_read;
            info!("Processed into {:?} records", processed_data.len());
        }
        Err(e) => {
            error!("Something went wrong: {:?}", e);
            exit(1);
        }
    }

    let report = generate_report(processed_data, output_format);
    output_report(report, output_file);

    Ok(())
}

/**
 * Read in each file one at a time and load as a DMARCAggregateReport, then process them all.
 */
fn read_report_files(input_dir: &str) -> std::io::Result<Vec<DMARCAggregateReport>> {
    let input_path = Path::new(input_dir);
    let mut all_data: Vec<DMARCAggregateReport> = Vec::new();

    if input_path.is_dir() {
        for dir_entry in fs::read_dir(input_path)? {
            let dir_entry = dir_entry?;
            if !dir_entry.path().is_dir() {
                debug!("Reading file: {:?}", dir_entry.file_name());
                let mut contents = String::new();
                let mut file = File::open(dir_entry.path())?;
                file.read_to_string(&mut contents)?;

                let report = parse_report_xml(contents).unwrap();

                trace!(
                    "Made a struct and it is for org {:?}",
                    report.report_metadata.org_name
                );

                all_data.push(report);
            }
        }
    }

    Ok(all_data)
}

/**
 * parse the Aggregate report XML into a DMARCAggregateReport instance
 */
fn parse_report_xml(xml: String) -> std::io::Result<DMARCAggregateReport> {
    let doc = roxmltree::Document::parse(&xml).unwrap();

    match dmarcreport::DMARCAggregateReport::process_report(&doc.root()) {
        Ok(report) => Ok(report),
        Err(e) => {
            eprintln!("Something went wrong 1: {}", e);
            exit(1);
        }
    }
}

/**
 * walk through the DMARCAggregateReport instances building up a reportable form of good and bad messages
 * in weekly time buckets for each domain found
 */
fn process_reports(
    mut reports: Vec<DMARCAggregateReport>,
) -> std::io::Result<HashMap<i64, WeeklyRecord>> {
    trace!("Processing {:?} reports", reports.len());
    let mut report_hash: HashMap<i64, WeeklyRecord> = HashMap::new();

    // First build a hash with the week-start timestamp as the key and a WeeklyRecord as the value
    for dmarc_report in reports.drain(0..) {
        trace!(
            "Processing report with start time {:?}",
            dmarc_report.report_metadata.date_range.begin
        );
        let mut realtime =
            NaiveDateTime::from_timestamp(dmarc_report.report_metadata.date_range.begin, 0);
        realtime = realtime
            - Duration::seconds(
                ((realtime.weekday().num_days_from_monday() + 1) * 24 * 60 * 60).into(),
            );
        let starttime =
            NaiveDate::from_ymd(realtime.year(), realtime.month(), realtime.day()).and_hms(0, 0, 0);
        let start_timestamp = starttime.timestamp();

        if report_hash.contains_key(&start_timestamp) {
            trace!("report has already has key {}", &start_timestamp);
            if let Some(record) = report_hash.get_mut(&start_timestamp) {
                record.dmarc_reports.push(dmarc_report);
            }
        } else {
            trace!("first entry for key {}", &start_timestamp);
            let mut dmark_reports: Vec<DMARCAggregateReport> = Vec::new();
            dmark_reports.push(dmarc_report);
            let data_records: HashMap<String, PrintableData> = HashMap::new();
            let start_date = NaiveDateTime::from_timestamp(start_timestamp, 0).date();
            let end_date =
                NaiveDateTime::from_timestamp(start_timestamp + (6 * 24 * 60 * 60), 0).date();
            let readable_date = format!(
                "{} - {}",
                start_date.format("%a %e %B").to_string(),
                end_date.format("%a %e %B").to_string()
            );
            let record = WeeklyRecord {
                readable_date: readable_date,
                printable_data: data_records,
                dmarc_reports: dmark_reports,
            };
            report_hash.insert(start_timestamp, record);
        }
    }

    // Then walk through the hash processing each WeeklyRecord into a PrintableData
    for weekly_record in report_hash.values_mut() {
        for dmarc_report in weekly_record.dmarc_reports.iter() {
            if !weekly_record
                .printable_data
                .contains_key(&dmarc_report.report_metadata.org_name)
            {
                weekly_record.printable_data.insert(
                    String::from(&dmarc_report.report_metadata.org_name),
                    PrintableData { good: 0, bad: 0 },
                );
            }
            if let Some(printable_data) = weekly_record
                .printable_data
                .get_mut(&dmarc_report.report_metadata.org_name)
            {
                for record in dmarc_report.records.iter() {
                    if record.row.policy_evaluated.disposition == "none" {
                        printable_data.good += record.row.count;
                    } else {
                        printable_data.bad += record.row.count;
                    }
                }
            }
        }
    }

    Ok(report_hash)
}

/**
 * Generate a report as a String of the requested format
 */
fn generate_report(processed_data: HashMap<i64, WeeklyRecord>, output_format: &str) -> String {
    match output_format {
        "html" => generate_html_report(processed_data),
        "txt" => generate_txt_report(processed_data),
        "json" => generate_json_report(processed_data),
        _ => String::from("not sure how this could ever be hit"),
    }
}

/**
 * Output the report, either to stdout or the requested file
 */
fn output_report(report: String, output_file: &str) {
    if output_file.len() == 0 {
        println!("{}", report);
    } else {
        let path = Path::new(output_file);
        let display = path.display();
        println!("Writing to file {:?}", display);

        let mut file = match File::create(&path) {
            Err(why) => panic!("couldn't create {}: {}", display, why),
            Ok(file) => file,
        };

        match file.write_all(report.as_bytes()) {
            Err(why) => panic!("couldn't write to {}: {}", display, why),
            Ok(_) => println!("successfully wrote to {}", display),
        }
    }
}

/**
 * Generate a HTML report
 */
fn generate_html_report(processed_data: HashMap<i64, WeeklyRecord>) -> String {
    info!("Generating html report");

    let mut report = String::from("<!DOCTYPE html>\n");
    report += &String::from("<html lang=\"en\">\n");
    report += &String::from("  <head>\n");
    report += &String::from("    <meta charset=\"utf-8\">\n");
    report += &String::from("    <title>DMARC Reports Summary</title>\n");
    report += &String::from("    <style>\n");
    report += &String::from("      html {font-family: Arial, Helvetica, sans-serif;}\n");
    report += &String::from(
        "      th {background-color: #77b7c6; color: #ffffff; padding: 6px 3px 6px 3px;}\n",
    );
    report +=
        &String::from("      td {background-color: #eeeeee; padding: 5px; vertical-align: top;}\n");
    report += &String::from("      td.date {text-align: right; background-color: #ebfbff;}\n");
    report += &String::from("      td.good {background-color: #e9f7e5;}\n");
    report += &String::from("      td.bad {background-color: #f9e0e0;}\n");
    report += &String::from("    </style>\n");
    report += &String::from("  </head>\n");
    report += &String::from("  <body>\n");
    report += &String::from("    <h1>DMARC Reports Summary</h1>\n");
    report += &String::from(format!(
        "    <p>Report generated at {}</p>\n",
        Local::now().format("%+").to_string()
    ));
    report += &String::from("    <table>\n");
    report += &String::from("      <tr>\n");
    report += &String::from("        <th>Date</th>\n");
    report += &String::from("        <th>Good</th>\n");
    report += &String::from("        <th>Bad</th>\n");
    report += &String::from("      </tr>\n");

    let mut sorted_keys = Vec::new();
    for key in processed_data.keys() {
        sorted_keys.push(key);
    }
    sorted_keys.sort();

    for key in sorted_keys.iter() {
        if let Some(record) = processed_data.get(&key) {
            let mut sorted_domains = Vec::new();
            for key in record.printable_data.keys() {
                sorted_domains.push(key);
            }
            sorted_domains.sort();
            report += &String::from("      <tr>\n");
            report += &String::from(format!(
                "        <td class=\"date\">{}</td>\n",
                record.readable_date
            ));
            report += &String::from(format!("        <td class=\"good\">"));
            let mut total_bad = 0;
            for domain in sorted_domains.iter() {
                if let Some(printable_data) = record.printable_data.get(*domain) {
                    report += &String::from(format!("{}: {:?}<br/>", domain, printable_data.good));
                    total_bad += printable_data.bad;
                }
            }
            report += &String::from(format!("</td>\n"));
            if total_bad > 0 {
                report += &String::from(format!("        <td class=\"bad\">"));
            } else {
                report += &String::from(format!("        <td class=\"good\">"));
            }
            for domain in sorted_domains.iter() {
                if let Some(printable_data) = record.printable_data.get(*domain) {
                    report += &String::from(format!("{}: {:?}<br/>", domain, printable_data.bad));
                }
            }
            report += &String::from(format!("</td>\n      </tr>\n"));
        }
    }

    report += &String::from("    </table>\n");
    report += &String::from("  </body>\n");
    report += &String::from("</html>\n");

    report
}

/**
 * Generate a text based report
 */
fn generate_txt_report(processed_data: HashMap<i64, WeeklyRecord>) -> String {
    info!("Generating text report");
    let mut report = String::from(format!(
        "DMARC REPORT GENERATED AT {}\n===\n",
        Local::now().format("%+").to_string()
    ));

    let mut sorted_keys = Vec::new();
    for key in processed_data.keys() {
        sorted_keys.push(key);
    }
    sorted_keys.sort();

    for key in sorted_keys.iter() {
        if let Some(record) = processed_data.get(&key) {
            let mut sorted_domains = Vec::new();
            for key in record.printable_data.keys() {
                sorted_domains.push(key);
            }
            sorted_domains.sort();
            report += &String::from(format!("Date: {}\n", record.readable_date));
            for domain in sorted_domains.iter() {
                if let Some(printable_data) = record.printable_data.get(*domain) {
                    report += &String::from(format!(
                        "Domain: {:?} - Good: {:?} - Bad: {:?}\n",
                        domain, printable_data.good, printable_data.bad
                    ));
                }
            }
            report += &String::from(format!("---\n"));
        }
    }

    report
}

/**
 * Generate a JSON object of the report
 */
fn generate_json_report(processed_data: HashMap<i64, WeeklyRecord>) -> String {
    info!("Generating json report");
    let mut report = String::from(format!(
        "{{\"report-time\":\"{}\",\"report\":[",
        Local::now().format("%+").to_string()
    ));

    let mut sorted_keys = Vec::new();
    for key in processed_data.keys() {
        sorted_keys.push(key);
    }
    sorted_keys.sort();

    let mut first_date_record = true;
    for key in sorted_keys.iter() {
        if let Some(record) = processed_data.get(&key) {
            let mut sorted_domains = Vec::new();
            for key in record.printable_data.keys() {
                sorted_domains.push(key);
            }
            sorted_domains.sort();
            if first_date_record {
                first_date_record = false;
            } else {
                report += &String::from(",")
            }
            report += &String::from(format!(
                "{{\"date-range\":\"{}\",\"domains\":[",
                record.readable_date
            ));
            let mut first_domain_record = true;
            for domain in sorted_domains.iter() {
                if let Some(printable_data) = record.printable_data.get(*domain) {
                    if first_domain_record {
                        first_domain_record = false;
                    } else {
                        report += &String::from(",")
                    }
                    report += &String::from(format!(
                        "{{\"domain\":\"{}\",\"good\":{},\"bad\":{}}}",
                        domain, printable_data.good, printable_data.bad
                    ));
                }
            }
            report += &String::from("]}");
        }
    }

    report += &String::from("]}");

    report
}
