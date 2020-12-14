use log::{debug, error, trace};
use std::io::{Error, ErrorKind};
use std::vec::Vec;

#[derive(Debug)]
pub struct DMARCAggregateReport {
    pub report_metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub records: Vec<Record>,
}

#[derive(Debug)]
pub struct ReportMetadata {
    pub org_name: String,
    pub date_range: DateRange,
}

#[derive(Debug)]
pub struct DateRange {
    pub begin: i64,
    pub end: i64,
}

#[derive(Debug)]
pub struct PolicyPublished {
    pub domain: String,
    pub adkim: String,
    pub aspf: String,
    pub p: String,
    pub sp: String,
    pub pct: i8,
}

#[derive(Debug)]
pub struct Record {
    pub row: Row,
    pub identifiers: Identifiers,
    pub auth_results: AuthResults,
}

#[derive(Debug)]
pub struct Row {
    pub source_ip: String,
    pub count: i64,
    pub policy_evaluated: PolicyEvaluated,
}

#[derive(Debug)]
pub struct PolicyEvaluated {
    pub disposition: String,
    pub dkim: String,
    pub spf: String,
}

#[derive(Debug)]
pub struct Identifiers {
    pub header_from: String,
}

#[derive(Debug)]
pub struct AuthResults {
    pub dkim: DKIM,
    pub spf: SPF,
}

#[derive(Debug)]
pub struct DKIM {
    pub domain: String,
    pub result: String,
    pub selector: String,
}

#[derive(Debug)]
pub struct SPF {
    pub domain: String,
    pub result: String,
}

impl DMARCAggregateReport {
    pub fn process_report(root: &roxmltree::Node) -> std::io::Result<DMARCAggregateReport> {
        if !root.has_children() {
            return Err(Error::new(ErrorKind::Other, "Bad XML"));
        }

        let feedback;
        match get_child(root, "feedback") {
            Ok(feedback_read) => feedback = feedback_read,
            Err(_) => {
                error!("XML is missing feedback element");
                return Err(Error::new(ErrorKind::Other, "Bad XML"));
            }
        }

        let report_metadata;
        let policy_published;
        let records;
        match ReportMetadata::process_report_metadata(&feedback) {
            Ok(report_metadata_returned) => {
                report_metadata = report_metadata_returned;
            }
            Err(e) => {
                error!("Failed to process report_metadata: {}", e);
                return Err(Error::new(ErrorKind::Other, "Bad XML"));
            }
        }
        match PolicyPublished::process_policy_published(&feedback) {
            Ok(policy_published_returned) => {
                policy_published = policy_published_returned;
            }
            Err(e) => {
                error!("Failed to process policy_published: {}", e);
                return Err(Error::new(ErrorKind::Other, "Bad XML"));
            }
        }
        match Record::process_records(&feedback) {
            Ok(records_returned) => {
                records = records_returned;
            }
            Err(e) => {
                error!("Failed to process record: {}", e);
                return Err(Error::new(ErrorKind::Other, "Bad XML"));
            }
        }
        Ok(DMARCAggregateReport {
            report_metadata: report_metadata,
            policy_published: policy_published,
            records: records,
        })
    }
}

impl ReportMetadata {
    fn process_report_metadata(feedback: &roxmltree::Node) -> std::io::Result<ReportMetadata> {
        match get_child(&feedback, "report_metadata") {
            Ok(report_metadata) => {
                let org_name = match get_value(&report_metadata, "org_name") {
                    Some(org_name_returned) => org_name_returned,
                    None => String::from("unknown"),
                };
                let date_range = match DateRange::process_date_range(&report_metadata) {
                    Ok(date_range_returned) => date_range_returned,
                    Err(_) => DateRange { begin: -1, end: -1 },
                };

                Ok(ReportMetadata {
                    org_name: org_name,
                    date_range: date_range,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl DateRange {
    fn process_date_range(report_metadata: &roxmltree::Node) -> std::io::Result<DateRange> {
        match get_child(&report_metadata, "date_range") {
            Ok(date_range) => {
                let begin = match get_value(&date_range, "begin") {
                    Some(begin_returned) => match begin_returned.parse() {
                        Ok(begin_parsed) => begin_parsed,
                        Err(_) => -1,
                    },
                    None => -1,
                };
                let end = match get_value(&date_range, "end") {
                    Some(end_returned) => match end_returned.parse() {
                        Ok(end_parsed) => end_parsed,
                        Err(_) => -1,
                    },
                    None => -1,
                };
                Ok(DateRange {
                    begin: begin,
                    end: end,
                })
            }
            Err(_) => Ok(DateRange { begin: -1, end: -1 }),
        }
    }
}

impl PolicyPublished {
    fn process_policy_published(feedback: &roxmltree::Node) -> std::io::Result<PolicyPublished> {
        match get_child(&feedback, "policy_published") {
            Ok(report_metadata) => {
                let domain = match get_value(&report_metadata, "domain") {
                    Some(domain_returned) => domain_returned,
                    None => String::from("unknown"),
                };
                let adkim = match get_value(&report_metadata, "adkim") {
                    Some(adkim_returned) => adkim_returned,
                    None => String::from("unknown"),
                };
                let aspf = match get_value(&report_metadata, "aspf") {
                    Some(aspf_returned) => aspf_returned,
                    None => String::from("unknown"),
                };
                let p = match get_value(&report_metadata, "p") {
                    Some(p_returned) => p_returned,
                    None => String::from("unknown"),
                };
                let sp = match get_value(&report_metadata, "sp") {
                    Some(sp_returned) => sp_returned,
                    None => String::from("unknown"),
                };
                let pct = match get_value(&report_metadata, "pct") {
                    Some(pct_returned) => match pct_returned.parse() {
                        Ok(pct_parsed) => pct_parsed,
                        Err(_) => -1,
                    },
                    None => -1,
                };
                Ok(PolicyPublished {
                    domain: domain,
                    adkim: adkim,
                    aspf: aspf,
                    p: p,
                    sp: sp,
                    pct: pct,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl Record {
    fn process_records(feedback: &roxmltree::Node) -> std::io::Result<Vec<Record>> {
        match get_children(&feedback, "record") {
            Ok(records_list) => {
                let mut records = Vec::new();
                for record in records_list {
                    let row;
                    let identifiers;
                    let auth_results;
                    match Row::process_row(&record) {
                        Ok(row_returned) => {
                            row = row_returned;
                        }
                        Err(e) => {
                            error!("Failed to process row: {}", e);
                            return Err(Error::new(ErrorKind::Other, "Bad XML"));
                        }
                    }
                    match Identifiers::process_identifiers(&record) {
                        Ok(identifiers_returned) => {
                            identifiers = identifiers_returned;
                        }
                        Err(e) => {
                            error!("Failed to process identifiers: {}", e);
                            return Err(Error::new(ErrorKind::Other, "Bad XML"));
                        }
                    }
                    match AuthResults::process_auth_results(&record) {
                        Ok(auth_results_returned) => {
                            auth_results = auth_results_returned;
                        }
                        Err(e) => {
                            error!("Failed to process auth_results: {}", e);
                            return Err(Error::new(ErrorKind::Other, "Bad XML"));
                        }
                    }
                    records.push(Record {
                        row: row,
                        identifiers: identifiers,
                        auth_results: auth_results,
                    });
                }
                Ok(records)
            }
            Err(e) => Err(e),
        }
    }
}

impl Row {
    fn process_row(record: &roxmltree::Node) -> std::io::Result<Row> {
        match get_child(&record, "row") {
            Ok(row) => {
                let source_ip = match get_value(&row, "source_ip") {
                    Some(source_ip_returned) => source_ip_returned,
                    None => String::from("unknown"),
                };
                let count = match get_value(&row, "count") {
                    Some(count_returned) => match count_returned.parse() {
                        Ok(count_parsed) => count_parsed,
                        Err(_) => -1,
                    },
                    None => -1,
                };
                let policy_evaluated;
                match PolicyEvaluated::process_policy_evaluated(&row) {
                    Ok(policy_evaluated_returned) => {
                        policy_evaluated = policy_evaluated_returned;
                    }
                    Err(e) => {
                        error!("Failed to process policy_evaluated: {}", e);
                        return Err(Error::new(ErrorKind::Other, "Bad XML"));
                    }
                };
                Ok(Row {
                    source_ip: source_ip,
                    count: count,
                    policy_evaluated: policy_evaluated,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl PolicyEvaluated {
    fn process_policy_evaluated(row: &roxmltree::Node) -> std::io::Result<PolicyEvaluated> {
        match get_child(&row, "policy_evaluated") {
            Ok(policy_evaluated) => {
                let disposition = match get_value(&policy_evaluated, "disposition") {
                    Some(disposition_returned) => disposition_returned,
                    None => String::from("unknown"),
                };
                let dkim = match get_value(&policy_evaluated, "dkim") {
                    Some(dkim_returned) => dkim_returned,
                    None => String::from("unknown"),
                };
                let spf = match get_value(&policy_evaluated, "spf") {
                    Some(spf_returned) => spf_returned,
                    None => String::from("unknown"),
                };
                Ok(PolicyEvaluated {
                    disposition: disposition,
                    dkim: dkim,
                    spf: spf,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl Identifiers {
    fn process_identifiers(record: &roxmltree::Node) -> std::io::Result<Identifiers> {
        match get_child(&record, "identifiers") {
            Ok(identifiers) => {
                let header_from = match get_value(&identifiers, "header_from") {
                    Some(header_from_returned) => header_from_returned,
                    None => String::from("unknown"),
                };
                Ok(Identifiers {
                    header_from: header_from,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl AuthResults {
    fn process_auth_results(record: &roxmltree::Node) -> std::io::Result<AuthResults> {
        match get_child(&record, "auth_results") {
            Ok(auth_results) => {
                let dkim;
                let spf;
                match DKIM::process_dkim(&auth_results) {
                    Ok(dkim_returned) => {
                        dkim = dkim_returned;
                    }
                    Err(e) => {
                        error!("Failed to process dkim: {}", e);
                        return Err(Error::new(ErrorKind::Other, "Bad XML"));
                    }
                }
                match SPF::process_spf(&auth_results) {
                    Ok(spf_returned) => {
                        spf = spf_returned;
                    }
                    Err(e) => {
                        error!("Failed to process spf: {}", e);
                        return Err(Error::new(ErrorKind::Other, "Bad XML"));
                    }
                }
                Ok(AuthResults {
                    dkim: dkim,
                    spf: spf,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl DKIM {
    fn process_dkim(auth_results: &roxmltree::Node) -> std::io::Result<DKIM> {
        match get_child(&auth_results, "dkim") {
            Ok(dkim) => {
                let domain = match get_value(&dkim, "domain") {
                    Some(domain_returned) => domain_returned,
                    None => String::from("unknown"),
                };
                let result = match get_value(&dkim, "result") {
                    Some(result_returned) => result_returned,
                    None => String::from("unknown"),
                };
                let selector = match get_value(&dkim, "selector") {
                    Some(selector_returned) => selector_returned,
                    None => String::from("unknown"),
                };
                Ok(DKIM {
                    domain: domain,
                    result: result,
                    selector: selector,
                })
            }
            Err(e) => {
                debug!("Failed to process feedback.record.auth_results.dkim: {}", e);
                Ok(DKIM {
                    domain: String::from("unknown"),
                    result: String::from("unknown"),
                    selector: String::from("unknown"),
                })
            }
        }
    }
}

impl SPF {
    fn process_spf(auth_results: &roxmltree::Node) -> std::io::Result<SPF> {
        match get_child(&auth_results, "spf") {
            Ok(spf) => {
                let domain = match get_value(&spf, "domain") {
                    Some(domain_returned) => domain_returned,
                    None => String::from("unknown"),
                };
                let result = match get_value(&spf, "result") {
                    Some(result_returned) => result_returned,
                    None => String::from("unknown"),
                };
                Ok(SPF {
                    domain: domain,
                    result: result,
                })
            }
            Err(e) => {
                debug!("Failed to process feedback.record.auth_results.spf: {}", e);
                Ok(SPF {
                    domain: String::from("unknown"),
                    result: String::from("unknown"),
                })
            }
        }
    }
}

fn get_children<'a>(
    node: &'a roxmltree::Node,
    name: &'a str,
) -> std::io::Result<Vec<roxmltree::Node<'a, 'a>>> {
    trace!("Listing children");
    let child_nodes = node.children().filter(|n| n.has_tag_name(name));
    let mut children = Vec::new();
    for child_node in child_nodes {
        debug!("found a child");
        children.push(child_node);
    }
    Ok(children)
}

fn get_child<'a>(
    node: &'a roxmltree::Node,
    name: &'a str,
) -> std::io::Result<roxmltree::Node<'a, 'a>> {
    trace!("Listing children");
    match node.children().find(|n| n.has_tag_name(name)) {
        Some(found_node_read) => {
            trace!("found child {:?}", name);
            let found_node = found_node_read;
            Ok(found_node)
        }
        None => {
            trace!("child {:?} not found", name);
            Err(Error::new(
                ErrorKind::Other,
                format!("{:?} not found", name),
            ))
        }
    }
}

fn get_value(node: &roxmltree::Node, name: &str) -> Option<String> {
    trace!("retrieving the value for element {:?}", name);
    match get_child(node, name) {
        Ok(found_element) => match found_element.text() {
            Some(found_text) => {
                trace!("found value {:?} for element {:?}", found_text, name);
                Some(String::from(found_text))
            }
            None => {
                trace!("found no value for element {:?}", name);
                None
            }
        },
        Err(_) => {
            trace!("found no value for element {:?}", name);
            None
        }
    }
}
