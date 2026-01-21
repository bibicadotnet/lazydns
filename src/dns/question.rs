//! DNS question section implementation
//!
//! Represents the question section of a DNS message, containing
//! the domain name being queried and the query type and class.

use super::types::{RecordClass, RecordType};
use std::fmt;
use std::sync::Arc;

/// DNS question
///
/// Represents a single question in the question section of a DNS message.
/// A question specifies what information is being requested from the DNS server.
///
/// # Example
///
/// ```
/// use lazydns::dns::{Question, RecordType, RecordClass};
///
/// let question = Question::new(
///     "example.com".to_string(),
///     RecordType::A,
///     RecordClass::IN,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The domain name being queried (shared via Arc for efficient cloning)
    qname: Arc<str>,
    /// The type of record being requested
    qtype: RecordType,
    /// The class of record being requested
    qclass: RecordClass,
}

impl Question {
    /// Create a new DNS question
    ///
    /// # Arguments
    ///
    /// * `qname` - The domain name to query (accepts String, &str, or Arc<str>)
    /// * `qtype` - The type of DNS record requested
    /// * `qclass` - The class of DNS record requested
    ///
    /// # Example
    ///
    /// ```
    /// use lazydns::dns::{Question, RecordType, RecordClass};
    ///
    /// let question = Question::new(
    ///     "www.example.com",
    ///     RecordType::A,
    ///     RecordClass::IN,
    /// );
    /// ```
    pub fn new(qname: impl AsRef<str>, qtype: RecordType, qclass: RecordClass) -> Self {
        Self {
            qname: Arc::from(qname.as_ref()),
            qtype,
            qclass,
        }
    }

    /// Create a new DNS question with a pre-allocated Arc<str>
    /// 
    /// This is more efficient when you already have an Arc<str> as it avoids
    /// an additional allocation.
    pub fn with_arc(qname: Arc<str>, qtype: RecordType, qclass: RecordClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }

    /// Get the domain name being queried
    pub fn qname(&self) -> &str {
        &self.qname
    }

    /// Get the query type
    pub fn qtype(&self) -> RecordType {
        self.qtype
    }

    /// Get the query class
    pub fn qclass(&self) -> RecordClass {
        self.qclass
    }

    /// Set the domain name
    pub fn set_qname(&mut self, qname: impl AsRef<str>) {
        self.qname = Arc::from(qname.as_ref());
    }

    /// Set the domain name with a pre-allocated Arc<str>
    pub fn set_qname_arc(&mut self, qname: Arc<str>) {
        self.qname = qname;
    }

    /// Get a clone of the Arc<str> for the domain name
    /// 
    /// This is useful for sharing the domain name without string allocation.
    pub fn qname_arc(&self) -> Arc<str> {
        Arc::clone(&self.qname)
    }

    /// Set the query type
    pub fn set_qtype(&mut self, qtype: RecordType) {
        self.qtype = qtype;
    }

    /// Set the query class
    pub fn set_qclass(&mut self, qclass: RecordClass) {
        self.qclass = qclass;
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\t{}\t{}", self.qname, self.qclass, self.qtype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_question_creation() {
        let question = Question::new("example.com".to_string(), RecordType::A, RecordClass::IN);

        assert_eq!(question.qname(), "example.com");
        assert_eq!(question.qtype(), RecordType::A);
        assert_eq!(question.qclass(), RecordClass::IN);
    }

    #[test]
    fn test_question_setters() {
        let mut question = Question::new("example.com".to_string(), RecordType::A, RecordClass::IN);

        question.set_qname("test.com".to_string());
        question.set_qtype(RecordType::AAAA);
        question.set_qclass(RecordClass::CH);

        assert_eq!(question.qname(), "test.com");
        assert_eq!(question.qtype(), RecordType::AAAA);
        assert_eq!(question.qclass(), RecordClass::CH);
    }

    #[test]
    fn test_question_display() {
        let question = Question::new("example.com".to_string(), RecordType::A, RecordClass::IN);

        let display = format!("{}", question);
        assert!(display.contains("example.com"));
        assert!(display.contains("IN"));
        assert!(display.contains("A"));
    }

    #[test]
    fn test_question_equality() {
        let q1 = Question::new("example.com".to_string(), RecordType::A, RecordClass::IN);
        let q2 = Question::new("example.com".to_string(), RecordType::A, RecordClass::IN);
        let q3 = Question::new("other.com".to_string(), RecordType::A, RecordClass::IN);

        assert_eq!(q1, q2);
        assert_ne!(q1, q3);
    }
}
