use crate::vault::model::Entry;

pub fn filter_entries(entries: &[Entry], query: &str) -> Vec<Entry> {
    if query.is_empty() {
        return entries.to_vec();
    }

    let query_lower = query.to_lowercase();

    entries
        .iter()
        .filter(|e| {
            e.title.to_lowercase().contains(&query_lower)
                || e.username.to_lowercase().contains(&query_lower)
                || e.url.to_lowercase().contains(&query_lower)
                || e.notes
                    .as_deref()
                    .map(|n| n.to_lowercase().contains(&query_lower))
                    .unwrap_or(false)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_entry(title: &str, username: &str, url: &str) -> Entry {
        Entry {
            id: 1,
            title: title.into(),
            username: username.into(),
            url: url.into(),
            notes: None,
            category_id: 0,
            favorite: false,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_empty_query_returns_all() {
        let entries = vec![make_entry("A", "", ""), make_entry("B", "", "")];
        assert_eq!(filter_entries(&entries, "").len(), 2);
    }

    #[test]
    fn test_filter_by_title() {
        let entries = vec![
            make_entry("GitHub", "user", ""),
            make_entry("Gmail", "user", ""),
        ];
        let result = filter_entries(&entries, "git");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "GitHub");
    }

    #[test]
    fn test_filter_case_insensitive() {
        let entries = vec![make_entry("GitHub", "", "")];
        assert_eq!(filter_entries(&entries, "GITHUB").len(), 1);
    }
}
