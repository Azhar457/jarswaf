use serde_json::Value;

pub struct GraphQLComplexity {
    pub max_depth: usize,
    pub node_count: usize,
}

pub fn analyze_graphql_complexity(query: &str) -> GraphQLComplexity {
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;
    let mut node_count: usize = 0;

    let mut in_arguments = false;
    let mut in_string = false;
    let mut in_comment = false;
    let mut current_word = String::new();

    let chars: Vec<char> = query.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if in_comment {
            if c == '\n' || c == '\r' {
                in_comment = false;
            }
            i += 1;
            continue;
        }
        if c == '#' && !in_string {
            in_comment = true;
            i += 1;
            continue;
        }

        if c == '"' {
            if i > 0 && chars[i - 1] == '\\' {
                // Escaped quote
            } else {
                in_string = !in_string;
            }
            i += 1;
            continue;
        }

        if in_string {
            i += 1;
            continue;
        }

        if c == '(' && !in_string {
            in_arguments = true;
            i += 1;
            continue;
        }
        if c == ')' && !in_string {
            in_arguments = false;
            i += 1;
            continue;
        }

        if in_arguments {
            i += 1;
            continue;
        }

        if c == '{' {
            current_depth += 1;
            if current_depth > max_depth {
                max_depth = current_depth;
            }
            if !current_word.is_empty() {
                if is_field_node(&current_word) {
                    node_count += 1;
                }
                current_word.clear();
            }
        } else if c == '}' {
            current_depth = current_depth.saturating_sub(1);
            if !current_word.is_empty() {
                if is_field_node(&current_word) {
                    node_count += 1;
                }
                current_word.clear();
            }
        } else if c.is_alphanumeric() || c == '_' {
            current_word.push(c);
        } else {
            if !current_word.is_empty() {
                if is_field_node(&current_word) {
                    node_count += 1;
                }
                current_word.clear();
            }
        }

        i += 1;
    }

    if !current_word.is_empty() && is_field_node(&current_word) {
        node_count += 1;
    }

    GraphQLComplexity {
        max_depth,
        node_count,
    }
}

fn is_field_node(word: &str) -> bool {
    let lowercase = word.to_lowercase();
    !matches!(
        lowercase.as_str(),
        "query" | "mutation" | "subscription" | "fragment" | "on" | "true" | "false" | "null"
    )
}

pub fn check_graphql_complexity_limits(path: &str, query_str: &str, body: &str) -> Option<String> {
    let mut graphql_query = None;

    // 1. Coba ekstrak dari POST JSON body
    if let Ok(json) = serde_json::from_str::<Value>(body) {
        if let Some(q) = json.get("query").and_then(|v| v.as_str()) {
            graphql_query = Some(q.to_string());
        }
    }

    // 2. Coba ekstrak dari query string params (?query=...)
    if graphql_query.is_none() {
        for part in query_str.split('&') {
            let kv: Vec<&str> = part.splitn(2, '=').collect();
            if kv.len() == 2 && kv[0] == "query" {
                if let Ok(decoded) = urlencoding::decode(kv[1]) {
                    graphql_query = Some(decoded.into_owned());
                }
            }
        }
    }

    // 3. Fallback jika path mengarah ke /graphql
    if graphql_query.is_none() && (path.ends_with("/graphql") || path.contains("/graphql/")) {
        let trimmed = body.trim();
        if trimmed.starts_with('{')
            || trimmed.starts_with("query")
            || trimmed.starts_with("mutation")
        {
            graphql_query = Some(trimmed.to_string());
        }
    }

    if let Some(ref q) = graphql_query {
        let complexity = analyze_graphql_complexity(q);

        let max_depth_limit = 5;
        let max_nodes_limit = 50;

        if complexity.max_depth > max_depth_limit {
            return Some(format!(
                "GraphQL query depth ({}) exceeds maximum limit ({})",
                complexity.max_depth, max_depth_limit
            ));
        }
        if complexity.node_count > max_nodes_limit {
            return Some(format!(
                "GraphQL node complexity ({}) exceeds maximum limit ({})",
                complexity.node_count, max_nodes_limit
            ));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_complexity_analysis() {
        let normal_query = "
            query GetUser {
                user(id: 1) {
                    name
                    email
                    profile {
                        avatar
                    }
                }
            }
        ";
        let normal_comp = analyze_graphql_complexity(normal_query);
        assert_eq!(normal_comp.max_depth, 3);
        assert_eq!(normal_comp.node_count, 6); // GetUser, user, name, email, profile, avatar

        // Test recursive/nested query DoS
        let nested_query = "
            {
                user {
                    friends {
                        user {
                            friends {
                                user {
                                    name
                                }
                            }
                        }
                    }
                }
            }
        ";
        let nested_comp = analyze_graphql_complexity(nested_query);
        assert_eq!(nested_comp.max_depth, 6);
    }

    #[test]
    fn test_graphql_limits() {
        // Deep query should be blocked
        let deep_query = "
            { a { b { c { d { e { f { name } } } } } } }
        ";
        let result = check_graphql_complexity_limits("/graphql", "", deep_query);
        assert!(result.is_some());
        assert!(result.unwrap().contains("query depth"));

        // Normal query should pass
        let normal_query = "
            { user { name } }
        ";
        let result_normal = check_graphql_complexity_limits("/graphql", "", normal_query);
        assert!(result_normal.is_none());
    }
}
