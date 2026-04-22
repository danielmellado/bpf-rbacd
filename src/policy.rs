//! Policy configuration for BPF RBAC

use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::protocol::Request;

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub roles: HashMap<String, Role>,
}

#[derive(Debug, Deserialize)]
pub struct Role {
    pub description: Option<String>,
    pub groups: Vec<String>,
    pub prog_types: Vec<String>,
    pub map_types: Vec<String>,
    #[serde(default)]
    pub attach_types: Vec<String>,
}

impl Policy {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let policy: Policy = serde_yaml::from_str(&contents)?;
        Ok(policy)
    }

    /// Get the role name for a user based on their groups
    /// Returns the most privileged role if user is in multiple groups
    pub fn get_role_for_groups(&self, user_groups: &[String]) -> Option<String> {
        let user_groups_set: HashSet<_> = user_groups.iter().collect();

        // Priority order: ebpf-admin > ebpf-net > ebpf
        let priority = ["ebpf-admin", "ebpf-net", "ebpf"];

        for role_name in priority {
            if let Some(role) = self.roles.get(role_name) {
                for group in &role.groups {
                    if user_groups_set.contains(group) {
                        return Some(role_name.to_string());
                    }
                }
            }
        }

        // Check any other roles
        for (role_name, role) in &self.roles {
            for group in &role.groups {
                if user_groups_set.contains(group) {
                    return Some(role_name.clone());
                }
            }
        }

        None
    }

    /// Check if a role is allowed to perform a request
    pub fn is_allowed(&self, role_name: &str, request: &Request) -> bool {
        let role = match self.roles.get(role_name) {
            Some(r) => r,
            None => return false,
        };

        match request {
            Request::LoadProgram { prog_type, .. } => self.is_prog_type_allowed(role, prog_type),
            Request::CreateMap { map_type, .. } => self.is_map_type_allowed(role, map_type),
            Request::Attach { attach_type, .. } => self.is_attach_type_allowed(role, attach_type),
        }
    }

    fn is_prog_type_allowed(&self, role: &Role, prog_type: &str) -> bool {
        role.prog_types.iter().any(|t| t == "any" || t == prog_type)
    }

    fn is_map_type_allowed(&self, role: &Role, map_type: &str) -> bool {
        role.map_types.iter().any(|t| t == "any" || t == map_type)
    }

    fn is_attach_type_allowed(&self, role: &Role, attach_type: &str) -> bool {
        if role.attach_types.is_empty() {
            // If no attach types specified, allow all that match prog_types
            return true;
        }
        role.attach_types
            .iter()
            .any(|t| t == "any" || t == attach_type)
    }
}

impl Default for Policy {
    fn default() -> Self {
        let mut roles = HashMap::new();

        roles.insert(
            "ebpf".to_string(),
            Role {
                description: Some("Tracing workloads".to_string()),
                groups: vec!["ebpf".to_string()],
                prog_types: vec![
                    "kprobe".to_string(),
                    "uprobe".to_string(),
                    "tracepoint".to_string(),
                    "perf_event".to_string(),
                    "raw_tracepoint".to_string(),
                ],
                map_types: vec![
                    "hash".to_string(),
                    "array".to_string(),
                    "perf_event_array".to_string(),
                    "ringbuf".to_string(),
                ],
                attach_types: vec![],
            },
        );

        roles.insert(
            "ebpf-net".to_string(),
            Role {
                description: Some("Networking workloads".to_string()),
                groups: vec!["ebpf-net".to_string()],
                prog_types: vec![
                    "xdp".to_string(),
                    "sched_cls".to_string(),
                    "sched_act".to_string(),
                    "socket_filter".to_string(),
                ],
                map_types: vec![
                    "hash".to_string(),
                    "array".to_string(),
                    "lru_hash".to_string(),
                    "devmap".to_string(),
                ],
                attach_types: vec![],
            },
        );

        roles.insert(
            "ebpf-admin".to_string(),
            Role {
                description: Some("Full BPF access".to_string()),
                groups: vec!["ebpf-admin".to_string()],
                prog_types: vec!["any".to_string()],
                map_types: vec!["any".to_string()],
                attach_types: vec!["any".to_string()],
            },
        );

        Policy { roles }
    }
}
