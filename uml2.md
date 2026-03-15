```mermaid
classDiagram
direction LR

namespace "View Layer (MVC)" {
    class DashboardAPIClient {
        <<module>>
        +get_stats(days: int) Dict
        +get_events(days: int, tier: str, category: str) List~Dict~
        +get_alerts(limit: int, acknowledged: bool) List~Dict~
        +get_agents() List~Dict~
        +approve_whitelist(rule_type: str, rule_value: str) bool
        +revoke_whitelist(entry_id: int) bool
    }

    class DashboardPages {
        <<module>>
        +overview_page() void
        +events_page() void
        +alerts_page() void
        +agents_page() void
        +whitelist_page() void
    }
}

namespace "Controller Layer (MVC)" {
    class AgentController {
        -_config: AgentConfig
        -_baseline: BaselineManager
        -_policy_sync: PolicySyncClient
        -_sensors: List~BaseSensor~
        +run_scan_cycle() List~SecurityEvent~
        +send_results(events: List~SecurityEvent~) bool
        +send_heartbeat() bool
        +sync_policy(force: bool) bool
    }

    class BaseSensor {
        <<abstract>>
        -_baseline: BaselineManager
        +sensor_name: str
        +scan() List~Dict~
    }

    class ProcessSensor { +scan() List~Dict~ }
    class NetworkSensor { +scan() List~Dict~ }
    class RegistrySensor { +scan() List~Dict~ }
    class FileSensor { +scan() List~Dict~ }
    class TaskSensor { +scan() List~Dict~ }

    class EventSender {
        -_server_url: str
        -_api_key: str
        -_headers: Dict
        +send_events(events: List~Dict~) bool
        +send_heartbeat(sensors_active: List~str~, uptime: float) bool
    }

    class EventFactory {
        <<Factory>>
        +set_context(hostname: str, agent_version: str, agent_id: str) void
        +create_process_event(data: Dict) SecurityEvent
        +create_network_event(data: Dict) SecurityEvent
        +create_registry_event(data: Dict) SecurityEvent
        +create_file_event(data: Dict) SecurityEvent
        +create_task_event(data: Dict) SecurityEvent
        +create_correlated_event(source: List~SecurityEvent~, description: str, mitre: str) SecurityEvent
    }

    class PolicySyncClient {
        -_cache: PolicyCache
        -_interval: int
        +maybe_sync(force: bool) bool
        +cache: PolicyCache
    }

    class EventProcessor {
        -_correlation: CorrelationEngine
        -_risk: RiskEngine
        -_alerts: AlertManager
        -_db: DatabaseManager
        +process_batch(events: List~SecurityEvent~, agent_id: str) ProcessingResult
    }

    class CorrelationEngine {
        -_rules: List~CorrelationRule~
        +register_rule(rule: CorrelationRule) void
        +correlate(events: List~SecurityEvent~) List~SecurityEvent~
    }

    class CorrelationRule {
        <<interface>>
        +evaluate(events: List~SecurityEvent~) List~SecurityEvent~
        +rule_name: str
        +mitre_technique: str
    }

    class SuspiciousParentRule
    class LOLBASRule
    class FirstSeenRule

    class RiskEngine {
        -_strategies: List~RiskStrategy~
        +register_strategy(strategy: RiskStrategy) void
        +evaluate(event: SecurityEvent) RiskScore
    }

    class RiskStrategy {
        <<interface>>
        +calculate(event: SecurityEvent) RiskScore
        +name: str
    }

    class BaselineRiskStrategy
    class LOLBASRiskStrategy
    class ProcessLineageRiskStrategy
    class NetworkAnomalyRiskStrategy
    class TemporalRiskStrategy

    class AlertManager {
        -_observers: List~AlertObserver~
        -_threshold_tier: str
        +attach(observer: AlertObserver) void
        +detach(observer: AlertObserver) void
        +process_event(event: SecurityEvent) int
    }

    class AlertObserver {
        <<interface>>
        +notify(event: SecurityEvent) void
        +observer_name: str
    }

    class LogAlertObserver
    class DashboardAlertObserver
    class UptimeKumaObserver

    class FastAPIApp {
        <<module>>
        +receive_events() BatchResponse
        +receive_heartbeat() Dict
        +get_events() List~EventResponse~
        +get_stats() StatsResponse
        +get_alerts() List~AlertResponse~
    }
}

namespace "Model Layer (MVC)" {
    class AgentConfig {
        <<Singleton>>
        -_instance: AgentConfig
        +server_url: str
        +api_key: str
        +agent_id: str
        +sensor_names: List~str~
    }

    class ServerConfig {
        <<Singleton>>
        -_instance: ServerConfig
        +api_keys: List~str~
        +db_path: str
        +alert_threshold_tier: str
        +uptime_kuma_push_url: str
    }

    class BaselineManager {
        -_db_path: str
        -_conn: sqlite3.Connection
        +get_executable_status(sha256: str, path: str) str
        +set_executable_status(sha256: str, status: str, path: str) bool
        +close() void
    }

    class SecurityEvent {
        +event_id: str
        +timestamp: datetime
        +source_sensor: str
        +category: EventCategory
        +description: str
        +details: Dict
        +mitre_technique: str
        +risk_score: RiskScore
        +to_dict() Dict
        +from_dict(data: Dict) SecurityEvent
    }

    class RiskScore {
        +impact: float
        +confidence: float
        +urgency: float
        +composite: float
        +tier: str
        +to_dict() Dict
    }

    class ProcessingResult {
        +total_received: int
        +correlated_generated: int
        +suppressed_by_policy: int
        +alerts_fired: int
        +highest_tier: str
        +events: List~SecurityEvent~
    }

    class DatabaseManager {
        -_db_path: str
        -_conn: sqlite3.Connection
        +add_event(event: SecurityEvent) void
        +add_alert(event: SecurityEvent) void
        +match_whitelist(event: SecurityEvent, agent_id: str) Dict
        +get_events(days: int, tier: str, category: str, hostname: str) List~Dict~
        +get_alerts(acknowledged: bool) List~Dict~
        +get_stats(days: int) Dict
    }

    class PolicyRule {
        +id: int
        +revision: int
        +rule_type: str
        +rule_value: str
        +normalized_value: str
    }

    class PolicyCache {
        -_cache_path: str
        -_revision: int
        -_rules: List~PolicyRule~
        +update(revision: int, rules: List~Dict~) bool
        +match_event(event: SecurityEvent) PolicyRule
        +annotate_events(events: List~SecurityEvent~) int
    }
}

DashboardPages ..> DashboardAPIClient : uses
DashboardAPIClient ..> FastAPIApp : REST API

BaseSensor <|-- ProcessSensor
BaseSensor <|-- NetworkSensor
BaseSensor <|-- RegistrySensor
BaseSensor <|-- FileSensor
BaseSensor <|-- TaskSensor

CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule
CorrelationRule <|.. FirstSeenRule

RiskStrategy <|.. BaselineRiskStrategy
RiskStrategy <|.. LOLBASRiskStrategy
RiskStrategy <|.. ProcessLineageRiskStrategy
RiskStrategy <|.. NetworkAnomalyRiskStrategy
RiskStrategy <|.. TemporalRiskStrategy

AlertObserver <|.. LogAlertObserver
AlertObserver <|.. DashboardAlertObserver
AlertObserver <|.. UptimeKumaObserver

AgentController *-- BaselineManager
AgentController *-- PolicySyncClient
AgentController o-- BaseSensor
AgentController ..> EventFactory
AgentController ..> EventSender
EventSender ..> AgentConfig
PolicySyncClient *-- PolicyCache
PolicyCache *-- PolicyRule

FastAPIApp ..> EventProcessor
FastAPIApp ..> DatabaseManager
FastAPIApp ..> ServerConfig
FastAPIApp ..> AgentConfig

EventProcessor *-- CorrelationEngine
EventProcessor *-- RiskEngine
EventProcessor *-- AlertManager
EventProcessor *-- DatabaseManager

CorrelationEngine o-- CorrelationRule
CorrelationRule ..> EventFactory : creates correlated event
RiskEngine o-- RiskStrategy
AlertManager o-- AlertObserver
DashboardAlertObserver --> DatabaseManager : stores alerts

EventFactory ..> SecurityEvent : creates
SecurityEvent *-- RiskScore
ProcessingResult o-- SecurityEvent
DatabaseManager ..> SecurityEvent : persists

note for AgentConfig "GoF Singleton: one shared configuration instance on agent side."
note for EventFactory "GoF Factory Method: typed create_* methods instantiate SecurityEvent variants."
note for RiskEngine "GoF Strategy: runtime-pluggable RiskStrategy family for scoring."
note for AlertManager "GoF Observer: subject notifies attached alert observers on threshold match."
```
