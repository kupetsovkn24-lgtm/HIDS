# Рис. 2.1 — UML-діаграма класів предметної області HIDS

```mermaid
%%{init: {"theme":"base","flowchart":{"nodeSpacing":18,"rankSpacing":18},"class":{"hideEmptyMembersBox":true}}}%%
classDiagram
direction LR

class SecurityEvent {
  +event_id: str
  +timestamp: datetime
  +source_sensor: str
  +category: EventCategory
  +description: str
  +details: Dict
  +mitre_technique: str
  +risk_score: RiskScore
}

class RiskScore {
  +impact: float
  +confidence: float
  +urgency: float
  +composite: float
  +tier: str
}

class EventCategory {
  <<enumeration>>
  PROCESS
  NETWORK
  REGISTRY
  FILE
  TASK
  CORRELATED
}

class EventFactory {
  <<FactoryMethod>>
  +create_process_event(data) SecurityEvent
  +create_correlated_event(source, desc, mitre) SecurityEvent
}

class AgentConfig {
  <<Singleton>>
  +server_url: str
  +api_key: str
  +agent_id: str
}

class ServerConfig {
  <<Singleton>>
  +api_keys: List~str~
  +db_path: str
  +alert_threshold_tier: str
}

class CorrelationEngine {
  +register_rule(rule) void
  +correlate(events) List~SecurityEvent~
}

class CorrelationRule {
  <<abstract>>
  +evaluate(events) List~SecurityEvent~
  +rule_name: str
  +mitre_technique: str
}

class SuspiciousParentRule
class LOLBASRule
class FirstSeenRule

class RiskEngine {
  <<StrategyContext>>
  +register_strategy(strategy) void
  +evaluate(event) RiskScore
}

class RiskStrategy {
  <<Strategy>>
  +calculate(event) RiskScore
  +name: str
}

class BaselineRiskStrategy
class LOLBASRiskStrategy
class ProcessLineageRiskStrategy
class NetworkAnomalyRiskStrategy
class TemporalRiskStrategy

class AlertManager {
  <<Subject>>
  +attach(observer) void
  +detach(observer) void
  +process_event(event) int
}

class AlertObserver {
  <<Observer>>
  +notify(event) void
}

class LogAlertObserver
class DashboardAlertObserver
class UptimeKumaObserver
class TelegramAlertObserver

class DatabaseManager {
  +add_event(event) void
  +add_alert(event) void
  +get_events(days, tier) List
  +get_alerts(acknowledged) List
}

class EventProcessor {
  +process_batch(events, agent_id) ProcessingResult
}

SecurityEvent *-- RiskScore
SecurityEvent --> EventCategory
EventFactory ..> SecurityEvent : creates
DatabaseManager ..> SecurityEvent : persists

CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule
CorrelationRule <|.. FirstSeenRule
CorrelationEngine o-- CorrelationRule
CorrelationRule ..> EventFactory

RiskStrategy <|.. BaselineRiskStrategy
RiskStrategy <|.. LOLBASRiskStrategy
RiskStrategy <|.. ProcessLineageRiskStrategy
RiskStrategy <|.. NetworkAnomalyRiskStrategy
RiskStrategy <|.. TemporalRiskStrategy
RiskEngine o-- RiskStrategy

AlertObserver <|.. LogAlertObserver
AlertObserver <|.. DashboardAlertObserver
AlertObserver <|.. UptimeKumaObserver
AlertObserver <|.. TelegramAlertObserver
AlertManager o-- AlertObserver

EventProcessor --> CorrelationEngine
EventProcessor --> RiskEngine
EventProcessor --> AlertManager
EventProcessor --> DatabaseManager
DashboardAlertObserver ..> DatabaseManager : stores
AgentConfig ..> EventFactory : agent-side config
ServerConfig ..> AlertManager : threshold config
```

---

# Рис. 2.2 — Архітектурний поділ системи за MVC

```mermaid
%%{init: {"theme":"base","flowchart":{"nodeSpacing":18,"rankSpacing":18},"class":{"hideEmptyMembersBox":true}}}%%
classDiagram
direction TB

class ViewLayer { <<MVC Layer>> }
class ControllerLayer { <<MVC Layer>> }
class ModelLayer { <<MVC Layer>> }

class DashboardPages {
  +overview_page()
  +alerts_page()
  +events_page()
  +agents_page()
  +whitelist_page()
  +system_page()
}

class DashboardAPIClient {
  +get_stats(days) Dict
  +get_events(days, tier, category) List
  +get_alerts(limit, acknowledged) List
  +get_agents() List
  +get_system_status() Dict
}

class FastAPIApp {
  +receive_events() BatchResponse
  +receive_heartbeat() Dict
  +get_events() List
  +get_alerts() List
  +get_stats() StatsResponse
  +get_agents() List
}

class AgentController {
  +run_scan_cycle() List~SecurityEvent~
  +send_results(events) bool
  +send_heartbeat() bool
}

class EventProcessor {
  +process_batch(events, agent_id) ProcessingResult
}

class SecurityEvent
class RiskScore
class DatabaseManager
class AgentConfig
class ServerConfig

ViewLayer .. DashboardPages
ViewLayer .. DashboardAPIClient

ControllerLayer .. FastAPIApp
ControllerLayer .. AgentController
ControllerLayer .. EventProcessor

ModelLayer .. SecurityEvent
ModelLayer .. RiskScore
ModelLayer .. DatabaseManager
ModelLayer .. AgentConfig
ModelLayer .. ServerConfig

DashboardPages ..> DashboardAPIClient : uses
DashboardAPIClient ..> FastAPIApp : REST API
AgentController ..> FastAPIApp : events + heartbeat
FastAPIApp ..> EventProcessor
FastAPIApp ..> DatabaseManager
EventProcessor ..> SecurityEvent
SecurityEvent *-- RiskScore
DatabaseManager ..> SecurityEvent : stores
```
