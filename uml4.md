# UML для курсової (розбиття на 4 компактні діаграми)

## 1) Предметна область HIDS: події, аномалії, правила, пріоритети

```mermaid
%%{init: {"theme":"base","flowchart":{"nodeSpacing":16,"rankSpacing":16},"class":{"hideEmptyMembersBox":true}}}%%
classDiagram
direction LR

class SecurityEvent {
  +event_id: str
  +timestamp: datetime
  +category: EventCategory
  +description: str
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

class EventFactory {
  <<FactoryMethod>>
  +create_process_event(data) SecurityEvent
  +create_correlated_event(source, desc, mitre) SecurityEvent
}

class EventProcessor {
  +process_batch(events, agent_id) ProcessingResult
}

SecurityEvent *-- RiskScore
SecurityEvent --> EventCategory

CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule
CorrelationRule <|.. FirstSeenRule
CorrelationEngine o-- CorrelationRule
CorrelationRule ..> EventFactory : create correlated anomaly
EventFactory ..> SecurityEvent : create event

EventProcessor --> CorrelationEngine
EventProcessor ..> SecurityEvent : processes
```

## 2) Патерни GoF у проєкті

```mermaid
%%{init: {"theme":"base","flowchart":{"nodeSpacing":16,"rankSpacing":16},"class":{"hideEmptyMembersBox":true}}}%%
classDiagram
direction LR

class RiskEngine {
  <<StrategyContext>>
  +register_strategy(strategy) void
  +evaluate(event) RiskScore
}

class RiskStrategy {
  <<Strategy>>
  <<abstract>>
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
  <<abstract>>
  +notify(event) void
  +observer_name: str
}

class LogAlertObserver
class DashboardAlertObserver
class UptimeKumaObserver
class TelegramAlertObserver

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
```

## 3) Архітектурний поділ за MVC

```mermaid
%%{init: {"theme":"base","flowchart":{"nodeSpacing":16,"rankSpacing":16},"class":{"hideEmptyMembersBox":true}}}%%
classDiagram
direction TB

class ViewLayer { <<MVC Layer>> }
class ControllerLayer { <<MVC Layer>> }
class ModelLayer { <<MVC Layer>> }

class DashboardPages {
  <<module>>
  +overview_page()
  +alerts_page()
  +events_page()
  +agents_page()
  +whitelist_page()
  +system_page()
}

class DashboardAPIClient {
  <<module>>
  +get_events(...)
  +get_alerts(...)
  +get_stats(...)
  +get_agents()
  +get_system_status()
}

class FastAPIApp {
  +receive_events()
  +receive_heartbeat()
  +get_events()
  +get_alerts()
  +get_stats()
  +get_agents()
}

class AgentController {
  +run_scan_cycle()
  +send_results(events)
  +send_heartbeat()
}

class EventProcessor {
  +process_batch(events, agent_id)
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
SecurityEvent *-- RiskScore
```

## 4) Міні-діаграма пайплайна обробки

```mermaid
%%{init: {"theme":"base","flowchart":{"nodeSpacing":14,"rankSpacing":14},"class":{"hideEmptyMembersBox":true}}}%%
classDiagram
direction LR

class AgentController {
  +run_scan_cycle()
  +send_results(events)
}

class EventFactory {
  <<FactoryMethod>>
  +create_*_event(data)
}

class FastAPIApp {
  +receive_events()
}

class EventProcessor {
  +process_batch(events, agent_id)
}

class CorrelationEngine
class RiskEngine { <<StrategyContext>> }
class AlertManager { <<Subject>> }
class DatabaseManager
class SecurityEvent
class RiskScore

AgentController ..> EventFactory : builds events
EventFactory ..> SecurityEvent : create
AgentController ..> FastAPIApp : POST /api/events
FastAPIApp ..> EventProcessor
EventProcessor --> CorrelationEngine
EventProcessor --> RiskEngine
EventProcessor --> AlertManager
EventProcessor --> DatabaseManager
SecurityEvent *-- RiskScore
```
