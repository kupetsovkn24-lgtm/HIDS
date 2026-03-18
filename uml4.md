# UML-діаграми класів для курсової роботи

---

```mermaid
classDiagram
direction TB

class ViewLayer {
  <<MVC View>>
}
class ControllerLayer {
  <<MVC Controller>>
}
class ModelLayer {
  <<MVC Model>>
}

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
AgentController ..> FastAPIApp : HTTP
FastAPIApp ..> EventProcessor
FastAPIApp ..> DatabaseManager
SecurityEvent *-- RiskScore
```

*Рис. 2.1. Архітектурна декомпозиція системи за патерном MVC.*
*Джерело: авторські напрацювання.*

---

```mermaid
classDiagram
direction LR

%% ── Моделі даних ──────────────────────────────────

class SecurityEvent {
  +event_id : str
  +timestamp : datetime
  +category : EventCategory
  +description : str
  +mitre_technique : str
  +risk_score : RiskScore
}

class RiskScore {
  +impact : float
  +confidence : float
  +urgency : float
  +composite : float
  +tier : str
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

SecurityEvent *-- RiskScore
SecurityEvent --> EventCategory

%% ── Factory Method ────────────────────────────────

class EventFactory {
  <<FactoryMethod>>
  +create_process_event(data) SecurityEvent
  +create_network_event(data) SecurityEvent
  +create_correlated_event(src, desc, mitre) SecurityEvent
}

EventFactory ..> SecurityEvent : creates

%% ── Сенсори (OCP: нові сенсори без зміни контролера) ──

class BaseSensor {
  <<abstract>>
  +scan()* List~Dict~
  +sensor_name : str
}

class ProcessSensor
class NetworkSensor
class RegistrySensor
class FileSensor
class TaskSensor

BaseSensor <|.. ProcessSensor
BaseSensor <|.. NetworkSensor
BaseSensor <|.. RegistrySensor
BaseSensor <|.. FileSensor
BaseSensor <|.. TaskSensor

AgentController o-- BaseSensor
AgentController ..> EventFactory : creates events

class AgentController {
  +run_scan_cycle() List~SecurityEvent~
  +send_results(events) bool
}

%% ── Кореляційне ядро ──────────────────────────────

class CorrelationEngine {
  +register_rule(rule) void
  +correlate(events) List~SecurityEvent~
}

class CorrelationRule {
  <<abstract>>
  +evaluate(events)* List~SecurityEvent~
  +rule_name : str
  +mitre_technique : str
}

class SuspiciousParentRule
class LOLBASRule
class FirstSeenRule

CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule
CorrelationRule <|.. FirstSeenRule
CorrelationEngine o-- CorrelationRule
CorrelationRule ..> EventFactory : creates

%% ── Strategy: оцінка ризику ───────────────────────

class RiskEngine {
  <<StrategyContext>>
  +register_strategy(s) void
  +evaluate(event) RiskScore
}

class RiskStrategy {
  <<Strategy>>
  <<abstract>>
  +calculate(event)* RiskScore
  +name : str
}

class BaselineRiskStrategy
class LOLBASRiskStrategy
class ProcessLineageRiskStrategy
class NetworkAnomalyRiskStrategy
class TemporalRiskStrategy

RiskStrategy <|.. BaselineRiskStrategy
RiskStrategy <|.. LOLBASRiskStrategy
RiskStrategy <|.. ProcessLineageRiskStrategy
RiskStrategy <|.. NetworkAnomalyRiskStrategy
RiskStrategy <|.. TemporalRiskStrategy
RiskEngine o-- RiskStrategy

%% ── Observer: сповіщення ──────────────────────────

class AlertManager {
  <<Subject>>
  +attach(observer) void
  +detach(observer) void
  +process_event(event) int
}

class AlertObserver {
  <<Observer>>
  <<abstract>>
  +notify(event)* void
  +observer_name : str
}

class LogAlertObserver
class DashboardAlertObserver
class UptimeKumaObserver
class TelegramAlertObserver

AlertObserver <|.. LogAlertObserver
AlertObserver <|.. DashboardAlertObserver
AlertObserver <|.. UptimeKumaObserver
AlertObserver <|.. TelegramAlertObserver
AlertManager o-- AlertObserver

%% ── Оркестратор + сховище ─────────────────────────

class EventProcessor {
  +process_batch(events, agent_id)
}

EventProcessor --> CorrelationEngine
EventProcessor --> RiskEngine
EventProcessor --> AlertManager
EventProcessor --> DatabaseManager

class DatabaseManager {
  +add_event(event) void
  +add_alert(event) void
  +get_events(days, tier) List
  +get_alerts(acknowledged) List
}

DashboardAlertObserver ..> DatabaseManager : stores

%% ── Singleton: конфігурація ───────────────────────

class AgentConfig {
  <<Singleton>>
  +server_url : str
  +api_key : str
  +agent_id : str
}

class ServerConfig {
  <<Singleton>>
  +api_keys : List~str~
  +db_path : str
  +alert_threshold_tier : str
}

AgentConfig ..> EventFactory : config
ServerConfig ..> AlertManager : threshold
```

*Рис. 2.2. UML-діаграма класів підсистеми аналізу та патернів GoF.*
*Джерело: авторські напрацювання.*
