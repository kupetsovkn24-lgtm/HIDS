# UML-діаграми для курсової роботи (4 компактні діаграми)

## 1. Діаграма класів предметної області

> Події безпеки, оцінка ризику, кореляційні правила, пріоритети.

```mermaid
classDiagram
direction LR

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

class EventFactory {
  <<FactoryMethod>>
  +create_process_event(data) SecurityEvent
  +create_correlated_event(src, desc, mitre) SecurityEvent
}

SecurityEvent *-- RiskScore
SecurityEvent --> EventCategory

CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule
CorrelationRule <|.. FirstSeenRule
CorrelationEngine o-- CorrelationRule
CorrelationRule ..> EventFactory : створює кореляцію
EventFactory ..> SecurityEvent : створює подію
```

---

## 2. Діаграма патернів GoF

> Strategy — оцінка ризику; Observer — сповіщення; Factory Method — створення подій; Singleton — конфігурація.

```mermaid
classDiagram
direction LR

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

class EventFactory {
  <<FactoryMethod>>
  +create_process_event(data) SecurityEvent
  +create_correlated_event(src, desc, mitre) SecurityEvent
}

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
```

---

## 3. Архітектурний поділ за MVC

> View — Dashboard (Streamlit); Controller — FastAPI, AgentController, EventProcessor; Model — доменні дані та база.

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
AgentController ..> FastAPIApp : events + heartbeat
FastAPIApp ..> EventProcessor
FastAPIApp ..> DatabaseManager
SecurityEvent *-- RiskScore
```

---

## 4. Пайплайн обробки подій

> Шлях події: Agent → Factory → Server → CorrelationEngine → RiskEngine → AlertManager → Database.

```mermaid
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

AgentController ..> EventFactory : створює події
EventFactory ..> SecurityEvent : create
AgentController ..> FastAPIApp : POST /api/events
FastAPIApp ..> EventProcessor
EventProcessor --> CorrelationEngine
EventProcessor --> RiskEngine
EventProcessor --> AlertManager
EventProcessor --> DatabaseManager

class SecurityEvent
class RiskScore
SecurityEvent *-- RiskScore
```
