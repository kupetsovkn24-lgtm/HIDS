# Рис. 2.1 — UML-діаграма класів предметної області HIDS

```mermaid
classDiagram
direction LR

class EventFactory {
    <<FactoryMethod>>
    +create_process_event(data) SecurityEvent
    +create_correlated_event(src, desc, mitre) SecurityEvent
}

class SecurityEvent {
    +event_id : str
    +category : EventCategory
    +risk_score : RiskScore
}

class RiskScore {
    +impact : float
    +confidence : float
    +urgency : float
    +composite : float
    +tier : str
}

SecurityEvent *-- RiskScore
EventFactory ..> SecurityEvent : creates

class CorrelationEngine {
    +register_rule(rule)
    +correlate(events) List~SecurityEvent~
}

class CorrelationRule {
    <<abstract>>
    +evaluate(events)
}
CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule

class RiskEngine {
    <<StrategyContext>>
    -strategies : List~RiskStrategy~
    +evaluate(event) RiskScore
}

class RiskStrategy {
    <<Strategy>>
    <<abstract>>
    +calculate(event) RiskScore
}
RiskStrategy <|.. BaselineRiskStrategy
RiskStrategy <|.. LOLBASRiskStrategy
RiskStrategy <|.. ProcessLineageRiskStrategy

class AlertManager {
    <<Subject>>
    +attach(observer)
    +process_event(event)
}

class AlertObserver {
    <<Observer>>
    <<abstract>>
    +notify(event)
}
AlertObserver <|.. TelegramAlertObserver
AlertObserver <|.. DashboardAlertObserver

class EventProcessor {
    +process_batch(events)
}

EventProcessor --> CorrelationEngine
EventProcessor --> RiskEngine
EventProcessor --> AlertManager
CorrelationEngine o-- CorrelationRule
RiskEngine o-- RiskStrategy
AlertManager o-- AlertObserver
CorrelationRule ..> EventFactory : uses
```

---

# Рис. 2.2 — Архітектурний поділ системи за MVC

```mermaid
classDiagram
direction TB

class ViewLayer { <<MVCView>> }
class ControllerLayer { <<MVCController>> }
class ModelLayer { <<MVCModel>> }

class DashboardPages { <<module>> }
class DashboardAPIClient { <<module>> }
class FastAPIApp { <<api>> }
class AgentController { <<service>> }
class EventProcessor { <<logic>> }

class SecurityEvent { <<entity>> }
class DatabaseManager { <<repository>> }
class ServerConfig { <<Singleton>> }
class AgentConfig { <<Singleton>> }

ViewLayer .. DashboardPages
ViewLayer .. DashboardAPIClient

ControllerLayer .. FastAPIApp
ControllerLayer .. AgentController
ControllerLayer .. EventProcessor

ModelLayer .. SecurityEvent
ModelLayer .. DatabaseManager
ModelLayer .. ServerConfig
ModelLayer .. AgentConfig

DashboardPages ..> DashboardAPIClient : uses
DashboardAPIClient ..> FastAPIApp : REST API
AgentController ..> FastAPIApp : HTTP POST
FastAPIApp ..> EventProcessor : delegates
FastAPIApp ..> DatabaseManager : queries
```
