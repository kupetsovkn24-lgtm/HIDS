# UML-діаграми класів для курсової роботи

---

```mermaid
classDiagram
direction LR

class SecurityEvent {
  +event_id : str
  +category : EventCategory
  +description : str
  +risk_score : RiskScore
}

class RiskScore {
  +impact : float
  +confidence : float
  +composite : float
  +tier : str
}

class EventCategory {
  <<enumeration>>
  PROCESS
  NETWORK
  FILE
  CORRELATED
}

SecurityEvent *-- RiskScore
SecurityEvent --> EventCategory

class CorrelationRule {
  <<abstract>>
  +evaluate(events)
  +rule_name : str
}
class SuspiciousParentRule
class LOLBASRule
class FirstSeenRule

CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule
CorrelationRule <|.. FirstSeenRule

class RiskStrategy {
  <<Strategy>>
  <<abstract>>
  +calculate(event) RiskScore
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

class AlertManager {
  <<Subject>>
  +attach(observer)
  +detach(observer)
  +process_event(event)
}

class AlertObserver {
  <<abstract>>
  +notify(event)
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

class EventProcessor {
  +process_batch(events)
}

EventProcessor --> CorrelationRule
EventProcessor --> RiskStrategy
EventProcessor --> AlertManager
EventProcessor ..> SecurityEvent
```

*Рис. 2.1. UML-діаграма класів предметної області HIDS.*
*Джерело: авторські напрацювання.*

---

```mermaid
classDiagram
direction TB

class ViewLayer { <<MVC View>> }
class ControllerLayer { <<MVC Controller>> }
class ModelLayer { <<MVC Model>> }

class DashboardPages { <<module>> }
class DashboardAPIClient { <<module>> }
class FastAPIApp
class AgentController
class EventProcessor
class SecurityEvent
class RiskScore
class DatabaseManager
class AgentConfig { <<Singleton>> }
class ServerConfig { <<Singleton>> }

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

*Рис. 2.2. Архітектурна декомпозиція системи за патерном MVC.*
*Джерело: авторські напрацювання.*
