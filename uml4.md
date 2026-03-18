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
EventFactory ..> SecurityEvent : <<creates>>

class CorrelationEngine {
    +register_rule(rule)
    +correlate(events) List~SecurityEvent~
}

class CorrelationRule {
    <<abstract>>
    +evaluate(events)*
}
CorrelationRule <|.. SuspiciousParentRule
CorrelationRule <|.. LOLBASRule

class RiskEngine {
    <<StrategyContext>>
    -strategies : List~RiskStrategy~
    +evaluate(event) RiskScore
}

class RiskStrategy {
    <<abstract>>
    +calculate(event)* RiskScore
}
RiskStrategy <|.. BaselineRiskStrategy
RiskStrategy <|.. LOLBASRiskStrategy
RiskStrategy <|.. ProcessLineageRiskStrategy

class AlertManager {
    <<Subject>>
    +attach(observer)
    +notify(event)
}

class AlertObserver {
    <<abstract>>
    +notify(event)*
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
CorrelationRule ..> EventFactory : <<uses>>

classDiagram
direction TB

class ViewLayer { <<MVC View>> }
class ControllerLayer { <<MVC Controller>> }
class ModelLayer { <<MVC Model>> }

class DashboardPages { <<module>> }
class DashboardAPIClient { <<module>> }
class FastAPIApp { <<API>> }
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

DashboardPages ..> DashboardAPIClient : <<uses>>
DashboardAPIClient ..> FastAPIApp : <<REST API>>
AgentController ..> FastAPIApp : <<HTTP POST>>
FastAPIApp ..> EventProcessor : <<delegates>>
FastAPIApp ..> DatabaseManager : <<queries>>
