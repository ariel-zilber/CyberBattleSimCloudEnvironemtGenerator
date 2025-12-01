from enum import Enum

class ClusterSize(Enum):
    """Cluster size categories with node ranges"""
    TINY = (1, 3)           # Dev/testing
    SMALL = (3, 10)         # Small production/startup
    MEDIUM = (10, 50)       # Growing company
    LARGE = (50, 200)       # Enterprise
    XLARGE = (200, 1000)    # Hyperscale

class UseCase(Enum):
    """Common cluster use cases"""
    STARTUP_MVP = "startup_mvp"
    MICROSERVICES = "microservices"
    DATA_ANALYTICS = "data_analytics"
    ML_PLATFORM = "ml_platform"
    WEB_HOSTING = "web_hosting"
    ENTERPRISE_INTERNAL = "enterprise_internal"
    ECOMMERCE = "ecommerce"
    SAAS_PLATFORM = "saas_platform"
    IOT_PLATFORM = "iot_platform"
    GAMING_BACKEND = "gaming_backend"