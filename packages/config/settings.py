from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("SHIELD_ENV", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    elasticsearch_url: str = os.getenv(
        "ELASTICSEARCH_URL",
        "http://localhost:9200",
    )

    kibana_url: str = os.getenv(
        "KIBANA_URL",
        "http://localhost:5601",
    )

    logstash_host: str = os.getenv(
        "LOGSTASH_HOST",
        "localhost",
    )

    logstash_port: int = int(
        os.getenv("LOGSTASH_PORT", "5044")
    )

    sensor_id: str = os.getenv(
        "SHIELD_SENSOR_ID",
        "local-dev",
    )


settings = Settings()