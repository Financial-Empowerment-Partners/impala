# --- OpenTelemetry Collector Configuration ---
#
# When var.signoz_endpoint is set, an OTEL Collector sidecar is added to each
# ECS task definition (see ecs.tf). The collector receives OTLP traces and
# metrics from the impala-bridge application on localhost:4317 and forwards
# them to SigNoz.

resource "aws_cloudwatch_log_group" "otel_collector" {
  count             = var.signoz_endpoint != "" ? 1 : 0
  name              = "/ecs/${local.name_prefix}-otel-collector"
  retention_in_days = 14

  tags = {
    Name = "${local.name_prefix}-otel-collector-logs"
  }
}

locals {
  # OTEL Collector config YAML — uses collector-native ${env:VAR} substitution
  # for SigNoz endpoint and access token at runtime.
  otel_collector_config = <<-EOT
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 5s
    send_batch_size: 256
  resource:
    attributes:
      - key: deployment.environment
        value: "${var.environment}"
        action: upsert

exporters:
  otlp/signoz:
    endpoint: $${env:SIGNOZ_ENDPOINT}
    headers:
      signoz-access-token: $${env:SIGNOZ_ACCESS_TOKEN}

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, resource]
      exporters: [otlp/signoz]
    metrics:
      receivers: [otlp]
      processors: [batch, resource]
      exporters: [otlp/signoz]
EOT

  # Sidecar container definition shared by server and worker task definitions
  otel_sidecar_container = var.signoz_endpoint != "" ? [
    {
      name      = "otel-collector"
      image     = "otel/opentelemetry-collector-contrib:0.96.0"
      essential = false

      command = ["--config=env:OTEL_COLLECTOR_CONFIG"]

      environment = [
        { name = "OTEL_COLLECTOR_CONFIG", value = local.otel_collector_config },
        { name = "SIGNOZ_ENDPOINT", value = var.signoz_endpoint },
        { name = "SIGNOZ_ACCESS_TOKEN", value = var.signoz_access_token },
      ]

      portMappings = [
        { containerPort = 4317, protocol = "tcp" },
        { containerPort = 4318, protocol = "tcp" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.otel_collector[0].name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "otel"
        }
      }

      memoryReservation = 128
    }
  ] : []

  # OTEL env vars for the app container — points to collector sidecar on localhost
  otel_app_env = var.signoz_endpoint != "" ? [
    { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = "http://localhost:4317" },
    { name = "OTEL_SERVICE_NAME", value = "${var.project_name}" },
  ] : []
}
