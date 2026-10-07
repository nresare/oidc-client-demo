# SPDX-License-Identifier: MIT
# Copyright (c) 2026 oidc-client-demo contributors

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.trace import SpanKind, StatusCode, Tracer
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from oidc_client_demo.config import OtelConfig


def create_tracer_provider(config: OtelConfig) -> TracerProvider:
    provider = TracerProvider(resource=Resource.create({"service.name": config.service_name}), sampler=ALWAYS_ON)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=config.endpoint)))
    return provider


class RequestTracingMiddleware:
    def __init__(self, app: ASGIApp, tracer: Tracer):
        self.app = app
        self.tracer = tracer

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope["method"]
        # Deliberately omit query strings, headers, bodies and exception messages:
        # OIDC callbacks and sessions contain credentials.
        with self.tracer.start_as_current_span(
            method,
            kind=SpanKind.SERVER,
            attributes={"http.request.method": method, "url.path": scope["path"]},
            record_exception=False,
            set_status_on_exception=False,
        ) as span:

            async def traced_send(message: Message) -> None:
                if message["type"] == "http.response.start":
                    status = message["status"]
                    span.set_attribute("http.response.status_code", status)
                    if status >= 500:
                        span.set_status(StatusCode.ERROR)
                await send(message)

            try:
                await self.app(scope, receive, traced_send)
            except Exception as exc:
                span.set_attribute("error.type", type(exc).__name__)
                span.set_status(StatusCode.ERROR)
                raise
