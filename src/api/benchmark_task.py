"""Benchmark task wrapper for API execution."""

from typing import Dict, Optional

from src.scanner.dvga_benchmark import run_dvga_benchmark


class BenchmarkTask:
    """Wrapper for running DVGA benchmark mode via API."""

    def __init__(
        self,
        benchmark_id: str,
        endpoint: str,
        label: str | None = None,
        group: str | None = None,
        profile: str = "default",
        enable_ml: bool = False,
        enable_llm: bool = False,
    ):
        self.benchmark_id = benchmark_id
        self.endpoint = endpoint
        self.label = label
        self.group = group
        self.profile = profile
        self.enable_ml = enable_ml
        self.enable_llm = enable_llm

        self.status = "pending"
        self.progress = 0.0
        self.error: Optional[str] = None
        self.current_phase = "Queued"

    def run(self) -> Dict:
        """Execute the benchmark and return result."""
        self.status = "running"
        self.progress = 0.02
        try:
            result = run_dvga_benchmark(
                self.endpoint,
                profile=self.profile,
                enable_ml=self.enable_ml,
                enable_llm=self.enable_llm,
                progress_callback=self._on_progress,
            )
            if self.label:
                result.setdefault("benchmark", {})["label"] = self.label
                result.setdefault("meta", {})["label"] = self.label
            if self.group:
                result.setdefault("benchmark", {})["group"] = self.group
                result.setdefault("meta", {})["group"] = self.group
            self.progress = 1.0
            self.status = "completed"
            return result
        except Exception as exc:
            self.status = "failed"
            self.error = str(exc)
            raise

    def _on_progress(self, phase: str, progress: float, status: str):
        self.current_phase = f"{phase}: {status}"
        self.progress = max(self.progress, min(progress, 0.99))
