"""Scanner task wrapper for API execution."""

from typing import Dict, Optional

from src.reporters.schema_map import build_schema_map
from src.scanner.orchestrator import ScanOrchestrator


class ScannerTask:
    """Wrapper for running the unified scanner via API."""
    
    def __init__(
        self,
        task_id: str,
        endpoint: str,
        enable_ml: bool = False,
        enable_llm: bool = False,
        risk_level: int = 1,
        technique: str = "IDAC",
        profile: Optional[str] = None,
    ):
        self.task_id = task_id
        self.endpoint = endpoint
        self.enable_ml = enable_ml
        self.enable_llm = enable_llm
        self.risk_level = risk_level
        self.technique = technique
        self.profile = profile
        
        self.status = "pending"
        self.progress = 0.0
        self.error: Optional[str] = None
        self.current_phase = "Queued"
    
    def run(self) -> Dict:
        """
        Execute the scanner and return results.
        """
        self.status = "running"
        self.progress = 0.02
        
        try:
            orchestrator = ScanOrchestrator(
                self.endpoint,
                profile=self.profile,
                risk_level=self.risk_level,
                technique=self.technique,
                enable_ml=self.enable_ml,
                enable_llm=self.enable_llm,
                progress_callback=self._on_progress,
            )
            results = orchestrator.run()
            results["graph"] = build_schema_map(results)
            
            self.progress = 1.0
            self.status = "completed"
            return results
            
        except Exception as e:
            self.status = "failed"
            self.error = str(e)
            raise

    def _on_progress(self, phase: str, progress: float, status: str):
        self.current_phase = f"{phase}: {status}"
        self.progress = max(self.progress, min(progress, 0.99))
    
