"""
Database layer for scan history and results.
Uses SQLite for simplicity.
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import threading
from src.risk.rating import rate_finding


def default_db_path() -> Path:
    """Return a user-writable database path for packaged CLI installs."""
    if os.getenv("GUARDQL_DB_PATH"):
        return Path(os.environ["GUARDQL_DB_PATH"]).expanduser()

    data_dir = os.getenv("GUARDQL_DATA_DIR")
    if data_dir:
        return Path(data_dir).expanduser() / "guardian.db"

    xdg_data_home = os.getenv("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home).expanduser() / "guardql" / "guardian.db"

    return Path.home() / ".local" / "share" / "guardql" / "guardian.db"


class Database:
    """SQLite database manager for scan data"""
    
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path).expanduser() if db_path else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()
    
    @property
    def conn(self):
        """Get thread-local connection"""
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            # Enable foreign keys for CASCADE deletions
            self._local.conn.execute("PRAGMA foreign_keys = ON")
        return self._local.conn
    
    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                config TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                error TEXT
            )
        """)
        
        # Results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                scan_id TEXT PRIMARY KEY,
                summary TEXT NOT NULL,
                findings TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("PRAGMA table_info(results)")
        columns = {row[1] for row in cursor.fetchall()}
        if "details" not in columns:
            cursor.execute("ALTER TABLE results ADD COLUMN details TEXT")
        
        # Graph data table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS graphs (
                scan_id TEXT PRIMARY KEY,
                nodes TEXT NOT NULL,
                edges TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        # Benchmarks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS benchmarks (
                id TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                config TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                error TEXT,
                metrics TEXT,
                result TEXT
            )
        """)

        # Manual notes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS manual_notes (
                scan_id TEXT NOT NULL,
                operation_name TEXT NOT NULL,
                status TEXT NOT NULL,
                observations TEXT,
                payload_tweaks TEXT,
                request_override TEXT,
                last_replay TEXT,
                promoted_finding_id TEXT,
                promoted_at TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (scan_id, operation_name),
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("PRAGMA table_info(manual_notes)")
        manual_note_columns = {row[1] for row in cursor.fetchall()}
        if "last_replay" not in manual_note_columns:
            cursor.execute("ALTER TABLE manual_notes ADD COLUMN last_replay TEXT")
        if "promoted_finding_id" not in manual_note_columns:
            cursor.execute("ALTER TABLE manual_notes ADD COLUMN promoted_finding_id TEXT")
        if "promoted_at" not in manual_note_columns:
            cursor.execute("ALTER TABLE manual_notes ADD COLUMN promoted_at TEXT")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS manual_replays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                operation_name TEXT NOT NULL,
                request_override TEXT NOT NULL,
                replay_result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)

        conn.commit()
        conn.close()
    
    def create_scan(self, scan_id: str, endpoint: str, config: Dict):
        """Create a new scan record"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO scans (id, endpoint, config, status, start_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            endpoint,
            json.dumps(config),
            "pending",
            datetime.now().isoformat()
        ))
        self.conn.commit()
    
    def update_scan_status(self, scan_id: str, status: str, error: Optional[str] = None):
        """Update scan status"""
        cursor = self.conn.cursor()
        
        if status in ["completed", "failed"]:
            cursor.execute("""
                UPDATE scans
                SET status = ?, end_time = ?, error = ?
                WHERE id = ?
            """, (status, datetime.now().isoformat(), error, scan_id))
        else:
            cursor.execute("""
                UPDATE scans
                SET status = ?
                WHERE id = ?
            """, (status, scan_id))
        
        self.conn.commit()
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan by ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        
        if row:
            return {
                "id": row["id"],
                "endpoint": row["endpoint"],
                "config": json.loads(row["config"]),
                "status": row["status"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "error": row["error"]
            }
        return None
    
    def save_scan_results(self, scan_id: str, results: Dict):
        """Save scan results and graph data"""
        cursor = self.conn.cursor()
        
        details = {
            key: value
            for key, value in results.items()
            if key not in {"summary", "findings", "graph"}
        }

        # Store summary and findings separately from the larger report details.
        cursor.execute("""
            INSERT OR REPLACE INTO results (scan_id, summary, findings, details)
            VALUES (?, ?, ?, ?)
        """, (
            scan_id,
            json.dumps(results.get("summary", {})),
            json.dumps(results.get("findings", [])),
            json.dumps(details)
        ))
        
        # Store graph data in its own table for schema map loading.
        if "graph" in results:
            cursor.execute("""
                INSERT OR REPLACE INTO graphs (scan_id, nodes, edges)
                VALUES (?, ?, ?)
            """, (
                scan_id,
                json.dumps(results["graph"].get("nodes", [])),
                json.dumps(results["graph"].get("edges", []))
            ))
        
        self.conn.commit()
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict]:
        """Get scan results"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM results WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        
        if row:
            details = json.loads(row["details"]) if row["details"] else {}
            return {
                "summary": json.loads(row["summary"]),
                "findings": json.loads(row["findings"]),
                **details
            }
        return None
    
    def get_scan_graph(self, scan_id: str) -> Optional[Dict]:
        """Get graph data"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM graphs WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        
        if row:
            return {
                "nodes": json.loads(row["nodes"]),
                "edges": json.loads(row["edges"])
            }
        return None
    
    def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """List all scans with pagination"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, endpoint, status, start_time, end_time
            FROM scans
            ORDER BY start_time DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    def count_scans(self) -> int:
        """Get total scan count"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        return cursor.fetchone()["count"]
    
    def delete_scan(self, scan_id: str):
        """Delete a scan and its results"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self.conn.commit()
    
    def get_statistics(self) -> Dict:
        """Get overall statistics"""
        cursor = self.conn.cursor()
        
        # Total scans
        cursor.execute("SELECT COUNT(*) as total FROM scans")
        total_scans = cursor.fetchone()["total"]
        
        # By status
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM scans
            GROUP BY status
        """)
        by_status = {row["status"]: row["count"] for row in cursor.fetchall()}
        
        # Total findings by severity - only from scans that still exist
        cursor.execute("""
            SELECT r.summary, r.findings
            FROM results r
            INNER JOIN scans s ON r.scan_id = s.id
        """)
        
        total_findings = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in cursor.fetchall():
            findings = json.loads(row["findings"]) if row["findings"] else []
            summary = self._build_summary_from_findings(findings) if findings else json.loads(row["summary"])
            total_findings["critical"] += summary.get("critical", 0)
            total_findings["high"] += summary.get("high", 0)
            total_findings["medium"] += summary.get("medium", 0)
            total_findings["low"] += summary.get("low", 0)
            total_findings["info"] += summary.get("info", 0)
        
        return {
            "total_scans": total_scans,
            "by_status": by_status,
            "total_findings": total_findings
        }

    def create_benchmark(self, benchmark_id: str, endpoint: str, config: Dict):
        """Create a new benchmark record."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO benchmarks (id, endpoint, config, status, start_time)
            VALUES (?, ?, ?, ?, ?)
        """, (
            benchmark_id,
            endpoint,
            json.dumps(config),
            "pending",
            datetime.now().isoformat(),
        ))
        self.conn.commit()

    def update_benchmark_status(self, benchmark_id: str, status: str, error: Optional[str] = None):
        """Update benchmark status."""
        cursor = self.conn.cursor()
        if status in ["completed", "failed"]:
            cursor.execute("""
                UPDATE benchmarks
                SET status = ?, end_time = ?, error = ?
                WHERE id = ?
            """, (status, datetime.now().isoformat(), error, benchmark_id))
        else:
            cursor.execute("""
                UPDATE benchmarks
                SET status = ?
                WHERE id = ?
            """, (status, benchmark_id))
        self.conn.commit()

    def save_benchmark_results(self, benchmark_id: str, result: Dict):
        """Persist benchmark metrics and full result."""
        cursor = self.conn.cursor()
        metrics = result.get("benchmark", {}).get("metrics", {})
        cursor.execute("""
            UPDATE benchmarks
            SET metrics = ?, result = ?
            WHERE id = ?
        """, (
            json.dumps(metrics),
            json.dumps(result),
            benchmark_id,
        ))
        self.conn.commit()

    def get_benchmark(self, benchmark_id: str) -> Optional[Dict]:
        """Get benchmark by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM benchmarks WHERE id = ?", (benchmark_id,))
        row = cursor.fetchone()
        config = json.loads(row["config"]) if row else {}
        if row:
            return {
                "id": row["id"],
                "endpoint": row["endpoint"],
                "config": config,
                "label": config.get("label"),
                "group": config.get("group"),
                "status": row["status"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "error": row["error"],
                "metrics": json.loads(row["metrics"]) if row["metrics"] else {},
            }
        return None

    def get_benchmark_result(self, benchmark_id: str) -> Optional[Dict]:
        """Get full benchmark result."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT result FROM benchmarks WHERE id = ?", (benchmark_id,))
        row = cursor.fetchone()
        if row and row["result"]:
            return json.loads(row["result"])
        return None

    def list_benchmarks(
        self,
        limit: int = 50,
        offset: int = 0,
        label: Optional[str] = None,
        group: Optional[str] = None,
        days: Optional[int] = None,
    ) -> List[Dict]:
        """List benchmark runs with metrics."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, endpoint, status, start_time, end_time, metrics, config
            FROM benchmarks
            ORDER BY start_time DESC
        """)
        rows = cursor.fetchall()

        label_filter = (label or "").strip().lower()
        group_filter = (group or "").strip().lower()
        cutoff = None
        if days:
            cutoff = datetime.now().timestamp() - (days * 86400)

        collected = []
        for row in rows:
            config = json.loads(row["config"]) if row["config"] else {}
            item = {
                "id": row["id"],
                "endpoint": row["endpoint"],
                "status": row["status"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "metrics": json.loads(row["metrics"]) if row["metrics"] else {},
                "label": config.get("label"),
                "group": config.get("group"),
                "role_breakdown": {},
            }

            if label_filter and label_filter not in (item["label"] or "").lower():
                continue

            if group_filter and group_filter not in (item["group"] or "").lower():
                continue

            if cutoff is not None:
                try:
                    started_at = datetime.fromisoformat(item["start_time"]).timestamp()
                except ValueError:
                    started_at = 0
                if started_at < cutoff:
                    continue

            if row["status"] == "completed":
                benchmark_result = self.get_benchmark_result(row["id"]) or {}
                item["role_breakdown"] = (
                    (benchmark_result.get("benchmark") or {}).get("role_breakdown") or {}
                )

            collected.append(item)

        return collected[offset : offset + limit]

    def count_benchmarks(
        self,
        label: Optional[str] = None,
        group: Optional[str] = None,
        days: Optional[int] = None,
    ) -> int:
        """Get total benchmark count."""
        return len(
            self.list_benchmarks(limit=100000, offset=0, label=label, group=group, days=days)
        )

    def summarize_benchmark_groups(
        self,
        label: Optional[str] = None,
        group: Optional[str] = None,
        days: Optional[int] = None,
    ) -> List[Dict]:
        """Aggregate benchmark metrics and role breakdown by group."""
        rows = self.list_benchmarks(limit=100000, offset=0, label=label, group=group, days=days)
        summaries: Dict[str, Dict] = {}

        for row in rows:
            if row["status"] != "completed":
                continue

            benchmark_result = self.get_benchmark_result(row["id"]) or {}
            benchmark_data = benchmark_result.get("benchmark", {})
            group_name = row.get("group") or "ungrouped"
            summary = summaries.setdefault(
                group_name,
                {
                    "name": group_name,
                    "runs": 0,
                    "latest_start_time": "",
                    "latest_label": "",
                    "overall": {"precision": 0.0, "recall": 0.0, "f1_score": 0.0},
                    "role_breakdown": {},
                },
            )

            metrics = benchmark_data.get("metrics", {})
            summary["runs"] += 1
            summary["overall"]["precision"] += float(metrics.get("precision", 0.0))
            summary["overall"]["recall"] += float(metrics.get("recall", 0.0))
            summary["overall"]["f1_score"] += float(metrics.get("f1_score", 0.0))

            if not summary["latest_start_time"] or row["start_time"] > summary["latest_start_time"]:
                summary["latest_start_time"] = row["start_time"]
                summary["latest_label"] = row.get("label") or row["endpoint"]

            for role, role_data in (benchmark_data.get("role_breakdown") or {}).items():
                role_summary = summary["role_breakdown"].setdefault(
                    role,
                    {
                        "runs": 0,
                        "truth_count": 0,
                        "precision": 0.0,
                        "recall": 0.0,
                        "f1_score": 0.0,
                    },
                )
                role_metrics = role_data.get("metrics", {})
                role_summary["runs"] += 1
                role_summary["truth_count"] += int(role_data.get("truth_count") or 0)
                role_summary["precision"] += float(role_metrics.get("precision", 0.0))
                role_summary["recall"] += float(role_metrics.get("recall", 0.0))
                role_summary["f1_score"] += float(role_metrics.get("f1_score", 0.0))

        normalized = []
        for summary in summaries.values():
            run_count = summary["runs"] or 1
            role_breakdown = {}
            for role, role_data in summary["role_breakdown"].items():
                role_runs = role_data["runs"] or 1
                role_breakdown[role] = {
                    "runs": role_data["runs"],
                    "truth_count": role_data["truth_count"],
                    "avg_precision": round(role_data["precision"] / role_runs, 4),
                    "avg_recall": round(role_data["recall"] / role_runs, 4),
                    "avg_f1_score": round(role_data["f1_score"] / role_runs, 4),
                }

            normalized.append(
                {
                    "name": summary["name"],
                    "runs": summary["runs"],
                    "latest_start_time": summary["latest_start_time"],
                    "latest_label": summary["latest_label"],
                    "avg_precision": round(summary["overall"]["precision"] / run_count, 4),
                    "avg_recall": round(summary["overall"]["recall"] / run_count, 4),
                    "avg_f1_score": round(summary["overall"]["f1_score"] / run_count, 4),
                    "role_breakdown": role_breakdown,
                }
            )

        return sorted(
            normalized,
            key=lambda item: (item["avg_f1_score"], item["runs"], item["name"]),
            reverse=True,
        )

    def get_manual_note(self, scan_id: str, operation_name: str) -> Optional[Dict]:
        """Get a saved manual note for a specific operation."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT operation_name, status, observations, payload_tweaks, request_override, last_replay,
                   promoted_finding_id, promoted_at, updated_at
            FROM manual_notes
            WHERE scan_id = ? AND operation_name = ?
            """,
            (scan_id, operation_name),
        )
        row = cursor.fetchone()
        return self._manual_note_from_row(row) if row else None

    def list_manual_notes(self, scan_id: str) -> List[Dict]:
        """List saved manual notes for a scan."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT operation_name, status, observations, payload_tweaks, request_override, last_replay,
                   promoted_finding_id, promoted_at, updated_at
            FROM manual_notes
            WHERE scan_id = ?
            ORDER BY updated_at DESC
        """, (scan_id,))
        rows = cursor.fetchall()
        return [self._manual_note_from_row(row) for row in rows]

    def list_manual_replays(
        self,
        scan_id: str,
        operation_name: str,
        limit: Optional[int] = 5,
    ) -> List[Dict]:
        """List replay history for a manual operation."""
        cursor = self.conn.cursor()
        query = """
            SELECT id, operation_name, request_override, replay_result, created_at
            FROM manual_replays
            WHERE scan_id = ? AND operation_name = ?
            ORDER BY id DESC
        """
        params = [scan_id, operation_name]
        if limit is not None:
            query += "\nLIMIT ?"
            params.append(limit)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [
            {
                "id": row["id"],
                "operation_name": row["operation_name"],
                "request_override": json.loads(row["request_override"]),
                "replay_result": json.loads(row["replay_result"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def count_manual_replays(self, scan_id: str, operation_name: str) -> int:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM manual_replays
            WHERE scan_id = ? AND operation_name = ?
            """,
            (scan_id, operation_name),
        )
        return int(cursor.fetchone()["count"])

    def save_manual_replay(
        self,
        scan_id: str,
        operation_name: str,
        request_override: Dict,
        replay_result: Dict,
    ) -> Dict:
        """Persist one replay attempt in history."""
        created_at = datetime.now().isoformat()
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO manual_replays (scan_id, operation_name, request_override, replay_result, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                operation_name,
                json.dumps(request_override),
                json.dumps(replay_result),
                created_at,
            ),
        )
        self.conn.commit()
        return {
            "id": cursor.lastrowid,
            "operation_name": operation_name,
            "request_override": request_override,
            "replay_result": replay_result,
            "created_at": created_at,
        }

    def save_manual_note(
        self,
        scan_id: str,
        operation_name: str,
        status: str,
        observations: str,
        payload_tweaks: str,
        request_override: Optional[Dict],
        last_replay: Optional[Dict] = None,
    ) -> Dict:
        """Create or update a manual testing note."""
        updated_at = datetime.now().isoformat()
        existing = self.get_manual_note(scan_id, operation_name)
        existing_promoted_finding_id = (existing or {}).get("promoted_finding_id")
        existing_promoted_at = (existing or {}).get("promoted_at")
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO manual_notes (
                scan_id,
                operation_name,
                status,
                observations,
                payload_tweaks,
                request_override,
                last_replay,
                promoted_finding_id,
                promoted_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            operation_name,
            status,
            observations,
            payload_tweaks,
            json.dumps(request_override) if request_override is not None else None,
            json.dumps(last_replay if last_replay is not None else (existing or {}).get("last_replay"))
            if (last_replay is not None or (existing or {}).get("last_replay") is not None)
            else None,
            existing_promoted_finding_id,
            existing_promoted_at,
            updated_at,
        ))
        self.conn.commit()
        return {
            "operation_name": operation_name,
            "status": status,
            "observations": observations,
            "payload_tweaks": payload_tweaks,
            "request_override": request_override,
            "last_replay": last_replay if last_replay is not None else (existing or {}).get("last_replay"),
            "promoted_finding_id": existing_promoted_finding_id,
            "promoted_at": existing_promoted_at,
            "updated_at": updated_at,
        }

    def list_manual_finding_provenance(
        self,
        scan_id: str,
        finding_id: Optional[str] = None,
    ) -> List[Dict]:
        """Collect promoted manual findings with note, request, and replay history."""
        report = self.get_scan_results(scan_id) or {}
        findings = report.get("findings") or []
        items: List[Dict] = []

        for finding in findings:
            if finding.get("source") != "manual":
                continue
            if finding_id and finding.get("id") != finding_id:
                continue

            provenance = finding.get("provenance") or {}
            operation_name = finding.get("manual_operation_name") or provenance.get("operation_name")
            note = self.get_manual_note(scan_id, operation_name) if operation_name else None
            replay_history = (
                self.list_manual_replays(scan_id, operation_name, limit=None)
                if operation_name
                else []
            )
            request_override = (note or {}).get("request_override") or provenance.get("request_override")

            items.append(
                {
                    "finding_id": finding.get("id"),
                    "operation_name": operation_name,
                    "finding": finding,
                    "note": note,
                    "request_override": request_override,
                    "replay_history": replay_history,
                    "replay_history_count": len(replay_history),
                    "promotion": {
                        "promoted_at": provenance.get("promoted_at")
                        or finding.get("promoted_from_note_at"),
                        "note_status": provenance.get("note_status") or (note or {}).get("status"),
                        "note_updated_at": provenance.get("note_updated_at")
                        or (note or {}).get("updated_at"),
                        "manual_mode_path": provenance.get("manual_mode_path")
                        or f"/manual/{scan_id}?op={operation_name or ''}",
                    },
                }
            )

        return sorted(
            items,
            key=lambda item: item.get("promotion", {}).get("promoted_at") or "",
            reverse=True,
        )

    def promote_manual_note_to_finding(
        self,
        scan_id: str,
        operation_name: str,
        finding: Dict,
    ) -> Dict:
        """Add or update a finding in a scan report from a manual note."""
        note = self.get_manual_note(scan_id, operation_name)
        if not note:
            raise ValueError("Manual note not found")

        cursor = self.conn.cursor()
        cursor.execute("SELECT summary, findings, details FROM results WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError("Scan results not found")

        findings = json.loads(row["findings"]) if row["findings"] else []
        details = json.loads(row["details"]) if row["details"] else {}
        replay_history = self.list_manual_replays(scan_id, operation_name, limit=6)
        replay_history_count = self.count_manual_replays(scan_id, operation_name)
        latest_replay_entry = replay_history[0] if replay_history else None

        finding_id = note.get("promoted_finding_id") or finding.get("id") or f"MANUAL-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        promoted_at = datetime.now().isoformat()
        finding_record = {
            **finding,
            "id": finding_id,
            "source": "manual",
            "manual_operation_name": operation_name,
            "promoted_from_note_at": promoted_at,
            "provenance": {
                "scan_id": scan_id,
                "operation_name": operation_name,
                "note_status": note.get("status"),
                "note_updated_at": note.get("updated_at"),
                "promoted_at": promoted_at,
                "manual_mode_path": f"/manual/{scan_id}?op={operation_name}",
                "request_override": note.get("request_override"),
                "replay_history_count": replay_history_count,
                "latest_replay_entry": latest_replay_entry,
            },
        }
        if not finding_record.get("risk"):
            finding_record["risk"] = rate_finding(
                category=finding_record.get("category"),
                severity=finding_record.get("severity"),
            )
            finding_record["severity"] = finding_record["risk"]["severity"]

        existing_index = next(
            (index for index, item in enumerate(findings) if item.get("id") == finding_id),
            None,
        )
        if existing_index is None:
            findings.append(finding_record)
        else:
            findings[existing_index] = finding_record

        details["manual_findings"] = sorted(
            {
                *(details.get("manual_findings") or []),
                finding_id,
            }
        )
        summary = self._build_summary_from_findings(findings)

        cursor.execute(
            """
            UPDATE results
            SET summary = ?, findings = ?, details = ?
            WHERE scan_id = ?
            """,
            (
                json.dumps(summary),
                json.dumps(findings),
                json.dumps(details),
                scan_id,
            ),
        )
        cursor.execute(
            """
            UPDATE manual_notes
            SET promoted_finding_id = ?, promoted_at = ?, updated_at = ?
            WHERE scan_id = ? AND operation_name = ?
            """,
            (finding_id, promoted_at, promoted_at, scan_id, operation_name),
        )
        self.conn.commit()

        updated_note = self.get_manual_note(scan_id, operation_name)
        return {
            "finding": finding_record,
            "note": updated_note,
            "summary": summary,
        }

    def _manual_note_from_row(self, row: sqlite3.Row) -> Dict:
        return {
            "operation_name": row["operation_name"],
            "status": row["status"],
            "observations": row["observations"] or "",
            "payload_tweaks": row["payload_tweaks"] or "",
            "request_override": json.loads(row["request_override"]) if row["request_override"] else None,
            "last_replay": json.loads(row["last_replay"]) if row["last_replay"] else None,
            "promoted_finding_id": row["promoted_finding_id"],
            "promoted_at": row["promoted_at"],
            "updated_at": row["updated_at"],
        }

    def _build_summary_from_findings(self, findings: List[Dict]) -> Dict:
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = self._finding_severity(finding)
            if severity == "CRITICAL":
                summary["critical"] += 1
            elif severity == "HIGH":
                summary["high"] += 1
            elif severity == "MEDIUM":
                summary["medium"] += 1
            elif severity == "LOW":
                summary["low"] += 1
            else:
                summary["info"] += 1

        return summary

    def _finding_severity(self, finding: Dict) -> str:
        risk = finding.get("risk") if isinstance(finding, dict) else None
        if isinstance(risk, dict) and risk.get("severity"):
            return str(risk["severity"]).upper()
        return rate_finding(
            category=finding.get("category"),
            severity=finding.get("severity"),
        )["severity"]

    def delete_benchmark(self, benchmark_id: str):
        """Delete benchmark result."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM benchmarks WHERE id = ?", (benchmark_id,))
        self.conn.commit()
