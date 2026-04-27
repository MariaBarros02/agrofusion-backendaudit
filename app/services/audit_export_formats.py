"""
Escritores de formatos para exportación de auditoría (streaming por lotes).

Columnas alineadas a RF: ID evento, origen y resultado internacionalizados,
fecha localizada, acción (CatTerm.label), usuario; en CSV/XLSX/JSONL (mismas columnas
y orden) además target_json, diff_json, IP y dispositivo. Excel: ancho fijo + wrap.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence
from xml.sax.saxutils import escape

from app.models.af_audit_log import AuditLog

_BRAND = "#047857"
_BRAND_LIGHT = "#ecfdf5"
_GRID = "#a7f3d0"
_SLATE = "#64748b"

# Origen (module_code) — mismas claves que i18n frontend audit.*
MODULE_LABELS_ES: Dict[str, str] = {
    "AUTH": "Autenticación",
    "SESSIONS": "Sesiones",
    "TOKENS": "Tokens",
    "USERS": "Usuarios",
    "OTP": "OTP",
    "PROJECTS": "Proyectos",
    "MODULES": "Módulos",
    "SUBMODULOS": "Submódulos",
    "KMS": "KMS",
    "LOGOUT": "Cierre de sesión",
    "ROLES": "Roles",
    "PERMISSIONS": "Permisos",
    "SSO": "SSO",
    "AUDIT": "Auditoría",
    "AUDIT_EXPORT": "Exportación de auditoría",
    "PAYMENTS": "Pagos",
    "ORDERS": "Pedidos",
}


def translate_module(code: str | None) -> str:
    if not code:
        return ""
    return MODULE_LABELS_ES.get(code.upper(), code)


def translate_outcome(outcome: str | None) -> str:
    if not outcome:
        return ""
    o = outcome.strip().lower()
    if o in ("success", "successful", "exitoso", "ok"):
        return "Exitoso"
    if o in ("failure", "failed", "fail", "error", "fallido"):
        return "Fallido"
    return outcome


def format_datetime_es(dt: datetime | None) -> str:
    """Formato tipo 03/04/2026, 09:01 p. m. (UTC del registro)."""
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    h24 = dt.hour
    h12 = h24 % 12
    if h12 == 0:
        h12 = 12
    ampm = "a. m." if h24 < 12 else "p. m."
    return f"{dt.day:02d}/{dt.month:02d}/{dt.year}, {h12:02d}:{dt.minute:02d} {ampm}"


EXPORT_FIELDS_PDF: List[str] = [
    "event_id",
    "origin_i18n",
    "outcome_i18n",
    "fecha_hora",
    "accion",
    "usuario",
]

EXPORT_FIELDS_TABULAR: List[str] = EXPORT_FIELDS_PDF + [
    "target_json",
    "diff_json",
    "actor_ip",
    "device_info",
]


def export_field_labels() -> Dict[str, str]:
    return {
        "event_id": "ID evento",
        "origin_i18n": "Origen",
        "outcome_i18n": "Resultado",
        "fecha_hora": "Fecha/Hora",
        "accion": "Acción",
        "usuario": "Usuario",
        "target_json": "Información registro",
        "diff_json": "Información registro actualizado",
        "actor_ip": "IP",
        "device_info": "Dispositivo",
        # compatibilidad columnas antiguas
        "audit_id": "ID evento",
        "module_code": "Origen (código)",
        "created_at": "Fecha/Hora",
        "action_code": "Código acción",
        "outcome": "Resultado",
        "actor_email": "Correo",
    }


# Anchos fijos (caracteres aprox.); Excel no ensancha columna — texto hace wrap
_COL_WIDTHS: Dict[str, float] = {
    "event_id": 38,
    "origin_i18n": 20,
    "outcome_i18n": 12,
    "fecha_hora": 22,
    "accion": 28,
    "usuario": 22,
    "target_json": 42,
    "diff_json": 42,
    "actor_ip": 14,
    "device_info": 28,
}


def _mask_email(email: str | None) -> str | None:
    if not email or "@" not in email:
        return email
    local, _, domain = email.partition("@")
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"
    parts = domain.split(".")
    dom_show = parts[-1] if parts else domain
    return f"{masked_local}@{dom_show}"


def _serialize_json_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, default=str)
    return str(v)


def build_export_row(
    log: AuditLog,
    *,
    actor_email: str | None,
    actor_name: str | None,
    action_label: str | None,
    mask_pii: bool,
    include_sensitive: bool = False,
) -> Dict[str, Any]:
    """Fila canónica para informes (PDF = primeras 6 claves)."""
    ip_out = None
    if log.actor_ip is not None:
        ip_s = str(log.actor_ip)
        if mask_pii and len(ip_s) > 4:
            ip_out = ip_s[:2] + "…" + ip_s[-2:]
        else:
            ip_out = ip_s

    name_out = (actor_name or "").strip()
    if not name_out:
        name_out = (
            _mask_email(actor_email) if mask_pii and actor_email else (actor_email or "")
        )

    accion = (action_label or "").strip() or (log.action_code or "")

    row: Dict[str, Any] = {
        "event_id": str(log.audit_id),
        "origin_i18n": translate_module(log.module_code),
        "outcome_i18n": translate_outcome(log.outcome),
        "fecha_hora": format_datetime_es(log.created_at),
        "accion": accion,
        "usuario": name_out or (_mask_email(actor_email) if mask_pii else actor_email) or "",
        "target_json": _serialize_json_value(log.target_json),
        "diff_json": _serialize_json_value(log.diff_json) if log.diff_json is not None else "",
        "actor_ip": ip_out or "",
        "device_info": _serialize_json_value(log.device_info),
    }
    if include_sensitive:
        row["payload_hash"] = log.payload_hash
        row["digital_signature"] = log.digital_signature
    return row


def audit_log_to_row(
    log: AuditLog,
    actor_email: str | None,
    fields: Sequence[str],
    *,
    mask_pii: bool,
    include_sensitive: bool,
) -> Dict[str, Any]:
    """Compatibilidad: exportaciones con lista de campos heredada."""
    raw = build_export_row(
        log,
        actor_email=actor_email,
        actor_name=None,
        action_label=None,
        mask_pii=mask_pii,
        include_sensitive=include_sensitive,
    )
    legacy = {
        "audit_id": raw["event_id"],
        "created_at": log.created_at.isoformat() if log.created_at else None,
        "actor_id": str(log.actor_id) if log.actor_id else None,
        "actor_email": actor_email,
        "module_code": log.module_code,
        "action_code": log.action_code,
        "outcome": log.outcome,
        "project_id": str(log.project_id) if log.project_id else None,
        "target_json": log.target_json,
        "diff_json": log.diff_json,
        "actor_ip": raw.get("actor_ip"),
        "session_id": str(log.session_id) if log.session_id else None,
        "trace_id": str(log.trace_id) if log.trace_id else None,
        "tenant_id": str(log.tenant_id) if log.tenant_id else None,
        "external_project_id": str(log.external_project_id) if log.external_project_id else None,
        "device_info": log.device_info,
        "at": log.at.isoformat() if log.at else None,
    }
    if include_sensitive:
        legacy["payload_hash"] = log.payload_hash
        legacy["digital_signature"] = log.digital_signature
    return {k: legacy[k] for k in fields if k in legacy}


DEFAULT_EXPORT_FIELDS = list(EXPORT_FIELDS_TABULAR)


class CsvExportWriter:
    def __init__(self, path: Path, fields: List[str]) -> None:
        self.path = path
        self.fields = fields
        labels = export_field_labels()
        self._f = open(path, "w", newline="", encoding="utf-8")
        self._f.write("\ufeff")
        self._w = csv.DictWriter(self._f, fieldnames=fields, extrasaction="ignore")
        header_labels = {f: labels.get(f, f) for f in fields}
        self._w.writerow(header_labels)

    def write_rows(self, rows: Iterable[Dict[str, Any]]) -> None:
        for r in rows:
            flat = {}
            for k in self.fields:
                v = r.get(k)
                flat[k] = _serialize_json_value(v) if isinstance(v, (dict, list)) else v
            self._w.writerow(flat)

    def close(self) -> None:
        self._f.close()


class JsonlExportWriter:
    """
    Mismas columnas y orden que CSV/XLSX: una línea JSON por registro, claves = ``fields``.
    (Sin sort_keys, para alinear con Excel y con el encabezado del CSV.)
    """

    def __init__(self, path: Path, fields: List[str]) -> None:
        self.path = path
        self.fields = list(fields)
        self._f = open(path, "w", encoding="utf-8")

    def write_rows(self, rows: Iterable[Dict[str, Any]]) -> None:
        for r in rows:
            line: Dict[str, Any] = {}
            for k in self.fields:
                v = r.get(k)
                line[k] = (
                    _serialize_json_value(v) if isinstance(v, (dict, list)) else v
                )
            self._f.write(json.dumps(line, ensure_ascii=False, default=str) + "\n")

    def close(self) -> None:
        self._f.close()


class XlsxExportWriter:
    def __init__(self, path: Path, fields: List[str]) -> None:
        import xlsxwriter

        self.fields = fields
        self.path = path
        labels = export_field_labels()
        self._wb = xlsxwriter.Workbook(
            str(path),
            {"constant_memory": True, "strings_to_urls": False},
        )
        self._ws = self._wb.add_worksheet("Auditoría")
        self._ws.set_tab_color(_BRAND)
        self._header_fmt = self._wb.add_format(
            {
                "bold": True,
                "font_color": "#ffffff",
                "bg_color": _BRAND,
                "border": 1,
                "border_color": _GRID,
                "valign": "top",
                "text_wrap": True,
            }
        )
        wrap_common = {
            "border": 1,
            "border_color": "#d1d5db",
            "text_wrap": True,
            "valign": "top",
            "shrink": False,
        }
        self._cell_fmt = self._wb.add_format(wrap_common)
        self._alt_fmt = self._wb.add_format({**wrap_common, "bg_color": _BRAND_LIGHT})
        for col, f in enumerate(fields):
            self._ws.write(0, col, labels.get(f, f), self._header_fmt)
        self._ws.freeze_panes(1, 0)
        self._ws.set_row(0, 28)
        self._ws.set_default_row(72)
        self._row = 1

    def write_rows(self, rows: Iterable[Dict[str, Any]]) -> None:
        for r in rows:
            use_alt = self._row % 2 == 0
            fmt = self._alt_fmt if use_alt else self._cell_fmt
            for col, k in enumerate(self.fields):
                v = r.get(k)
                val = _serialize_json_value(v) if isinstance(v, (dict, list)) else v
                self._ws.write(self._row, col, val, fmt)
            self._row += 1

    def close(self) -> None:
        for col, f in enumerate(self.fields):
            w = _COL_WIDTHS.get(f, 18)
            self._ws.set_column(col, col, min(float(w), 50.0))
        self._wb.close()


class PdfExportWriter:
    def __init__(
        self,
        path: Path,
        fields: List[str],
        title: str,
        *,
        subtitle: str | None = None,
    ) -> None:
        from reportlab.lib import colors
        from reportlab.lib.colors import HexColor
        from reportlab.lib.pagesizes import landscape, A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Table,
            TableStyle,
        )

        self.fields = fields
        self.path = path
        self._buf = io.BytesIO()
        page = landscape(A4)
        self._page = page
        self._doc = SimpleDocTemplate(
            self._buf,
            pagesize=page,
            title=title,
            leftMargin=12 * mm,
            rightMargin=12 * mm,
            topMargin=14 * mm,
            bottomMargin=16 * mm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            name="ExportTitle",
            parent=styles["Title"],
            fontSize=18,
            spaceAfter=6,
            textColor=HexColor(_BRAND),
        )
        sub_style = ParagraphStyle(
            name="ExportSub",
            parent=styles["Normal"],
            fontSize=9,
            textColor=HexColor(_SLATE),
            spaceAfter=14,
        )
        self._cell_para_style = ParagraphStyle(
            name="PdfCell",
            parent=styles["Normal"],
            fontSize=7,
            leading=8.5,
            textColor=HexColor("#1e293b"),
        )

        self._story = []
        self._story.append(Paragraph(escape(title), title_style))
        sub = subtitle or datetime.now(timezone.utc).strftime(
            "Generado el %d/%m/%Y a las %H:%M UTC · AgroFusion"
        )
        self._story.append(Paragraph(escape(sub), sub_style))
        self._story.append(
            HRFlowable(width="100%", thickness=1, color=HexColor(_GRID), spaceAfter=10)
        )

        self._colors = colors
        self._HexColor = HexColor
        self._mm = mm
        self._Table = Table
        self._TableStyle = TableStyle
        self._Paragraph = Paragraph
        labels = export_field_labels()
        self._headers = [[labels.get(f, f) for f in fields]]
        self._rows: List[List[Any]] = []

    def _cell_para(self, value: Any) -> Any:
        from reportlab.platypus import Paragraph

        if value is None:
            s = ""
        elif isinstance(value, (dict, list)):
            s = json.dumps(value, ensure_ascii=False, default=str)
        else:
            s = str(value)
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        safe = escape(s).replace("\n", "<br/>")
        return Paragraph(safe, self._cell_para_style)

    def _on_page(self, canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(self._HexColor(_SLATE))
        w, _h = self._page
        canvas.drawString(12 * self._mm, 8 * self._mm, "AgroFusion · Informe de auditoría")
        canvas.drawRightString(w - 12 * self._mm, 8 * self._mm, f"Página {canvas.getPageNumber()}")
        canvas.restoreState()

    def write_rows(self, rows: Iterable[Dict[str, Any]]) -> None:
        for r in rows:
            line = [self._cell_para(r.get(k)) for k in self.fields]
            self._rows.append(line)

    def close(self) -> None:
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm

        hdr_para_style = ParagraphStyle(
            "PdfHdrCell",
            parent=self._cell_para_style,
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=10,
            textColor=self._colors.white,
        )
        hdr_rows = [
            [self._Paragraph(escape(str(h)), hdr_para_style) for h in self._headers[0]]
        ]
        data = hdr_rows + self._rows
        total_w = self._page[0] - 24 * mm
        ncols = max(len(self.fields), 1)
        base = total_w / ncols
        col_widths = [min(max(base * 1.05, 26 * mm), 52 * mm) for _ in self.fields]
        s = sum(col_widths)
        if s > total_w:
            scale = total_w / s
            col_widths = [w * scale for w in col_widths]

        tbl = self._Table(data, colWidths=col_widths, repeatRows=1)
        brand = self._HexColor(_BRAND)
        light = self._HexColor(_BRAND_LIGHT)
        grid = self._HexColor(_GRID)
        tbl.setStyle(
            self._TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), brand),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self._colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self._colors.white, light]),
                    ("GRID", (0, 0), (-1, -1), 0.25, grid),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 1), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
                ]
            )
        )
        self._story.append(tbl)
        self._doc.build(
            self._story,
            onFirstPage=self._on_page,
            onLaterPages=self._on_page,
        )
        self.path.write_bytes(self._buf.getvalue())
