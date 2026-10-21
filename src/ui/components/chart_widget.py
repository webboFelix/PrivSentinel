"""Animated, data-driven 3D charts built with pyqtgraph's OpenGL widgets."""

import math
from collections.abc import Sequence

import numpy as np
import pyqtgraph.opengl as gl
from PySide6.QtCore import QCoreApplication, Qt, QTimer
from PySide6.QtGui import QColor, QHideEvent, QIcon, QShowEvent, QSurfaceFormat
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from src.ui.icon_assets import icon_path

QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)


class ChartWidget(QFrame):
    """A rotating 3D chart; empty collections are shown as truthful empty states."""

    def __init__(
        self,
        title: str,
        message: str,
        parent: QWidget | None = None,
        *,
        icon: str = "system-activity.png",
        color: str = "#05bfe8",
        mode: str = "line",
        period: str = "",
    ) -> None:
        super().__init__(parent)
        if mode not in {"line", "bar", "pie", "network"}:
            raise ValueError(f"Unsupported 3D chart mode: {mode}")
        self.mode = mode
        self.color = QColor(color)
        self._message = message
        self._items: list[gl.GLGraphicsItem] = []
        self._azimuth = 35.0
        self._has_data = False
        self.setObjectName("panel")
        self.setMinimumHeight(130)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 10, 13, 8)
        layout.setSpacing(4)
        header = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(QIcon(icon_path(icon)).pixmap(18, 18))
        header.addWidget(icon_label)
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        header.addWidget(heading, 1)
        self.period_label = QLabel(period)
        self.period_label.setObjectName("chartPeriod")
        if period:
            header.addWidget(self.period_label)
        layout.addLayout(header)

        self.view = gl.GLViewWidget(self)
        self.view.setObjectName("chart3D")
        surface_format = QSurfaceFormat()
        surface_format.setVersion(2, 1)
        surface_format.setProfile(QSurfaceFormat.OpenGLContextProfile.CompatibilityProfile)
        surface_format.setDepthBufferSize(24)
        self.view.setFormat(surface_format)
        self.view.setBackgroundColor(QColor("#091d37"))
        self.view.setCameraPosition(distance=12, elevation=24, azimuth=self._azimuth)
        self.view.setMinimumHeight(78)
        layout.addWidget(self.view, 1)
        self.empty_label = QLabel(message, self.view)
        self.empty_label.setObjectName("chartEmpty")
        self.empty_label.setWordWrap(True)
        self.empty_label.setStyleSheet(
            "background: rgba(7, 24, 47, 190); color: #a9c2df; "
            "border: 1px solid #1b4269; border-radius: 7px; padding: 7px 10px;"
        )
        self.empty_label.setMaximumWidth(260)
        self.empty_label.adjustSize()
        self.empty_label.move(12, 12)
        self._add_grid()
        self.legend_label = QLabel()
        self.legend_label.setObjectName("chartLegend")
        self.legend_label.hide()
        layout.addWidget(self.legend_label)

        self._rotation_timer = QTimer(self)
        self._rotation_timer.setInterval(120)
        self._rotation_timer.timeout.connect(self._rotate)

    def set_data(self, points: Sequence[tuple[str, float]]) -> None:
        normalized = tuple((str(label), max(0.0, float(value))) for label, value in points)
        self._clear_data_items()
        self._has_data = any(value > 0 for _, value in normalized)
        self._sync_rotation()
        self.empty_label.setText(self._message)
        self.empty_label.setVisible(not self._has_data)
        self.legend_label.setVisible(self._has_data)
        if not self._has_data:
            return
        stride = max(1, (len(normalized) + 5) // 6)
        legend_values = normalized[::stride]
        if normalized and legend_values[-1] != normalized[-1]:
            legend_values = (*legend_values, normalized[-1])
        self.legend_label.setText(
            "    ".join(f"{label}: {value:g}" for label, value in legend_values)
        )
        if self.mode == "pie":
            self._render_pie(normalized)
        elif self.mode == "network":
            self._render_network(normalized)
        else:
            self._render_series(normalized)

    def set_message(self, message: str) -> None:
        self._message = message
        self._clear_data_items()
        self._has_data = False
        self._sync_rotation()
        self.empty_label.setText(message)
        self.empty_label.adjustSize()
        self.empty_label.setVisible(True)
        self.legend_label.clear()
        self.legend_label.hide()

    def set_empty_message(self, message: str) -> None:
        self._message = message
        if not self._has_data:
            self.set_message(message)

    def _add_grid(self) -> None:
        grid = gl.GLGridItem()
        grid.setSize(x=10, y=10)
        grid.setSpacing(x=1, y=1)
        grid.setColor((0.12, 0.32, 0.48, 0.85))
        self.view.addItem(grid)
        self._items.append(grid)

    def _render_series(self, points: tuple[tuple[str, float], ...]) -> None:
        values = np.array([value for _, value in points], dtype=float)
        maximum = max(float(values.max()), 1.0)
        values = values / maximum * 3.6
        x_positions = np.arange(len(points), dtype=float)
        positions = np.column_stack(
            (x_positions - (len(points) - 1) / 2, np.zeros(len(points)), values)
        )
        if self.mode == "bar":
            for position, height in zip(positions, values, strict=True):
                self._add_bar(position, height)
        else:
            if len(points) > 1:
                line = gl.GLLinePlotItem(
                    pos=positions,
                    color=self._rgba(),
                    width=3,
                    antialias=True,
                    mode="line_strip",
                )
                self.view.addItem(line)
                self._items.append(line)
            dots = gl.GLScatterPlotItem(
                pos=positions,
                color=self._rgba(),
                size=9,
                pxMode=True,
            )
            self.view.addItem(dots)
            self._items.append(dots)
        self.view.setCameraPosition(
            distance=max(8, len(points) * 0.7),
            elevation=25,
            azimuth=self._azimuth,
        )

    def _render_pie(self, points: tuple[tuple[str, float], ...]) -> None:
        colors = ("#00c6f2", "#18d89b", "#f5ad32", "#f04b67", "#806cff")
        total = sum(value for _, value in points if value > 0)
        if total <= 0:
            return
        angle = 0.0
        for index, (_, value) in enumerate(points):
            if value <= 0:
                continue
            sweep = value / total * math.tau
            mesh = self._pie_slice(angle, angle + sweep, 0.28)
            item = gl.GLMeshItem(
                vertexes=mesh[0],
                faces=mesh[1],
                smooth=False,
                drawEdges=True,
                edgeColor=(0.04, 0.15, 0.25, 1),
                color=QColor(colors[index % len(colors)]),
                shader="shaded",
            )
            self.view.addItem(item)
            self._items.append(item)
            angle += sweep
        self.view.setCameraPosition(distance=8.5, elevation=35, azimuth=self._azimuth)

    def _render_network(self, points: tuple[tuple[str, float], ...]) -> None:
        total = sum(value for _, value in points if value > 0)
        count = sum(value > 0 for _, value in points)
        if not count:
            return
        node_positions = []
        node_colors = []
        for index, (_label, value) in enumerate(points):
            if value <= 0:
                continue
            angle = math.tau * index / max(count, 1)
            node_positions.append((math.cos(angle) * 3, math.sin(angle) * 3, 0.25 + value / total))
            node_colors.append(
                QColor("#f04b67").getRgbF()
                if "critical" in _label.casefold() or "high" in _label.casefold()
                else QColor("#00b9e8").getRgbF()
            )
        center = np.array([[0.0, 0.0, 0.0]])
        nodes = np.asarray(node_positions, dtype=float)
        for position in nodes:
            edge = gl.GLLinePlotItem(
                pos=np.vstack((center[0], position)),
                color=(0.05, 0.45, 0.7, 0.8),
                width=1,
                antialias=True,
            )
            self.view.addItem(edge)
            self._items.append(edge)
        scatter_positions = np.vstack((center, nodes))
        scatter_colors = np.asarray([(0.05, 0.8, 1.0, 1.0), *node_colors], dtype=float)
        scatter = gl.GLScatterPlotItem(
            pos=scatter_positions,
            color=scatter_colors,
            size=np.asarray([18, *([10] * len(nodes))]),
            pxMode=True,
        )
        self.view.addItem(scatter)
        self._items.append(scatter)
        self.view.setCameraPosition(distance=9, elevation=25, azimuth=self._azimuth)

    def _add_bar(self, position: np.ndarray, height: float) -> None:
        width = 0.48
        vertices = np.array(
            [
                [position[0] - width / 2, -width / 2, 0],
                [position[0] + width / 2, -width / 2, 0],
                [position[0] + width / 2, width / 2, 0],
                [position[0] - width / 2, width / 2, 0],
                [position[0] - width / 2, -width / 2, height],
                [position[0] + width / 2, -width / 2, height],
                [position[0] + width / 2, width / 2, height],
                [position[0] - width / 2, width / 2, height],
            ],
            dtype=float,
        )
        faces = np.array(
            [
                [0, 1, 2],
                [0, 2, 3],
                [4, 6, 5],
                [4, 7, 6],
                [0, 4, 5],
                [0, 5, 1],
                [1, 5, 6],
                [1, 6, 2],
                [2, 6, 7],
                [2, 7, 3],
                [3, 7, 4],
                [3, 4, 0],
            ]
        )
        item = gl.GLMeshItem(
            vertexes=vertices,
            faces=faces,
            smooth=False,
            drawEdges=True,
            edgeColor=(0.05, 0.22, 0.34, 1),
            color=self._rgba(),
            shader="shaded",
        )
        self.view.addItem(item)
        self._items.append(item)

    @staticmethod
    def _pie_slice(start: float, end: float, thickness: float):
        segments = max(8, int((end - start) * 28))
        angles = np.linspace(start, end, segments + 1)
        vertices: list[tuple[float, float, float]] = [(0, 0, thickness)]
        vertices.extend((math.cos(angle), math.sin(angle), thickness) for angle in angles)
        vertices.append((0, 0, 0))
        vertices.extend((math.cos(angle), math.sin(angle), 0) for angle in angles)
        faces: list[tuple[int, int, int]] = []
        bottom_center = segments + 2
        bottom_start = bottom_center + 1
        for index in range(segments):
            faces.append((0, index + 1, index + 2))
            faces.append((bottom_center, bottom_start + index + 1, bottom_start + index))
            top_a, top_b = index + 1, index + 2
            bot_a, bot_b = bottom_start + index, bottom_start + index + 1
            faces.extend(
                (
                    (top_a, bot_a, bot_b),
                    (top_a, bot_b, top_b),
                )
            )
        faces.extend(
            (
                (0, bottom_center, bottom_start),
                (0, bottom_start, 1),
                (0, segments + 1, bottom_start + segments),
                (0, bottom_start + segments, bottom_center),
            )
        )
        return np.asarray(vertices, dtype=float), np.asarray(faces, dtype=np.uint32)

    def _clear_data_items(self) -> None:
        for item in self._items[1:]:
            self.view.removeItem(item)
        self._items = self._items[:1]

    def _rgba(self) -> tuple[float, float, float, float]:
        red, green, blue, alpha = self.color.getRgbF()
        return red, green, blue, alpha

    def _rotate(self) -> None:
        if not self.isVisible() or not self._has_data:
            self._rotation_timer.stop()
            return
        self._azimuth = (self._azimuth + 0.12) % 360
        self.view.setCameraPosition(azimuth=self._azimuth)

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self._sync_rotation()

    def hideEvent(self, event: QHideEvent) -> None:
        self._rotation_timer.stop()
        super().hideEvent(event)

    def _sync_rotation(self) -> None:
        if self._has_data and self.isVisible():
            if not self._rotation_timer.isActive():
                self._rotation_timer.start()
        else:
            self._rotation_timer.stop()
