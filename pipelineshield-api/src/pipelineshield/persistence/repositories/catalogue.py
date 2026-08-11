"""CatalogueRepository — abstract interface and SQLAlchemy implementation."""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.control_catalogue_version import ControlCatalogueVersion


class CatalogueRepository(ABC):
    """Abstract repository interface for ControlCatalogueVersion entities."""

    @abstractmethod
    def get_by_id(self, version_id: uuid.UUID) -> ControlCatalogueVersion | None:
        """Return the catalogue version with *version_id*, or None."""

    @abstractmethod
    def get_latest(self) -> ControlCatalogueVersion | None:
        """Return the highest-version-number catalogue entry, or None."""

    @abstractmethod
    def get_by_version_number(self, version_number: int) -> ControlCatalogueVersion | None:
        """Return the catalogue version with *version_number*, or None."""

    @abstractmethod
    def list_all(self) -> Sequence[ControlCatalogueVersion]:
        """Return all catalogue versions in ascending version order."""

    @abstractmethod
    def add(self, version: ControlCatalogueVersion) -> ControlCatalogueVersion:
        """Persist a new catalogue version and return the managed instance."""


class SQLAlchemyCatalogueRepository(CatalogueRepository):
    """SQLAlchemy 2.0 implementation of CatalogueRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_id(self, version_id: uuid.UUID) -> ControlCatalogueVersion | None:
        stmt = select(ControlCatalogueVersion).where(
            ControlCatalogueVersion.id == version_id
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def get_latest(self) -> ControlCatalogueVersion | None:
        stmt = (
            select(ControlCatalogueVersion)
            .order_by(ControlCatalogueVersion.version_number.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def get_by_version_number(
        self, version_number: int
    ) -> ControlCatalogueVersion | None:
        stmt = select(ControlCatalogueVersion).where(
            ControlCatalogueVersion.version_number == version_number
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def list_all(self) -> Sequence[ControlCatalogueVersion]:
        stmt = select(ControlCatalogueVersion).order_by(
            ControlCatalogueVersion.version_number
        )
        return self._session.execute(stmt).scalars().all()

    def add(self, version: ControlCatalogueVersion) -> ControlCatalogueVersion:
        self._session.add(version)
        self._session.flush()
        return version
