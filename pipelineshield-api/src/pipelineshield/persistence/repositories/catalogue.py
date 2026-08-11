"""CatalogueRepository — abstract interface and SQLAlchemy 2.0 implementation.

All writes go through create_version which only ever issues INSERT statements.
No code path in this module may issue UPDATE or DELETE against an existing
control_catalogue_version row — that invariant is enforced at the repository
boundary and verified by the event-listener test in test_catalogue_repository.
"""
from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models.control_catalogue_version import ControlCatalogueVersion
from ...catalogue.checksum import compute_checksum
from ...catalogue.schemas import CatalogueSnapshot, CatalogueVersionConflictError

log = logging.getLogger(__name__)


class CatalogueRepository(ABC):
    """Abstract repository interface for ControlCatalogueVersion entities."""

    @abstractmethod
    def get_active(self) -> ControlCatalogueVersion | None:
        """Return the current active catalogue version, or None."""

    @abstractmethod
    def get_by_version(self, version: int) -> ControlCatalogueVersion | None:
        """Return the catalogue version with *version*, or None."""

    @abstractmethod
    def list_versions(self) -> Sequence[ControlCatalogueVersion]:
        """Return all catalogue versions in ascending version order."""

    @abstractmethod
    def create_version(
        self,
        version: int,
        snapshot: CatalogueSnapshot,
        created_by: uuid.UUID,
        change_notes: str | None = None,
    ) -> ControlCatalogueVersion:
        """Persist a new catalogue version (INSERT only).

        Validates the snapshot, computes the content checksum, and inserts a new
        row.  Raises CatalogueVersionConflictError if *version* is already used.
        Never issues UPDATE or DELETE against an existing row.
        """


class SQLAlchemyCatalogueRepository(CatalogueRepository):
    """SQLAlchemy 2.0 implementation of CatalogueRepository."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_active(self) -> ControlCatalogueVersion | None:
        stmt = (
            select(ControlCatalogueVersion)
            .where(ControlCatalogueVersion.status == "active")
            .order_by(ControlCatalogueVersion.version.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def get_by_version(self, version: int) -> ControlCatalogueVersion | None:
        stmt = select(ControlCatalogueVersion).where(
            ControlCatalogueVersion.version == version
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def list_versions(self) -> Sequence[ControlCatalogueVersion]:
        stmt = select(ControlCatalogueVersion).order_by(
            ControlCatalogueVersion.version
        )
        return self._session.execute(stmt).scalars().all()

    def create_version(
        self,
        version: int,
        snapshot: CatalogueSnapshot,
        created_by: uuid.UUID,
        change_notes: str | None = None,
    ) -> ControlCatalogueVersion:
        snapshot_dict: Any = snapshot.model_dump()
        grade_bands_list: Any = [gb.model_dump() for gb in snapshot.grade_bands]
        checksum = compute_checksum(snapshot_dict)

        row = ControlCatalogueVersion(
            id=uuid.uuid4(),
            version=version,
            status="active",
            snapshot=snapshot_dict,
            grade_bands=grade_bands_list,
            created_by=created_by,
            change_notes=change_notes,
            content_checksum=checksum,
        )
        self._session.add(row)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise CatalogueVersionConflictError(
                f"Catalogue version {version} already exists."
            ) from exc

        log.info(
            "catalogue_version_created",
            extra={
                "actor": str(created_by),
                "version": version,
                "checksum": checksum,
                "category_ids": [c["id"] for c in snapshot_dict.get("categories", [])],
            },
        )
        return row
