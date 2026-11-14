from abc import ABC, abstractmethod
from app.extensions import db
from app.models.network_scan import NetworkScan

class NetworkScanRepositoryInterface(ABC):
    """Abstract interface defining database access rules for network assessment scans."""

    @abstractmethod
    def save(self, network_scan: NetworkScan) -> NetworkScan:
        """Persist a network scan and its associated port findings."""
        pass

    @abstractmethod
    def find_by_id(self, scan_id: int) -> NetworkScan:
        """Retrieve a specific network scan record by its internal integer ID."""
        pass

    @abstractmethod
    def find_by_uuid(self, uuid: str) -> NetworkScan:
        """Retrieve a specific network scan record by its unique public UUID."""
        pass

    @abstractmethod
    def get_history_by_user(self, user_id: int) -> list:
        """Retrieve all completed network scan records initiated by a specific user."""
        pass


class SQLAlchemyNetworkScanRepository(NetworkScanRepositoryInterface):
    """Concrete SQLAlchemy implementation of the network scan repository interface."""

    def save(self, network_scan: NetworkScan) -> NetworkScan:
        db.session.add(network_scan)
        db.session.commit()
        return network_scan

    def find_by_id(self, scan_id: int) -> NetworkScan:
        return db.session.get(NetworkScan, scan_id)

    def find_by_uuid(self, uuid: str) -> NetworkScan:
        return NetworkScan.query.filter_by(uuid=uuid).first()

    def get_history_by_user(self, user_id: int) -> list:
        return NetworkScan.query.filter_by(user_id=user_id).order_by(NetworkScan.started_at.desc()).all()

