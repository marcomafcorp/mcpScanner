import json
import csv
import io
from typing import Dict, List, Any, Optional, Type, Union
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
import zipfile

from app.models.base import BaseModel
from app.models import User, Scan, Finding, Target, Vulnerability, AuditLog, SecureCredential
from app.core.encryption import field_encryption


class DataExporter:
    """Service for exporting user data."""
    
    # Models that contain user data
    USER_DATA_MODELS = [
        User,
        Scan,
        Finding,
        Target,
        AuditLog,
        SecureCredential,
    ]
    
    def __init__(self):
        """Initialize data exporter."""
        self.exporters = {
            "json": self._export_json,
            "csv": self._export_csv,
            "xml": self._export_xml,
        }
    
    async def export_user_data(
        self,
        db: AsyncSession,
        user_id: str,
        format: str = "json",
        include_encrypted: bool = False
    ) -> bytes:
        """
        Export all data associated with a user.
        
        Args:
            db: Database session
            user_id: User ID
            format: Export format (json, csv, xml)
            include_encrypted: Whether to include decrypted sensitive data
            
        Returns:
            Exported data as bytes
        """
        if format not in self.exporters:
            raise ValueError(f"Unsupported format: {format}")
        
        # Gather all user data
        user_data = await self._gather_user_data(db, user_id, include_encrypted)
        
        # Export in requested format
        return await self.exporters[format](user_data)
    
    async def _gather_user_data(
        self,
        db: AsyncSession,
        user_id: str,
        include_encrypted: bool
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Gather all data associated with a user.
        
        Args:
            db: Database session
            user_id: User ID
            include_encrypted: Whether to include decrypted sensitive data
            
        Returns:
            Dictionary of model name to list of records
        """
        data = {}
        
        # Export user record
        user_result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            raise ValueError(f"User {user_id} not found")
        
        data["user"] = [self._serialize_model(user, include_encrypted)]
        
        # Export scans
        scans_result = await db.execute(
            select(Scan)
            .where(Scan.user_id == user_id)
            .options(selectinload(Scan.targets), selectinload(Scan.findings))
        )
        scans = scans_result.scalars().all()
        data["scans"] = [self._serialize_model(scan, include_encrypted) for scan in scans]
        
        # Export findings
        findings_result = await db.execute(
            select(Finding)
            .join(Scan)
            .where(Scan.user_id == user_id)
            .options(selectinload(Finding.vulnerability))
        )
        findings = findings_result.scalars().all()
        data["findings"] = [self._serialize_model(finding, include_encrypted) for finding in findings]
        
        # Export targets
        targets_result = await db.execute(
            select(Target)
            .join(Scan)
            .where(Scan.user_id == user_id)
        )
        targets = targets_result.scalars().all()
        data["targets"] = [self._serialize_model(target, include_encrypted) for target in targets]
        
        # Export vulnerabilities
        vuln_result = await db.execute(
            select(Vulnerability)
            .join(Finding)
            .join(Scan)
            .where(Scan.user_id == user_id)
        )
        vulnerabilities = vuln_result.scalars().all()
        data["vulnerabilities"] = [
            self._serialize_model(vuln, include_encrypted) for vuln in vulnerabilities
        ]
        
        # Export audit logs
        audit_result = await db.execute(
            select(AuditLog)
            .where(AuditLog.actor_id == user_id)
        )
        audit_logs = audit_result.scalars().all()
        data["audit_logs"] = [
            self._serialize_model(log, include_encrypted) for log in audit_logs
        ]
        
        # Export secure credentials
        if include_encrypted:
            creds_result = await db.execute(
                select(SecureCredential)
                .where(SecureCredential.user_id == user_id)
            )
            credentials = creds_result.scalars().all()
            data["secure_credentials"] = [
                self._serialize_model(cred, include_encrypted) for cred in credentials
            ]
        
        return data
    
    def _serialize_model(
        self,
        instance: BaseModel,
        include_encrypted: bool
    ) -> Dict[str, Any]:
        """
        Serialize a model instance to dictionary.
        
        Args:
            instance: Model instance
            include_encrypted: Whether to include decrypted sensitive data
            
        Returns:
            Dictionary representation
        """
        # Use model's to_dict if available
        if hasattr(instance, "to_dict"):
            return instance.to_dict(include_value=include_encrypted)
        
        # Otherwise build dict from columns
        data = {}
        for column in instance.__table__.columns:
            value = getattr(instance, column.name)
            
            # Handle datetime
            if isinstance(value, datetime):
                value = value.isoformat()
            # Handle other non-serializable types
            elif value is not None and not isinstance(value, (str, int, float, bool, list, dict)):
                value = str(value)
            
            data[column.name] = value
        
        return data
    
    async def _export_json(self, data: Dict[str, List[Dict[str, Any]]]) -> bytes:
        """Export data as JSON."""
        return json.dumps(data, indent=2, default=str).encode('utf-8')
    
    async def _export_csv(self, data: Dict[str, List[Dict[str, Any]]]) -> bytes:
        """Export data as CSV (in a zip file with multiple CSVs)."""
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for model_name, records in data.items():
                if not records:
                    continue
                
                # Create CSV for this model
                csv_buffer = io.StringIO()
                
                # Get all unique keys from all records
                all_keys = set()
                for record in records:
                    all_keys.update(record.keys())
                
                fieldnames = sorted(all_keys)
                writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
                
                writer.writeheader()
                for record in records:
                    writer.writerow(record)
                
                # Add to zip
                zip_file.writestr(
                    f"{model_name}.csv",
                    csv_buffer.getvalue().encode('utf-8')
                )
        
        zip_buffer.seek(0)
        return zip_buffer.read()
    
    async def _export_xml(self, data: Dict[str, List[Dict[str, Any]]]) -> bytes:
        """Export data as XML."""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        
        root = Element('user_data')
        root.set('export_date', datetime.utcnow().isoformat())
        
        for model_name, records in data.items():
            model_elem = SubElement(root, model_name)
            
            for record in records:
                record_elem = SubElement(model_elem, 'record')
                
                for key, value in record.items():
                    field_elem = SubElement(record_elem, key)
                    if value is not None:
                        field_elem.text = str(value)
        
        # Pretty print
        rough_string = tostring(root, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ").encode('utf-8')


class DataDeletionService:
    """Service for deleting user data."""
    
    def __init__(self):
        """Initialize deletion service."""
        pass
    
    async def delete_user_data(
        self,
        db: AsyncSession,
        user_id: str,
        soft_delete: bool = True
    ) -> Dict[str, int]:
        """
        Delete all data associated with a user.
        
        Args:
            db: Database session
            user_id: User ID
            soft_delete: Whether to soft delete (anonymize) or hard delete
            
        Returns:
            Dictionary with deletion counts
        """
        deletion_counts = {}
        
        if soft_delete:
            # Anonymize user data
            deletion_counts = await self._anonymize_user_data(db, user_id)
        else:
            # Hard delete user data
            deletion_counts = await self._hard_delete_user_data(db, user_id)
        
        await db.commit()
        return deletion_counts
    
    async def _anonymize_user_data(
        self,
        db: AsyncSession,
        user_id: str
    ) -> Dict[str, int]:
        """
        Anonymize user data (soft delete).
        
        Args:
            db: Database session
            user_id: User ID
            
        Returns:
            Dictionary with anonymization counts
        """
        counts = {}
        
        # Anonymize user record
        user_result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()
        if user:
            user.email = f"deleted_{user.id}@example.com"
            user.username = f"deleted_user_{user.id}"
            user.full_name = "Deleted User"
            user.is_active = False
            user.hashed_password = "DELETED"
            counts["user"] = 1
        
        # Anonymize audit logs
        audit_result = await db.execute(
            select(AuditLog).where(AuditLog.actor_id == user_id)
        )
        audit_logs = audit_result.scalars().all()
        for log in audit_logs:
            log.actor_name = "Deleted User"
            log.ip_address = "0.0.0.0"
            log.user_agent = "DELETED"
        counts["audit_logs"] = len(audit_logs)
        
        # Delete sensitive credentials
        creds_result = await db.execute(
            select(SecureCredential).where(SecureCredential.user_id == user_id)
        )
        credentials = creds_result.scalars().all()
        for cred in credentials:
            await db.delete(cred)
        counts["secure_credentials"] = len(credentials)
        
        return counts
    
    async def _hard_delete_user_data(
        self,
        db: AsyncSession,
        user_id: str
    ) -> Dict[str, int]:
        """
        Hard delete all user data.
        
        Args:
            db: Database session
            user_id: User ID
            
        Returns:
            Dictionary with deletion counts
        """
        counts = {}
        
        # Delete in order of dependencies
        # 1. Delete secure credentials
        creds_result = await db.execute(
            select(SecureCredential).where(SecureCredential.user_id == user_id)
        )
        credentials = creds_result.scalars().all()
        for cred in credentials:
            await db.delete(cred)
        counts["secure_credentials"] = len(credentials)
        
        # 2. Delete audit logs
        audit_result = await db.execute(
            select(AuditLog).where(AuditLog.actor_id == user_id)
        )
        audit_logs = audit_result.scalars().all()
        for log in audit_logs:
            await db.delete(log)
        counts["audit_logs"] = len(audit_logs)
        
        # 3. Delete scans (cascades to findings, targets, vulnerabilities)
        scans_result = await db.execute(
            select(Scan).where(Scan.user_id == user_id)
        )
        scans = scans_result.scalars().all()
        for scan in scans:
            await db.delete(scan)
        counts["scans"] = len(scans)
        
        # 4. Delete user
        user_result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()
        if user:
            await db.delete(user)
            counts["user"] = 1
        
        return counts


# Global instances
data_exporter = DataExporter()
data_deletion_service = DataDeletionService()