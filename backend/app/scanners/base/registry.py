import importlib
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

from app.scanners.base.scanner import BaseScanner, ScannerType

logger = logging.getLogger(__name__)


class ScannerRegistry:
    """Registry for managing scanner modules."""
    
    def __init__(self):
        self._scanners: Dict[str, Type[BaseScanner]] = {}
        self._initialized = False
    
    def register(self, scanner_class: Type[BaseScanner]) -> None:
        """Register a scanner class."""
        if not issubclass(scanner_class, BaseScanner):
            raise ValueError(f"{scanner_class} must be a subclass of BaseScanner")
        
        scanner_name = scanner_class.name
        if scanner_name in self._scanners:
            logger.warning(f"Scanner '{scanner_name}' is already registered, overwriting...")
        
        self._scanners[scanner_name] = scanner_class
        logger.info(f"Registered scanner: {scanner_name}")
    
    def unregister(self, scanner_name: str) -> None:
        """Unregister a scanner."""
        if scanner_name in self._scanners:
            del self._scanners[scanner_name]
            logger.info(f"Unregistered scanner: {scanner_name}")
    
    def get_scanner(self, scanner_name: str) -> Optional[Type[BaseScanner]]:
        """Get a scanner class by name."""
        return self._scanners.get(scanner_name)
    
    def create_scanner(self, scanner_name: str, config: Optional[Dict] = None) -> Optional[BaseScanner]:
        """Create a scanner instance by name."""
        scanner_class = self.get_scanner(scanner_name)
        if scanner_class:
            return scanner_class(config=config)
        return None
    
    def list_scanners(self, scanner_type: Optional[ScannerType] = None) -> List[str]:
        """List registered scanner names."""
        if scanner_type:
            return [
                name for name, cls in self._scanners.items()
                if cls.scanner_type == scanner_type
            ]
        return list(self._scanners.keys())
    
    def get_scanner_info(self, scanner_name: str) -> Optional[Dict]:
        """Get scanner information."""
        scanner_class = self.get_scanner(scanner_name)
        if scanner_class:
            return {
                "name": scanner_class.name,
                "description": scanner_class.description,
                "type": scanner_class.scanner_type,
                "version": scanner_class.version,
                "categories": [cat.value for cat in scanner_class().get_supported_categories()],
            }
        return None
    
    def auto_discover_scanners(self, base_path: Path) -> None:
        """Auto-discover and register scanners from a directory."""
        logger.info(f"Auto-discovering scanners from: {base_path}")
        
        # Look for scanner modules in passive and active directories
        for scanner_type in ["passive", "active"]:
            scanner_dir = base_path / scanner_type
            if not scanner_dir.exists():
                continue
            
            for py_file in scanner_dir.glob("*.py"):
                if py_file.stem.startswith("_"):
                    continue
                
                module_path = f"app.scanners.{scanner_type}.{py_file.stem}"
                try:
                    module = importlib.import_module(module_path)
                    
                    # Find all BaseScanner subclasses in the module
                    for name, obj in inspect.getmembers(module):
                        if (
                            inspect.isclass(obj) 
                            and issubclass(obj, BaseScanner) 
                            and obj != BaseScanner
                            and obj.__module__ == module.__name__
                        ):
                            self.register(obj)
                            
                except Exception as e:
                    logger.error(f"Failed to import scanner module {module_path}: {e}")
    
    def initialize(self) -> None:
        """Initialize the registry by auto-discovering scanners."""
        if not self._initialized:
            scanners_path = Path(__file__).parent.parent
            self.auto_discover_scanners(scanners_path)
            self._initialized = True
            logger.info(f"Scanner registry initialized with {len(self._scanners)} scanners")


# Global scanner registry instance
scanner_registry = ScannerRegistry()