"""
Hellcat Dependency Injection Container
======================================
Ported from AutoRedTeam-Orchestrator core/container.py.
Supports Singleton / Scoped / Transient lifetimes, auto-wiring via
type-hints, cycle detection, factory registration, and decorator sugar.
"""
from __future__ import annotations

import inspect
import threading
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Lifetime enum
# ---------------------------------------------------------------------------

class Lifetime(Enum):
    TRANSIENT = "transient"
    SINGLETON = "singleton"
    SCOPED = "scoped"


# ---------------------------------------------------------------------------
# Service registration record
# ---------------------------------------------------------------------------

class _Registration:
    __slots__ = ("service_type", "implementation", "lifetime", "factory", "instance")

    def __init__(
        self,
        service_type: Type,
        implementation: Optional[Type] = None,
        lifetime: Lifetime = Lifetime.TRANSIENT,
        factory: Optional[Callable] = None,
        instance: Optional[Any] = None,
    ):
        self.service_type = service_type
        self.implementation = implementation or service_type
        self.lifetime = lifetime
        self.factory = factory
        self.instance = instance


# ---------------------------------------------------------------------------
# Container
# ---------------------------------------------------------------------------

class Container:
    """IoC container with constructor injection and lifetime management."""

    def __init__(self, parent: Optional[Container] = None) -> None:
        self._registrations: Dict[Type, _Registration] = {}
        self._singletons: Dict[Type, Any] = {}
        self._lock = threading.RLock()
        self._parent = parent
        self._resolving: set = set()  # cycle detection

    # -- Registration helpers ------------------------------------------------

    def register(
        self,
        service_type: Type[T],
        implementation: Optional[Type[T]] = None,
        lifetime: Lifetime = Lifetime.TRANSIENT,
    ) -> Container:
        with self._lock:
            self._registrations[service_type] = _Registration(
                service_type=service_type,
                implementation=implementation or service_type,
                lifetime=lifetime,
            )
        return self

    def register_singleton(
        self,
        service_type: Type[T],
        implementation: Optional[Type[T]] = None,
    ) -> Container:
        return self.register(service_type, implementation, Lifetime.SINGLETON)

    def register_transient(
        self,
        service_type: Type[T],
        implementation: Optional[Type[T]] = None,
    ) -> Container:
        return self.register(service_type, implementation, Lifetime.TRANSIENT)

    def register_scoped(
        self,
        service_type: Type[T],
        implementation: Optional[Type[T]] = None,
    ) -> Container:
        return self.register(service_type, implementation, Lifetime.SCOPED)

    def register_instance(self, service_type: Type[T], instance: T) -> Container:
        with self._lock:
            reg = _Registration(
                service_type=service_type,
                lifetime=Lifetime.SINGLETON,
                instance=instance,
            )
            self._registrations[service_type] = reg
            self._singletons[service_type] = instance
        return self

    def register_factory(
        self,
        service_type: Type[T],
        factory: Callable[[Container], T],
        lifetime: Lifetime = Lifetime.TRANSIENT,
    ) -> Container:
        with self._lock:
            self._registrations[service_type] = _Registration(
                service_type=service_type,
                lifetime=lifetime,
                factory=factory,
            )
        return self

    # -- Resolution ----------------------------------------------------------

    def resolve(self, service_type: Type[T]) -> T:
        with self._lock:
            return self._resolve_internal(service_type)

    def _resolve_internal(self, service_type: Type[T]) -> T:
        # Cycle detection
        if service_type in self._resolving:
            chain = " -> ".join(t.__name__ for t in self._resolving)
            raise RuntimeError(f"Circular dependency detected: {chain} -> {service_type.__name__}")

        reg = self._registrations.get(service_type)
        if reg is None:
            if self._parent:
                return self._parent.resolve(service_type)
            raise KeyError(f"Service {service_type.__name__} is not registered")

        # Return existing singleton
        if reg.lifetime == Lifetime.SINGLETON and service_type in self._singletons:
            return self._singletons[service_type]

        # Pre-set instance
        if reg.instance is not None:
            return reg.instance

        self._resolving.add(service_type)
        try:
            instance = self._create_instance(reg)
        finally:
            self._resolving.discard(service_type)

        if reg.lifetime == Lifetime.SINGLETON:
            self._singletons[service_type] = instance

        return instance

    def _create_instance(self, reg: _Registration) -> Any:
        if reg.factory:
            return reg.factory(self)

        impl = reg.implementation
        # Prefer get_type_hints (resolves forward refs) with fallback
        try:
            import typing
            hints = typing.get_type_hints(impl.__init__)
        except Exception:
            sig = inspect.signature(impl.__init__)
            hints = {
                k: v.annotation
                for k, v in sig.parameters.items()
                if k != "self" and v.annotation is not inspect.Parameter.empty
            }
        hints.pop("return", None)
        kwargs: Dict[str, Any] = {}
        for name, hint in hints.items():
            if isinstance(hint, str):
                continue  # unresolvable forward ref, skip
            if self.is_registered(hint) or (self._parent and self._parent.is_registered(hint)):
                kwargs[name] = self._resolve_internal(hint)
        return impl(**kwargs)

    # -- Queries -------------------------------------------------------------

    def is_registered(self, service_type: Type) -> bool:
        return service_type in self._registrations

    def create_scope(self) -> ScopedContainer:
        return ScopedContainer(self)

    def clear(self) -> None:
        with self._lock:
            self._registrations.clear()
            self._singletons.clear()


# ---------------------------------------------------------------------------
# Scoped container
# ---------------------------------------------------------------------------

class ScopedContainer(Container):
    """Child container that holds scoped instances and delegates to parent."""

    def __init__(self, parent: Container) -> None:
        super().__init__(parent=parent)
        self._scoped_instances: Dict[Type, Any] = {}

    def _resolve_internal(self, service_type: Type[T]) -> T:
        reg = self._registrations.get(service_type)
        if reg is None and self._parent:
            reg = self._parent._registrations.get(service_type)

        if reg and reg.lifetime == Lifetime.SCOPED:
            if service_type in self._scoped_instances:
                return self._scoped_instances[service_type]
            instance = self._parent._create_instance(reg) if self._parent else super()._create_instance(reg)
            self._scoped_instances[service_type] = instance
            return instance

        return super()._resolve_internal(service_type)

    def dispose(self) -> None:
        for inst in self._scoped_instances.values():
            if hasattr(inst, "dispose"):
                inst.dispose()
        self._scoped_instances.clear()


# ---------------------------------------------------------------------------
# Abstract base classes for services
# ---------------------------------------------------------------------------

class Service(ABC):
    """Optional base for services that need lifecycle hooks."""

    @abstractmethod
    def initialize(self) -> None: ...

    def dispose(self) -> None:
        pass


class ServiceProvider(ABC):
    """Groups related service registrations."""

    @abstractmethod
    def register_services(self, container: Container) -> None: ...


# ---------------------------------------------------------------------------
# Global container singleton
# ---------------------------------------------------------------------------

_global_container: Optional[Container] = None
_global_lock = threading.Lock()


def get_container() -> Container:
    global _global_container
    with _global_lock:
        if _global_container is None:
            _global_container = Container()
        return _global_container


def set_container(container: Container) -> None:
    global _global_container
    with _global_lock:
        _global_container = container


def inject(service_type: Type[T]) -> T:
    return get_container().resolve(service_type)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def injectable(cls: Type[T]) -> Type[T]:
    """Mark a class for auto-registration as TRANSIENT."""
    cls.__hellcat_lifetime__ = Lifetime.TRANSIENT
    return cls


def singleton(cls: Type[T]) -> Type[T]:
    """Mark a class for auto-registration as SINGLETON."""
    cls.__hellcat_lifetime__ = Lifetime.SINGLETON
    return cls


def scoped(cls: Type[T]) -> Type[T]:
    """Mark a class for auto-registration as SCOPED."""
    cls.__hellcat_lifetime__ = Lifetime.SCOPED
    return cls


def configure_services(container: Container, providers: List[ServiceProvider]) -> None:
    """Convenience: run multiple providers against one container."""
    for p in providers:
        p.register_services(container)
