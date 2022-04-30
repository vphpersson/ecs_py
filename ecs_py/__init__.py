from dataclasses import dataclass, fields
from typing import Optional, Literal, Any
from shlex import join as shlex_join
from pathlib import PurePath
from datetime import datetime
from abc import ABC


@dataclass
class ECSEntry(ABC):

    def get_field_value(self, field_name: str, create_namespaces: bool = False) -> Any:
        """
        Retrieve the value corresponding to the provided field name.

        :param field_name: A field name whose value to retrieve.
        :param create_namespaces: Whether to create the namespace that does not already exist when resolving the field
            name.
        :return: The value corresponding to the provided field name.
        """

        if '.' in field_name:
            current_field_name, remaining_field_name = field_name.split(sep='.', maxsplit=1)
        else:
            current_field_name = field_name
            remaining_field_name = ''

        if not hasattr(self, current_field_name):
            raise ValueError(f'{self} does not have the field "{current_field_name}"')

        if (field_value := getattr(self, current_field_name)) is None:
            field_type = self.__annotations__[current_field_name].__args__[0]
            if issubclass(field_type, ECSEntry) and create_namespaces:
                created_namespace = field_type()
                setattr(self, current_field_name, created_namespace)

                return (
                    created_namespace.get_field_value(field_name=remaining_field_name)
                    if remaining_field_name else created_namespace
                )
            else:
                return None
        elif isinstance(field_value, ECSEntry) and remaining_field_name != '':
            return field_value.get_field_value(field_name=remaining_field_name)
        else:
            return field_value

    # TODO: What gets called when one runs `dict` on an object? Use that instead?

    def to_dict(self) -> dict[str, Any]:
        """
        Produce a `dict` from the ECS entry, removing fields with `None` as value.

        :return: A `dict` representation of ECS entry.
        """

        entry_dict: dict[str, Any] = dict()

        for field in fields(self):
            field_value = getattr(self, field.name)

            if isinstance(field_value, ECSEntry):
                if field_value_dict := field_value.to_dict():
                    entry_dict[field.name] = field_value_dict
            else:
                if field_value is not None:
                    entry_dict[field.name] = field_value

        return entry_dict


@dataclass
class Error(ECSEntry):
    code: Optional[str] = None
    message: Optional[str] = None
    id: Optional[str] = None
    stack_trace: Optional[str] = None
    type: Optional[str] = None


@dataclass
class OS(ECSEntry):
    family: Optional[str] = None
    full: Optional[str] = None
    kernel: Optional[str] = None
    name: Optional[str] = None
    platform: Optional[str] = None
    type: Optional[Literal['linux', 'macos', 'unix', 'windows']] = None
    version: Optional[str] = None


@dataclass
class Host(ECSEntry):
    architecture: Optional[str] = None
    # cpu.*
    # disk.*
    domain: Optional[str] = None
    # geo.*
    hostname: Optional[str] = None
    id: Optional[str] = None
    ip: Optional[list[str]] = None
    mac: Optional[list[str]] = None
    name: Optional[str] = None
    # network.*
    type: Optional[str] = None
    uptime: Optional[int] = None
    os: Optional[OS] = None


@dataclass
class ProcessThread(ECSEntry):
    id: Optional[int] = None
    name: Optional[str] = None


@dataclass
class Process(ECSEntry):
    args: Optional[list[str]] = None
    arg_count: Optional[int] = None
    command_line: Optional[str] = None
    end: Optional[datetime] = None
    entity_id: Optional[str] = None
    executable: Optional[str] = None
    exit_code: Optional[int] = None
    name: Optional[str] = None
    pgid: Optional[int] = None
    pid: Optional[int] = None
    start: Optional[datetime] = None
    thread: Optional[ProcessThread] = None
    title: Optional[str] = None
    uptime: Optional[int] = None
    working_directory: Optional[str] = None
    # code_signature.*
    # elf.*
    # hash.*
    # parent.*
    # pe.*

    def __post_init__(self):
        if self.command_line is None and self.args:
            self.command_line = shlex_join(self.args)

        if self.name is None and self.args:
            self.name = PurePath(self.args[0]).name

        if self.arg_count is None and self.args:
            self.arg_count = len(self.args)


@dataclass
class Event(ECSEntry):
    action: Optional[str] = None
    agent_id_status: Optional[str] = None
    category: Optional[list[str]] = None
    code: Optional[str] = None
    created: Optional[datetime] = None
    dataset: Optional[str] = None
    duration: Optional[int] = None
    end: Optional[datetime] = None
    hash: Optional[str] = None
    id: Optional[str] = None
    ingested: Optional[datetime] = None
    kind: Optional[Literal['alert', 'enrichment', 'event', 'metric', 'state', 'pipeline_error', 'signal']] = None
    module: Optional[str] = None
    original: Optional[str] = None
    outcome: Optional[Literal['failure', 'success', 'unknown']] = None
    provider: Optional[str] = None
    reason: Optional[str] = None
    reference: Optional[str] = None
    risk_score: Optional[float] = None
    risk_score_norm: Optional[float] = None
    sequence: Optional[int] = None
    severity: Optional[str] = None
    start: Optional[datetime] = None
    timezone: Optional[str] = None
    type: Optional[list[str]] = None
    url: Optional[str] = None


@dataclass
class LogSyslogSeverity(ECSEntry):
    code: Optional[int] = None
    name: Optional[str] = None


@dataclass
class LogSyslogFacility(ECSEntry):
    code: Optional[int] = None
    name: Optional[str] = None


@dataclass
class LogSyslog(ECSEntry):
    facility: Optional[LogSyslogFacility] = None
    priority: Optional[int] = None
    severity: Optional[LogSyslogSeverity] = None


@dataclass
class LogOriginFile(ECSEntry):
    path: Optional[str] = None
    name: Optional[str] = None
    line: Optional[int] = None


@dataclass
class LogOrigin(ECSEntry):
    file: Optional[LogOriginFile] = None
    function: Optional[str] = None


@dataclass
class LogFile(ECSEntry):
    path: Optional[str] = None


@dataclass
class Log(ECSEntry):
    level: Optional[str] = None
    logger: Optional[str] = None
    origin: Optional[LogOrigin] = None


@dataclass
class Base(ECSEntry):
    error: Optional[Error] = None
    event: Optional[Event] = None
    host: Optional[Host] = None
    log: Optional[Log] = None
    process: Optional[Process] = None
    message: Optional[str] = None
