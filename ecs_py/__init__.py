from dataclasses import dataclass
from typing import Optional, Literal
from shlex import join as shlex_join
from pathlib import PurePath
from datetime import datetime


@dataclass
class Error:
    code: Optional[str] = None
    message: Optional[str] = None
    id: Optional[str] = None
    stack_trace: Optional[str] = None
    type: Optional[str] = None


@dataclass
class OS:
    family: Optional[str] = None
    full: Optional[str] = None
    kernel: Optional[str] = None
    name: Optional[str] = None
    platform: Optional[str] = None
    type: Optional[Literal['linux', 'macos', 'unix', 'windows']] = None
    version: Optional[str] = None


@dataclass
class Host:
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
class ProcessThread:
    id: Optional[int] = None
    name: Optional[str] = None


@dataclass
class Process:
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
class Event:
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
class LogSyslogSeverity:
    code: Optional[int] = None
    name: Optional[str] = None


@dataclass
class LogSyslogFacility:
    code: Optional[int] = None
    name: Optional[str] = None


@dataclass
class LogSyslog:
    facility: Optional[LogSyslogFacility] = None
    priority: Optional[int] = None
    severity: Optional[LogSyslogSeverity] = None


@dataclass
class LogOriginFile:
    path: Optional[str] = None
    name: Optional[str] = None
    line: Optional[int] = None


@dataclass
class LogOrigin:
    file: LogOriginFile
    function: str


@dataclass
class LogFile:
    path: Optional[str] = None


@dataclass
class Log:
    level: Optional[str] = None
    logger: Optional[str] = None
    origin: Optional[LogOrigin] = None


@dataclass
class Base:
    error: Optional[Error] = None
    event: Optional[Event] = None
    host: Optional[Host] = None
    log: Optional[Log] = None
    process: Optional[Process] = None
    message: Optional[str] = None
