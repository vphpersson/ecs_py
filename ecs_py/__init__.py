from __future__ import annotations
from dataclasses import dataclass, fields
from typing import Literal, Any, Final
from shlex import join as shlex_join
from pathlib import PurePath
from datetime import datetime
from abc import ABC
from re import compile as re_compile, Pattern as RePattern


_OPTIONAL_TYPE_PATTERN: Final[RePattern] = re_compile(pattern=r'^Optional\[([^]]+)\]$')


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
            field_type = globals()[_OPTIONAL_TYPE_PATTERN.sub(repl=r'\1', string=self.__annotations__[current_field_name])]

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

    def to_dict(self) -> dict[str, Any]:
        """
        Produce a `dict` from the ECS entry, removing fields with `None` as value.

        :return: A `dict` representation of ECS entry.
        """

        entry_dict: dict[str, Any] = dict()

        for field in fields(self):
            field_value = getattr(self, field.name)

            # Override for reserved field names.
            dict_field_name: str
            match field.name:
                case 'class_':
                    dict_field_name = 'class'
                case _:
                    dict_field_name = field.name

            if isinstance(field_value, ECSEntry):
                if field_value_dict := field_value.to_dict():
                    entry_dict[field.name] = field_value_dict
            else:
                if field_value is not None:
                    if isinstance(field_value, list):
                        dict_field_value = []
                        for element in field_value:
                            if isinstance(element, ECSEntry):
                                if element_dict := element.to_dict():
                                    dict_field_value.append(element_dict)
                            else:
                                dict_field_value.append(element)
                    else:
                        dict_field_value = field_value

                    entry_dict[dict_field_name] = dict_field_value

        return entry_dict


@dataclass
class Error(ECSEntry):
    code: str | None = None
    message: str | None = None
    id: str | None = None
    stack_trace: str | None = None
    type: str | None = None


@dataclass
class DNSAnswer(ECSEntry):
    class_: str | None = None
    data: str | None = None
    name: str | None = None
    ttl: int | None = None
    type: str | None = None


@dataclass
class DNSQuestion(ECSEntry):
    class_: str | None = None
    name: str | None = None
    registered_domain: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None
    type: str | None = None


@dataclass
class DNS(ECSEntry):
    answers: list[DNSAnswer] | None = None
    header_flags: list[str] | None = None
    id: str | None = None
    op_code: str | None = None
    question: DNSQuestion | None = None
    resolved_ip: list[str] | None = None
    response_code: str | None = None
    type: str | None = None


@dataclass
class OS(ECSEntry):
    family: str | None = None
    full: str | None = None
    kernel: str | None = None
    name: str | None = None
    platform: str | None = None
    type: Literal['linux', 'macos', 'unix', 'windows'] | None = None
    version: str | None = None


@dataclass
class Host(ECSEntry):
    architecture: str | None = None
    # cpu.*
    # disk.*
    domain: str | None = None
    # geo.*
    hostname: str | None = None
    id: str | None = None
    ip: list[str | None] = None
    mac: list[str | None] = None
    name: str | None = None
    # network.*
    type: str | None = None
    uptime: int | None = None
    os: OS | None = None


@dataclass
class ProcessThread(ECSEntry):
    id: int | None = None
    name: str | None = None


@dataclass
class Group(ECSEntry):
    domain: str | None = None
    id: str | None = None
    name: str | None = None
    # NOTE: Custom.
    effective: Group | None = None


@dataclass
class User(ECSEntry):
    domain: str | None = None
    email: str | None = None
    full_name: str | None = None
    hash: str | None = None
    id: str | None = None
    name: str | None = None
    roles: list[str | None] = None
    changes: User | None = None
    effective: User | None = None
    group: Group | None = None
    target: User | None = None


@dataclass
class Process(ECSEntry):
    args: list[str | None] = None
    arg_count: int | None = None
    command_line: str | None = None
    end: datetime | None = None
    entity_id: str | None = None
    executable: str | None = None
    exit_code: int | None = None
    name: str | None = None
    pgid: int | None = None
    pid: int | None = None
    start: datetime | None = None
    thread: ProcessThread | None = None
    title: str | None = None
    uptime: int | None = None
    working_directory: str | None = None
    parent: Process | None = None
    # NOTE: Custom.
    user: User | None = None
    # NOTE: Custom.
    group: Group | None = None

    # code_signature.*
    # elf.*
    # hash.*
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
    action: str | None = None
    agent_id_status: str | None = None
    category: list[str | None] = None
    code: str | None = None
    created: datetime | None = None
    dataset: str | None = None
    duration: int | None = None
    end: datetime | None = None
    hash: str | None = None
    id: str | None = None
    ingested: datetime | None = None
    kind: Literal['alert', 'enrichment', 'event', 'metric', 'state', 'pipeline_error', 'signal'] | None = None
    module: str | None = None
    original: str | None = None
    outcome: Literal['failure', 'success', 'unknown'] | None = None
    provider: str | None = None
    reason: str | None = None
    reference: str | None = None
    risk_score: float | None = None
    risk_score_norm: float | None = None
    sequence: int | None = None
    severity: str | None = None
    start: datetime | None = None
    timezone: str | None = None
    type: list[str | None] = None
    url: str | None = None


@dataclass
class LogSyslogSeverity(ECSEntry):
    code: int | None = None
    name: str | None = None


@dataclass
class LogSyslogFacility(ECSEntry):
    code: int | None = None
    name: str | None = None


@dataclass
class LogSyslog(ECSEntry):
    facility: LogSyslogFacility | None = None
    priority: int | None = None
    severity: LogSyslogSeverity | None = None


@dataclass
class LogOriginFile(ECSEntry):
    path: str | None = None
    name: str | None = None
    line: int | None = None


@dataclass
class LogOrigin(ECSEntry):
    file: LogOriginFile | None = None
    function: str | None = None


@dataclass
class LogFile(ECSEntry):
    path: str | None = None


@dataclass
class Log(ECSEntry):
    level: str | None = None
    logger: str | None = None
    origin: LogOrigin | None = None


@dataclass
class DestinationNat(ECSEntry):
    ip: str | None = None
    port: str | None = None


@dataclass
class Destination(ECSEntry):
    address: str | None = None
    bytes: int | None = None
    domain: str | None = None
    ip: str | None = None
    mac: str | None = None
    # nat.*
    packets: int | None = None
    port: int | None = None
    registered_domain: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None
    # as.*
    # geo.*
    user: User | None = None


@dataclass
class SourceNat(ECSEntry):
    ip: str | None = None
    port: str | None = None


@dataclass
class Source(ECSEntry):
    address: str | None = None
    bytes: int | None = None
    domain: str | None = None
    ip: str | None = None
    mac: str | None = None
    # nat.*
    packets: int | None = None
    port: int | None = None
    registered_domain: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None
    # as.*
    # geo.*
    user: User | None = None


@dataclass
class HttpBody(ECSEntry):
    bytes: int | None = None
    content: str | None = None
    # Custom
    decompressed_content: str | None = None


@dataclass
class HttpRequest(ECSEntry):
    body: HttpBody | None = None
    # Custom
    headers: dict[str, list[str | None]] = None
    bytes: int | None = None
    id: str | None = None
    method: str | None = None
    mime_type: str | None = None
    # Custom
    content_type: list[str | None] = None
    referrer: str | None = None


@dataclass
class HttpResponse(ECSEntry):
    body: HttpBody | None = None
    # Custom
    headers: dict[str, str | None] = None
    bytes: int | None = None
    mime_type: str | None = None
    # Custom
    content_type: list[str | None] = None
    status_code: int | None = None
    # Custom
    reason_phrase: str | None = None


@dataclass
class Http(ECSEntry):
    request: HttpRequest | None = None
    response: HttpResponse | None = None
    version: str | None = None


@dataclass
class UserAgentDevice(ECSEntry):
    name: str | None = None


@dataclass
class UserAgent(ECSEntry):
    name: str | None = None
    original: str | None = None
    version: str | None = None
    os: OS | None = None


@dataclass
class Network(ECSEntry):
    application: str | None = None
    bytes: int | None = None
    community_id: str | None = None
    direction: Literal['ingress', 'egress', 'inbound', 'outbound', 'internal', 'external', 'unknown'] | None = None
    forwarded_ip: str | None = None
    iana_number: str | None = None
    # inner
    name: str | None = None
    packets: int | None = None
    protocol: str | None = None
    transport: str | None = None
    type: str | None = None
    # inner.vlan.*
    # vlan.*


@dataclass
class URL(ECSEntry):
    domain: str | None = None
    extension: str | None = None
    fragment: str | None = None
    full: str | None = None
    original: str | None = None
    password: str | None = None
    path: str | None = None
    port: int | None = None
    query: str | None = None
    registered_domain: str | None = None
    scheme: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None
    username: str | None = None
    # Custom
    query_keys: list[str | None] = None
    query_values: list[str | None] = None


@dataclass
class Client(ECSEntry):
    address: str | None = None
    bytes: int | None = None
    domain: str | None = None
    ip: str | None = None
    mac: str | None = None
    # nat.*
    packets: int | None = None
    port: int | None = None
    registered_domain: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None
    # as.*
    # geo.*
    user: User | None = None


@dataclass
class Server(ECSEntry):
    address: str | None = None
    bytes: int | None = None
    domain: str | None = None
    ip: str | None = None
    mac: str | None = None
    # nat.*
    packets: int | None = None
    port: int | None = None
    registered_domain: str | None = None
    subdomain: str | None = None
    top_level_domain: str | None = None
    # as.*
    # geo.*
    user: User | None = None


@dataclass
class Base(ECSEntry):
    client: Client | None = None
    error: Error | None = None
    event: Event | None = None
    destination: Destination | None = None
    dns: DNS | None = None
    group: Group | None = None
    host: Host | None = None
    http: Http | None = None
    log: Log | None = None
    network: Network | None = None
    process: Process | None = None
    server: Server | None = None
    source: Source | None = None
    url: URL | None = None
    user: User | None = None
    user_agent: UserAgent | None = None
    message: str | None = None
