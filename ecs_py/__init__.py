from __future__ import annotations
from dataclasses import dataclass, fields
from typing import Literal, Any, Final, Self
from shlex import join as shlex_join
from pathlib import PurePath
from datetime import datetime
from abc import ABC
from re import compile as re_compile, Pattern as RePattern
from warnings import warn
from json import dumps as json_dumps
from copy import deepcopy

_OPTIONAL_TYPE_PATTERN: Final[RePattern] = re_compile(pattern=r'^([^ |]+)\s*\|\s*None$')


def _json_dumps_default(obj: Any):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.decode()
    elif isinstance(obj, memoryview):
        return obj.tobytes().decode()

    raise TypeError(f'Unexpected dumps type: {type(obj)}')


@dataclass
class ECSEntry(ABC):

    def _get_namespace(self, field_name: str, create_namespaces: bool = False) -> Self:
        if not field_name:
            return self
        elif '.' in field_name:
            current_field_name, remaining_field_name = field_name.split(sep='.', maxsplit=1)
        else:
            current_field_name = field_name
            remaining_field_name = ''

        if (field_value := getattr(self, current_field_name)) is None:
            if create_namespaces:
                field_type = globals()[_OPTIONAL_TYPE_PATTERN.sub(repl=r'\1', string=self.__annotations__[current_field_name])]
                if issubclass(field_type, ECSEntry):
                    created_namespace: ECSEntry = field_type()
                    setattr(self, current_field_name, created_namespace)
                    return created_namespace._get_namespace(
                        field_name=remaining_field_name,
                        create_namespaces=create_namespaces
                    )
                else:
                    raise ValueError(
                        'A namespace cannot be created for the field name because a non-namespace type is reached: '
                        f'{field_name}'
                    )
            else:
                raise ValueError(f'A namespace cannot be resolved because a None is reached: {field_name}')
        elif isinstance(field_value, ECSEntry):
            return field_value._get_namespace(field_name=remaining_field_name, create_namespaces=create_namespaces)
        else:
            raise ValueError(
                'A namespace cannot be resolved because a non-namespace type is reached: '
                f'{field_name}'
            )

    def _get_namespace_and_field(self, field_name: str, create_namespaces: bool = False) -> tuple[Self, str]:
        if not field_name:
            raise ValueError('No field name provided.')

        namespace_selector: str
        last_field_name_list: list[str]
        namespace_selector, *last_field_name_list = field_name.rsplit(sep='.', maxsplit=1)

        namespace = self._get_namespace(field_name=namespace_selector, create_namespaces=create_namespaces)
        last_field_name = next(iter(last_field_name_list), namespace_selector)

        return namespace, last_field_name

    def set_field_value(self, field_name: str, value: Any, create_namespaces: bool = True) -> None:
        """
        Set a field name to a value.

        :param field_name: The field name to be set.
        :param value: The value to set.
        :param create_namespaces: Whether to create the namespace that does not already exist when resolving the field
            name.
        :return: None.
        """

        if '.' in field_name:
            namespace, last_field_name = self._get_namespace_and_field(
                field_name=field_name,
                create_namespaces=create_namespaces
            )

            if field_name == last_field_name:
                namespace = self
        else:
            namespace = self
            last_field_name = field_name

        if not hasattr(namespace, last_field_name):
            raise ValueError(f'The namespace does not have the attribute {last_field_name}')

        setattr(namespace, last_field_name, value)

    def get_field_value(self, field_name: str, create_namespaces: bool = False) -> Any:
        """
        Retrieve the value corresponding to the provided field name.

        :param field_name: A field name whose value to retrieve.
        :param create_namespaces: Whether to create the namespace that does not already exist when resolving the field
            name.
        :return: The value corresponding to the provided field name.
        """

        namespace, last_field_name = self._get_namespace_and_field(
            field_name=field_name,
            create_namespaces=create_namespaces
        )

        if field_name == last_field_name:
            return namespace

        return getattr(namespace, last_field_name)

    def assign(self, value_dict: dict[str, Any], create_namespaces: bool = True):
        for key, value in value_dict.items():
            self.set_field_value(field_name=key, value=value, create_namespaces=create_namespaces)

    def _to_dict(self) -> dict[str, Any]:
        """
        Produce a `dict` from the ECS entry, removing fields with `None` as value.

        :return: A `dict` representation of ECS entry.
        """

        entry_dict: dict[str, Any] = dict()

        for field in fields(self):
            field_value = getattr(self, field.name)

            dict_field_name: str = field.name.rstrip('_')

            if isinstance(field_value, ECSEntry):
                if field_value_dict := field_value._to_dict():
                    entry_dict[dict_field_name] = field_value_dict
            else:
                if field_value is not None:
                    if isinstance(field_value, list):
                        dict_field_value = []
                        for element in field_value:
                            if isinstance(element, ECSEntry):
                                if element_dict := element._to_dict():
                                    dict_field_value.append(element_dict)
                            else:
                                dict_field_value.append(element)
                    else:
                        dict_field_value = field_value

                    entry_dict[dict_field_name] = dict_field_value

        return entry_dict

    def to_dict(self) -> dict[str, Any]:
        """
        Produce a `dict` from the ECS entry, removing fields with `None` as value.

        :return: A `dict` representation of ECS entry.
        """

        warn('To be deprecated. Use `dict()` instead.', PendingDeprecationWarning)
        return self._to_dict()

    def __iter__(self):
        # NOTE: Is this actually the expected type of the returned values?
        return iter(self._to_dict().items())

    def __len__(self) -> int:
        return sum(
            bool(getattr(self, field.name))
            for field in fields(self)
        )

    def __str__(self) -> str:
        return json_dumps(self._to_dict(), default=_json_dumps_default)

    def __or__(self, other: Self) -> Self:
        if not isinstance(other, ECSEntry):
            raise NotImplemented(f'__or__ is not implemented for types other than {self.__class__.__name__}.')

        new: ECSEntry = deepcopy(self)
        return _merge(a=new, b=other)

    def __ior__(self, other: Self) -> Self:
        if not isinstance(other, ECSEntry):
            raise NotImplemented(f'__ior__ is not implemented for types other than {self.__class__.__name__}.')

        return _merge(a=self, b=other)


def _merge(a: ECSEntry, b: ECSEntry) -> ECSEntry:

    if (a_type := type(a)) is not (b_type := type(b)):
        raise TypeError(f'The ECS entry types are not the same: "{a_type}", "{b_type}"')

    b_key_value_pairs = tuple((field.name, getattr(b, field.name)) for field in fields(b))

    for key, b_value in b_key_value_pairs:
        if isinstance(a_value := getattr(a, key, None), ECSEntry) and isinstance(b_value, ECSEntry):
            _merge(a_value, b_value)
        elif b_value is not None:
            setattr(a, key, b_value)

    return a


@dataclass
class Error(ECSEntry):
    code: str | None = None
    message: str | None = None
    id: str | None = None
    stack_trace: str | None = None
    type: str | None = None
    # NOTE: Custom
    input: str | None = None


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
class Hash(ECSEntry):
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    sha384: str | None = None
    sha512: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None


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
class Interface(ECSEntry):
    alias: str | None = None
    id: str | None = None
    name: str | None = None


@dataclass
class ObserverIngressEgress(ECSEntry):
    interface: Interface | None = None
    # vlan.*
    zone: str | None = None


@dataclass
class Observer(ECSEntry):
    egress: ObserverIngressEgress | None = None
    # geo.*
    hostname: str | None = None
    ingress: ObserverIngressEgress | None = None
    ip: str | None = None
    mac: str | None = None
    name: str | None = None
    os: OS | None = None
    product: str | None = None
    serial_number: str | None = None
    type: str | None = None
    vendor: str | None = None
    version: str | None = None


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
    # NOTE: Custom
    process: Process | None = None


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
    headers: dict[str, str] | None = None
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
class TLSClient(ECSEntry):
    certificate: str | None = None
    certificate_chain: list[str] | None = None
    hash: Hash | None = None
    issuer: str | None = None
    ja3: str | None = None
    # NOTE: Custom.
    ja3_full: str | None = None
    # NOTE: Custom
    ja3_ssl_version: str | None = None
    # NOTE: Custom
    ja3_cipher: str | None = None
    # NOTE: Custom
    ja3_ssl_extension: str | None = None
    # NOTE: Custom
    ja3_elliptic_curve: str | None = None
    # NOTE: Custom
    ja3_elliptic_curve_point_format: str | None = None
    not_after: str | None = None
    not_before: str | None = None
    server_name: str | None = None
    subject: str | None = None
    supported_ciphers: list[str] | None = None


@dataclass
class TLSServer(ECSEntry):
    certificate: str | None = None
    certificate_chain: list[str] | None = None
    hash: Hash | None = None
    issuer: str | None = None
    ja3s: str | None = None
    not_after: str | None = None
    not_before: str | None = None
    subject: str | None = None


@dataclass
class TLS(ECSEntry):
    cipher: str | None = None
    client: TLSClient | None = None
    curve: str | None = None
    established: bool | None = None
    # TODO: Should be a list?
    next_protocol: str | None = None
    resumed: bool | None = None
    server: TLSServer | None = None
    version: str | None = None
    version_protocol: str | None = None


# NOTE: Custom.
@dataclass
class ICMP(ECSEntry):
    version: str | None = None
    type: int | None = None
    type_str: str | None = None
    code: int | None = None
    code_str: str | None = None
    transport: str | None = None
    application: str | None = None


@dataclass
class EmailAttachmentFile(ECSEntry):
    # NOTE: Custom.
    content: str | None = None
    extension: str | None = None
    hash: Hash | None = None
    mime_type: str | None = None
    name: str | None = None
    size: int | None = None


@dataclass
class EmailAttachment(ECSEntry):
    file: EmailAttachmentFile | None = None


@dataclass
class BCC(ECSEntry):
    # NOTE: Custom.
    name: list[str | None] | None = None
    address: list[str] = None


@dataclass
class CC(ECSEntry):
    # NOTE: Custom.
    name: list[str | None] | None = None
    address: list[str] = None


@dataclass
class From(ECSEntry):
    # NOTE: Custom.
    name: list[str | None] | None = None
    address: list[str] | None = None


@dataclass
class ReplyTo(ECSEntry):
    # NOTE: Custom.
    name: list[str | None] | None = None
    address: list[str | None] | None = None


@dataclass
class Sender(ECSEntry):
    address: str | None = None


@dataclass
class To(ECSEntry):
    # NOTE: Custom.
    name: list[str | None] | None = None
    address: list[str] | None = None

# NOTE: Custom
@dataclass
class SMTPEnhancedStatusCode(ECSEntry):
    class_: str | None = None
    class_text: str | None = None
    subject: str | None = None
    subject_text: str | None = None
    detail: str | None = None
    detail_text: str | None = None
    original: str | None = None

# NOTE: Custom
@dataclass
class SMTPResponse(ECSEntry):
    status_code: str | None = None
    enhanced_status_code: SMTPEnhancedStatusCode | None = None
    lines: list[str] | None = None


# NOTE: Custom
@dataclass
class SMTPRequest(ECSEntry):
    command: str | None = None
    arguments_string: str | None = None


# NOTE: Custom
@dataclass
class SMTPExchange(ECSEntry):
    request: SMTPRequest | None = None
    response: SMTPResponse | None = None


# NOTE: Custom
@dataclass
class SMTPTranscript(ECSEntry):
    exchange: list[SMTPExchange] | None = None
    original: str | None = None


# NOTE: Custom
@dataclass
class SMTP(ECSEntry):
    ehlo: str | None = None
    mail_from: str | None = None
    rcpt_to: str | None = None
    transcript: SMTPTranscript | None = None


@dataclass
class EmailBody(ECSEntry):
    content_type: str | None = None
    content: str | None = None
    size: int | None = None


@dataclass
class Email(ECSEntry):
    attachments: list[EmailAttachment] | None = None
    # NOTE: Custom
    bodies: list[EmailBody] | None = None
    bcc: BCC | None = None
    cc: CC | None = None
    content_type: str | None = None
    delivery_timestamp: datetime | None = None
    direction: str | None = None
    from_: From | None = None
    # NOTE: Custom
    headers: dict[str, list[str]] | None = None
    local_id: str | None = None
    message_id: str | None = None
    origination_timestamp: datetime | None = None
    # NOTE: Custom
    raw_headers: str | None = None
    reply_to: ReplyTo | None = None
    sender: Sender | None = None
    subject: str | None = None
    to: To | None = None
    x_mailer: str | None = None
    # NOTE: Custom
    x_original_ip: str | None = None
    # NOTE: Custom
    x_user_agent: str | None = None


# NOTE: Custom.
@dataclass
class TCP(ECSEntry):
    flags: list[str] | None = None
    acknowledgement_number: int | None = None
    sequence_number: int | None = None


@dataclass
class Related(ECSEntry):
    hash: list[str] | None = None
    hosts: list[str] | None = None
    ip: list[str] | None = None
    user: list[str] | None = None


@dataclass
class Rule(ECSEntry):
    author: str | None = None
    category: str | None = None
    description: str | None = None
    id: str | None = None
    license: str | None = None
    name: str | None = None
    reference: str | None = None
    ruleset: str | None = None
    uuid: str | None = None
    version: str | None = None


@dataclass
class Base(ECSEntry):
    client: Client | None = None
    email: Email | None = None
    error: Error | None = None
    event: Event | None = None
    destination: Destination | None = None
    dns: DNS | None = None
    group: Group | None = None
    host: Host | None = None
    http: Http | None = None
    # NOTE: Custom.
    icmp: ICMP | None = None
    log: Log | None = None
    network: Network | None = None
    observer: Observer | None = None
    process: Process | None = None
    related: Related | None = None
    rule: Rule | None = None
    server: Server | None = None
    # NOTE Custom.
    smtp: SMTP | None = None
    source: Source | None = None
    # NOTE: Custom
    tcp: TCP | None = None
    tls: TLS | None = None
    url: URL | None = None
    user: User | None = None
    user_agent: UserAgent | None = None
    message: str | None = None
