"""Guest network observations and explicit bounded TCP probes."""
import asyncio
import ipaddress
import json
import math
from atlas.core.events import now
from atlas.core.process import run

def network():
    when = now()
    observations = []
    for row in json.loads(run(['ip', '-j', 'neigh', 'show'])):
        if row.get('dst') and row.get('lladdr') and not set(row.get('state', [])) & {'FAILED', 'INCOMPLETE'}:
            observations.append(dict(kind='neighbor', id=row['dst'], ip=row['dst'], mac=row['lladdr'],
                                     interface=row.get('dev', ''), observed_at=when, source='guest:ip-neigh'))
    for row in json.loads(run(['ip', '-j', 'route', 'show'])):
        if row.get('gateway'):
            observations.append(dict(kind='route', id=f"{row.get('dst', 'default')}@{row.get('dev', '')}",
                                     gateway=row['gateway'], interface=row.get('dev', ''),
                                     observed_at=when, source='guest:ip-route'))
    return observations


def targets(scopes):
    hosts = set()
    for scope in scopes:
        if '%' in scope:
            raise ValueError('zone identifiers are unsupported')
        try:
            net = ipaddress.ip_network(scope, strict=False)
        except ValueError as exc:
            raise ValueError('scope must be a literal IP or CIDR, not a hostname') from exc
        if net.num_addresses > 256:
            raise ValueError('each scope is limited to 256 addresses')
        for host in net.hosts():
            if host.is_multicast or host.is_unspecified or host.is_link_local or host.is_reserved:
                raise ValueError('multicast, unspecified, reserved and link-local targets are unsupported')
            hosts.add(str(host))
        if len(hosts) > 256:
            raise ValueError('combined scope is limited to 256 hosts')
    return sorted(hosts)


async def probe(scopes, ports, timeout=0.7, concurrency=16):
    hosts = targets(scopes)
    if not ports or len(set(ports)) > 32 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError('provide 1..32 TCP ports between 1 and 65535')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.05 <= timeout <= 5 or type(concurrency) is not int or not 1 <= concurrency <= 32:
        raise ValueError('timeout must be 0.05..5 seconds; concurrency 1..32')
    queue = asyncio.Queue()
    for host in hosts:
        for port in sorted(set(ports)):
            queue.put_nowait((host, port))
    observations = []
    async def worker():
        while not queue.empty():
            host, port = queue.get_nowait()
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
                writer.close()
                await writer.wait_closed()
                observations.append(dict(kind='service', id=f'{host}/tcp/{port}', ip=host,
                                         port=port, observed_at=now(), source='guest:tcp-connect'))
            except PermissionError as exc:
                raise ValueError('TCP sockets denied by the environment; no reachability conclusion is possible') from exc
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                queue.task_done()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    return observations, {"hosts": len(hosts), "ports": len(set(ports)), "attempts": len(hosts) * len(set(ports)),
                          "open": len(observations), "scope": scopes,
                          "note": "Successful TCP connects only. No service fingerprinting; unresponsive hosts may exist."}
