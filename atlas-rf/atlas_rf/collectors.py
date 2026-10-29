"""Compatibility imports for the original atlas-rf CLI."""
import asyncio
from atlas.core.process import run
from atlas.core.diagnostics import legacy_doctor as doctor
from atlas.wifi.collector import wifi, split_nm
from atlas.bluetooth.collector import ble
from atlas.network.collector import network, targets, probe
