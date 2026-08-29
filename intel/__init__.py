"""Shared domain and service classification helpers."""

from .app_classifier import (
    GENERIC_CERT_ORGS,
    MULTI_TENANT_SUFFIXES,
    clean_cert_org_to_app_name,
    clean_domain_to_app_name,
    clean_process_to_app_name,
    clean_title_to_app_name,
    infer_app_category,
)
from .domain_intelligence import classify_domain, get_service_info, is_noise, is_sensitive_destination
from .domain_utils import get_base_domain, normalize_host

__all__ = [
    "GENERIC_CERT_ORGS",
    "MULTI_TENANT_SUFFIXES",
    "clean_cert_org_to_app_name",
    "clean_domain_to_app_name",
    "clean_process_to_app_name",
    "clean_title_to_app_name",
    "infer_app_category",
    "classify_domain",
    "get_base_domain",
    "get_service_info",
    "is_noise",
    "is_sensitive_destination",
    "normalize_host",
]

