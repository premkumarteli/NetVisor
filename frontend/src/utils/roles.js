export const ADMIN_ROLES = ["org_admin", "super_admin"];
export const OPERATOR_ROLES = ["org_admin", "super_admin", "operator"];
export const ALL_ROLES = ["org_admin", "super_admin", "operator", "viewer"];

export function isAdminRole(role) {
  return ADMIN_ROLES.includes(role);
}

export function isOperatorRole(role) {
  return OPERATOR_ROLES.includes(role);
}

export function isAllowedRole(userRole, allowedRoles) {
  if (!allowedRoles || allowedRoles.length === 0) return true;
  return allowedRoles.includes(userRole);
}
