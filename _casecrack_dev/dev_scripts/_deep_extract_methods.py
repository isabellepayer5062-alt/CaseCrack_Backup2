#!/usr/bin/env python3
"""Deep extraction of methods from minified catalog bundle"""
import re

print("Loading catalog bundle...")
with open("_catalog_bundle_D1Me60L7.js", "r", encoding="utf-8", errors="replace") as f:
    bundle = f.read()
print(f"Bundle size: {len(bundle)} chars")

# 1. Extract context around InsecureAuthAdmin and InsecureAccessManagerAPI
print("\n=== InsecureAuthAdmin context ===")
for match in re.finditer(r'InsecureAuthAdmin.{0,500}', bundle):
    print(match.group()[:500])
    print("---")

print("\n=== InsecureAccessManagerAPI context ===")  
for match in re.finditer(r'InsecureAccessManagerAPI.{0,500}', bundle):
    print(match.group()[:500])
    print("---")

print("\n=== ImpersonateTestPermissions context ===")
for match in re.finditer(r'.{200}ImpersonateTestPermissions.{400}', bundle):
    print(match.group()[:700])
    print("---")

print("\n=== ListPoliciesForPrincipalInsecure context ===")
for match in re.finditer(r'.{100}ListPoliciesForPrincipalInsecure.{200}', bundle):
    print(match.group()[:500])
    print("---")

# 2. Find all method names in class-like patterns
# Look for protobuf service method patterns
# Pattern: method names appear as "this.MethodName = this.MethodName.bind(this)"
method_binds = re.findall(r'this\.([A-Z][a-zA-Z]+)\s*=\s*this\.\1\.bind\(this\)', bundle)
print(f"\n=== Method bind patterns ({len(method_binds)}) ===")
for m in sorted(set(method_binds)):
    print(f"  {m}")

# 3. Pattern: this.MethodName = function or this.MethodName(n,t,d){return this.rpc.
method_rpc = re.findall(r'this\.([A-Z][a-zA-Z]+)\s*\(n,t,d\)\s*\{return this\.rpc\.', bundle)
print(f"\n=== RPC method patterns ({len(method_rpc)}) ===")
for m in sorted(set(method_rpc)):
    print(f"  {m}")

# 4. Look for the class constructor that defines all the services
# Pattern: prototype.ServiceName = class or new X({serviceName: ...})
svc_patterns = re.findall(r'\.prototype\.([A-Za-z]+API|[A-Za-z]+Service|[A-Za-z]+Manager)\s*=', bundle)
print(f"\n=== Service prototype patterns ({len(svc_patterns)}) ===")
for s in sorted(set(svc_patterns)):
    print(f"  {s}")

# 5. Try to find method descriptors (method_desc or getMethodDesc patterns)
method_descs = re.findall(r'([A-Z][a-zA-Z]+)\.getMethodDesc\s*=', bundle)
print(f"\n=== getMethodDesc patterns ({len(method_descs)}) ===")
for m in sorted(set(method_descs)):
    print(f"  {m}")

# 6. Find all service names and their associated method objects
# The bundle format seems to use: serviceName:"anduril.xxx", and method names separately
# Let's look for method-like names near each service
for svc_match in re.finditer(r'"(anduril\.[^"]{5,60})"', bundle):
    svc = svc_match.group(1)
    if any(keyword in svc for keyword in ['InsecureAuth', 'InsecureAccess', 'DroneCommand', 'Interceptor', 'Mission', 'TaskManager', 'EntityManager']):
        start = max(0, svc_match.start() - 200)
        end = min(len(bundle), svc_match.end() + 500)
        context = bundle[start:end]
        print(f"\n=== Service '{svc}' context ===")
        print(context[:700])

# 7. Extract specific methods for drone + interceptor + insecure services
print("\n\n=== Drone/Interceptor/Mission/Insecure methods ===")
for keyword in ['Drone', 'Interceptor', 'Mission', 'Insecure', 'Auth', 'Token', 'Client']:
    matches = re.findall(rf'this\.([A-Z][a-zA-Z]*{keyword}[A-Za-z]*)\s*[=\(]', bundle)
    matches += re.findall(rf'this\.({keyword}[A-Za-z]+)\s*[=\(]', bundle)
    unique = sorted(set(matches))
    if unique:
        print(f"  {keyword} methods: {unique[:20]}")
