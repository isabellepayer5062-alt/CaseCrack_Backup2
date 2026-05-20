import urllib.request, json
req = urllib.request.Request("http://localhost:8770/api/standalone/status", headers={"Authorization": "Bearer mpogZXAS82-WoTm6_5evKtWQlQUIt23KVCxTV73qoY0"})
r = urllib.request.urlopen(req, timeout=10)
data = json.loads(r.read())
running = [p["name"] for p in data["phases"] if p["status"] == "running"]
done = [p["name"] for p in data["phases"] if p["status"] == "done"]
print(f"Phase: {data['phases_done']}/{data['phases_total']} | findings={data['findings_count']} | complete={data['is_complete']}")
print(f"Running: {running}")
