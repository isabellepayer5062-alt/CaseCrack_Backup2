import ast

FILEPATH = 'CaseCrack/tools/burp_enterprise/intel/github_deep_recon.py'

with open(FILEPATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the exact start/end line numbers dynamically
start_idx = None
end_idx = None
for i, line in enumerate(lines):
    if '    def search_gists(' in line and start_idx is None:
        start_idx = i
    if start_idx is not None and '    def close(self)' in line:
        end_idx = i
        break

print(f"Found search_gists at line {start_idx+1}, close() at line {end_idx+1}")

new_methods = [
    "    def search_gists(\n",
    "        self,\n",
    "        query: str,\n",
    "        per_page: int = 30,\n",
    "        page: int = 1,\n",
    "    ) -> list[dict[str, Any]] | None:\n",
    '        """Search gist content via GitHub code search.\n',
    "\n",
    "        GitHub code search indexes gist content. Results whose html_url\n",
    "        starts with ``https://gist.github.com/`` are gist hits. We\n",
    "        request the text-match accept header for highlighted fragments.\n",
    '        """\n',
    "        data = self.api_get(\n",
    '            "search/code",\n',
    '            params={"q": f"{query} in:file", "per_page": per_page, "page": page},\n',
    '            accept="application/vnd.github.text-match+json",\n',
    "        )\n",
    '        if data and "items" in data:\n',
    '            return data["items"]\n',
    "        return None\n",
    "\n",
    "    def search_gists_by_description(\n",
    "        self,\n",
    "        query: str,\n",
    "        per_page: int = 100,\n",
    "    ) -> list[dict[str, Any]] | None:\n",
    '        """Scan the public gist stream and filter by description keyword.\n',
    "\n",
    "        GitHub exposes ``GET /gists/public`` sorted by ``updated``.\n",
    "        We scan descriptions for the domain, complementing code-search\n",
    "        which only finds gists where the domain appears in file content.\n",
    '        """\n',
    "        data = self.api_get(\n",
    '            "gists/public",\n',
    '            params={"per_page": per_page},\n',
    "        )\n",
    "        if not isinstance(data, list):\n",
    "            return None\n",
    "        q_lower = query.lower()\n",
    "        return [\n",
    "            g for g in data\n",
    '            if q_lower in (g.get("description") or "").lower()\n',
    "        ]\n",
    "\n",
    "    def fetch_gist(\n",
    "        self,\n",
    "        gist_id: str,\n",
    "    ) -> dict[str, Any] | None:\n",
    '        """Fetch full gist metadata + file contents via ``GET /gists/{id}``."""\n',
    '        return self.api_get(f"gists/{gist_id}")\n',
    "\n",
    "    def list_gist_commits(\n",
    "        self,\n",
    "        gist_id: str,\n",
    "        per_page: int = 30,\n",
    "    ) -> list[dict[str, Any]] | None:\n",
    '        """List revision history for a gist (``GET /gists/{id}/commits``)."""\n',
    "        data = self.api_get(\n",
    '            f"gists/{gist_id}/commits",\n',
    '            params={"per_page": per_page},\n',
    "        )\n",
    "        return data if isinstance(data, list) else None\n",
    "\n",
    "    def fetch_gist_revision(\n",
    "        self,\n",
    "        gist_id: str,\n",
    "        sha: str,\n",
    "    ) -> dict[str, Any] | None:\n",
    '        """Fetch a specific historical revision (``GET /gists/{id}/{sha}``)."""\n',
    '        return self.api_get(f"gists/{gist_id}/{sha}")\n',
    "\n",
    "    def list_user_gists(\n",
    "        self,\n",
    "        user: str,\n",
    "        per_page: int = 30,\n",
    "    ) -> list[dict[str, Any]] | None:\n",
    '        """``GET /users/{user}/gists``."""\n',
    '        data = self.api_get(f"users/{user}/gists", params={"per_page": per_page})\n',
    "        return data if isinstance(data, list) else None\n",
    "\n",
]

new_lines = lines[:start_idx] + new_methods + lines[end_idx:]
with open(FILEPATH, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Replaced {end_idx - start_idx} old lines with {len(new_methods)} new lines")

with open(FILEPATH, 'r', encoding='utf-8') as f:
    src = f.read()
try:
    ast.parse(src)
    print("Syntax OK")
except SyntaxError as e:
    print(f"SyntaxError: {e}")
