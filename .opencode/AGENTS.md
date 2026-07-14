# ZT Agentic Gateway — Project Knowledge

## Location
- `D:\zt agenticv`
- GitHub: `https://github.com/Tamerktb/ZT-Agentic-gateway.git`
- Branch: `master`

## Dual Mode Architecture

### Smol Mode (personal)
- Single process: `pip install zt-gateway && zt-gateway`
- Package: `zt_gateway/` — Entry: `zt_gateway/cli.py`
- All 6 services collapsed into one FastAPI app in `zt_gateway/smol_app.py`
- SQLite databases in `.data/` directory
- Verify: `python test_smol.py` (23 tests)

### Enterprise Mode (production)
- Docker Compose: `docker-compose.prod.yml`
- 6 separate microservices in `services/`
- Terraform deployment in `terraform/`
- Wazuh SIEM rules in `monitoring/`
- Verify: `python test_integration.py` (24 tests)

## Common Workflows

### After making changes
```
cd D:\zt agenticv
git add -A
git commit -m "descriptive message"
git push origin master
```

### Update README checklist
- Add new features to Quick Start order (smol first, then enterprise)
- Update project structure tree
- Update tests badge if count changed
- Keep dual-mode pitch at the top

## Key Files
| File | Purpose |
|------|---------|
| `zt_gateway/smol_app.py` | Smol mode — all services in one process |
| `zt_gateway/cli.py` | CLI `--mode smol|prod|demo` |
| `pyproject.toml` | Pip packaging |
| `test_smol.py` | Smol mode 23-test suite |
| `test_integration.py` | Enterprise 24-test suite |
| `services/` | Enterprise microservices (Docker) |
| `shared/production.py` | Shared utils (metrics, logging, headers) |
| `ui/` | Web dashboard |

## Credential Helper
- GitHub credentials should be configured via `git config --global credential.helper`
- Push with: `git push origin master`
