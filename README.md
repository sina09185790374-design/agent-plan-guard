# agent-plan-guard

A pre-flight safety gate + audit trail for autonomous agents — one Python file, stdlib only, no network.

**Pattern** (original code; pattern only, learned from today's radar): open-source AI-coworker platforms ship autonomy *with guardrails* — every action is decided in advance and recorded. This tool enforces that contract locally: an agent may only run the exact plan it declared up front. The guard checks every step against a policy **before** anything runs, refuses the whole plan on any violation (nothing is half-executed), and appends an audit record for every action it takes.

## How it works

1. Write a **plan** (`plan.example.json`): an ordered list of steps — `id`, `argv`, `cwd`, `timeout`, and a human-readable `note` explaining the action.
2. Write a **policy** (`policy.example.json`): denied binaries, denied argv patterns, optional strict binary allowlist, `max_timeout_seconds`, `allowed_roots` (cwd containment), `require_note`.
3. `review` the plan — the guard prints ALLOW/DENY per step and runs **nothing**.
4. `run` the plan — it runs **only** if every step is allowed; every action is appended to an append-only JSONL audit log (started → step_completed → finished), stamped with the plan's SHA-256 hash so the audit trail is tied to the exact plan that was reviewed.

## Usage

```bash
python3 agent_plan_guard.py review --plan plan.example.json --policy policy.example.json
python3 agent_plan_guard.py run    --plan plan.example.json --policy policy.example.json --audit audit.log.jsonl
```

Exit codes: `0` everything ran fine · `1` a step failed (audit still complete) · `2` bad input · `3` policy violation — the plan was refused and **nothing executed**.

## Safety rules (deliberate)

1. **Commands are argv lists, never shell strings.** There is no `shell=True` anywhere — `; rm -rf /` is a literal argument that fails, not a second command (enforced by a unit test).
2. **Refusal is all-or-nothing.** One denied step blocks the entire plan before any step runs.
3. **Working directories are contained** inside `allowed_roots` (symlink-resolved), so `../../..` escapes are denied.
4. **Secrets are flagged**, not executed: argv containing `--token/--password/--api-key` values is a policy violation.
5. **No network, no keys.** The guard never reads `.env` (see `.env.example`) and the audit log is a plain JSONL file you own.

## Tests

```bash
python3 -m unittest discover -s tests -v   # 21 tests, all green
```

## License

MIT — see `LICENSE`.

---

# agent-plan-guard (فارسی)

دروازه‌ی امنیتیِ «پیش از اجرا» + گزارش حسابرسی برای ایجنت‌های خودکار — فقط یک فایل پایتون، فقط کتابخانه استاندارد، بدون شبکه.

**الگو** (کد کاملاً اورجینال؛ فقط الگو از رادار امروز): پلتفرم‌های همکار هوش مصنوعی، خودمختاری را با «نرده‌های محافظ» می‌دهند — هر اقدام از قبل تصمیم‌گیری و ثبت می‌شود. این ابزار همان قرارداد را محلی اجرا می‌کند: ایجنت فقط می‌تواند همان برنامه‌ای را اجرا کند که از قبل اعلام کرده. نگهبان همه‌ی گام‌ها را **قبل از** اجرا با سیاست چک می‌کند، با یک تخلف کل برنامه را رد می‌کند (هیچ‌چیز نصفه اجرا نمی‌شود) و برای هر اقدام یک رکورد حسابرسی در فایل JSONL ضمیمه می‌کند که با هش SHA-256 برنامه مهر شده است.

## روش کار

1. **برنامه** بنویس (`plan.example.json`): لیست مرتب گام‌ها — `id`، `argv`، `cwd`، `timeout` و یک `note` که اقدام را به زبان انسانی توضیح می‌دهد.
2. **سیاست** بنویس (`policy.example.json`): باینری‌های ممنوع، الگوهای argv ممنوع، لیست سفید اختیاری باینری‌ها، سقف تایم‌اوت، `allowed_roots` (محدودسازی دایرکتوری)، `require_note`.
3. `review` — برای هر گام ALLOW یا DENY چاپ می‌کند و **هیچ‌چیز اجرا نمی‌شود**.
4. `run` — فقط اگر همه‌ی گام‌ها مجاز باشند اجرا می‌شود؛ هر اقدام در لاگ حسابرسی ضمیمه‌ای ثبت می‌شود.

## قوانین امنیتی

1. دستورها فقط لیست آرگومان‌اند، هرگز رشته‌ی شل — `shell=True` هیچ‌جا نیست (با تست واحد تضمین شده).
2. رد کردنِ سیاست، همه‌یا‌هیچ است: یک گام ممنوع، کل برنامه را قبل از اجرای هر گامی متوقف می‌کند.
3. دایرکتوری‌های کاری داخل `allowed_roots` محصورند (با resolve شدن symlink) — فرار با `../..` رد می‌شود.
4. آرگومان‌های حاوی توکن/پسورد/کلید، تخلف سیاست‌اند، نه چیزی برای اجرا.
5. بدون شبکه و بدون کلید — نگهبان `.env` را نمی‌خواند.

## تست

```bash
python3 -m unittest discover -s tests -v   # ۲۱ تست، همه سبز
```

## مجوز

MIT — فایل `LICENSE`.
