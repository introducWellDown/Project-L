# pylynis (Python port of Lynis)

Неофициальный, экспериментальный Python-порт Lynis. Совместимость и CLI сохраняются по мере развития.

## Установка (локально)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Запуск
```bash
pylynis audit system --format json --report-file report.json -v
```

## Лицензия
GPL-3.0-only. Lynis — (c) CISOfy. Этот проект — независимый порт/реимплементация.
