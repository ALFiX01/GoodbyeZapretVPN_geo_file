# GoodbyeZapretVPN_geo

Этот репозиторий хранит списки `geoip_list.txt` и `geosite_list.txt` (или в папке `edits/`) и автоматически собирает из них бинарные файлы `geoip.dat` и `geosite.dat` (или в папке `complete/`).

## Локальная работа

1. Измените списки в `geoip_list.txt` и `geosite_list.txt` (или `edits/geoip_list.txt`, `edits/geosite_list.txt`).
2. Пересоберите бинарники:

```powershell
.\geo_tool.ps1 import
```

Если нужно получить текстовые списки из текущих `.dat`:

```powershell
.\geo_tool.ps1 export
```

## Автосборка на GitHub

Workflow `.github/workflows/build-dat.yml` запускается при изменениях в `geoip_list.txt`, `geosite_list.txt` (или в папке `edits/`) или `geo_tool.ps1` и:

1. Ставит `.dat` из текстовых файлов.
2. Коммитит обновлённые `geoip.dat` и `geosite.dat` обратно в репозиторий.
