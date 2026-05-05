# Itsumma AF_ALG Check

Диагностическая утилита для Linux, которая проверяет доступность `AF_ALG` / `algif_aead` и помогает оценить риск по `CVE-2026-31431` (copy-fail).

> Инструмент предназначен для defensive-проверки и не является эксплойтом.

## Возможности

- выполняет runtime-пробу `socket + bind` для `AF_ALG AEAD`;
- анализирует компоненты ядра через `/proc/modules`, `modules.builtin`, `modules.builtin.modinfo`;
- пытается определить наличие vendor backport-фикса по changelog (`rpm`/Debian changelog);
- показывает процессы, которые держат `AF_ALG`-сокеты (`/proc/*/fd`, best effort);
- печатает рекомендации по mitigation для разных семейств дистрибутивов.

## Требования

- Linux;
- Go `1.24+`;
- для полного сканирования `/proc/*/fd` лучше запускать от `root`.

## Сборка

Entrypoint находится в корне проекта, сборка выполняется из корня:

```bash
go build -o itsumma-afalg-check .
```

## Запуск

```bash
./itsumma-afalg-check
```

## Что выводит утилита

При старте:

`Itsumma Security Check — AF_ALG / CVE-2026-31431`

Далее:

- результат runtime-пробы `AF_ALG` (`socket + bind`);
- версия ядра и доступность `modules.builtin`;
- состояние `af_alg` и `algif_aead` (loaded / built-in / unknown);
- итоговая оценка по `CVE-2026-31431` (включая попытку определить vendor backport);
- список текущих процессов с `AF_ALG`-сокетами (если найдено);
- пошаговые команды mitigation и пост-проверки после reboot.

## Базовая пост-проверка после mitigation

```bash
cat /proc/cmdline
modprobe -n -v algif_aead
lsmod | grep '^algif_aead\b' || echo 'algif_aead not loaded'
./itsumma-afalg-check
```

Для built-in сценария вместо `modprobe/lsmod` полезно дополнительно проверить:

```bash
dmesg | grep -i 'algif_aead\|initcall_blacklist'
```

## Важно

- Утилита носит диагностический характер и не заменяет обновление ядра от вендора.
- Наличие `algif_aead` означает attack surface, но финальный вывод зависит от версии ядра и backport-патчей дистрибутива.
- Если runtime-проба `AF_ALG AEAD` не проходит, в рамках этой проверки вектор считается недоступным.
