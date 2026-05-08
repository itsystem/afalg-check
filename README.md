# Itsumma AF_ALG Check

Диагностическая утилита для Linux, которая проверяет:

- доступность `AF_ALG` / `algif_aead` и помогает оценить риск по `CVE-2026-31431` (copy-fail);
- наличие поверхности атаки для класса уязвимостей **Dirty Frag** (цепочка `xfrm-ESP Page-Cache Write` + `RxRPC Page-Cache Write`) по компонентам `esp4`, `esp6`, `rxrpc` и печатает mitigation.

> Инструмент предназначен для defensive-проверки и не является эксплойтом.

## Возможности

- выполняет runtime-пробу `socket + bind` для `AF_ALG AEAD`;
- анализирует компоненты ядра через `/proc/modules`, `modules.builtin`, `modules.builtin.modinfo`;
- пытается определить наличие vendor backport-фикса по changelog (`rpm`/Debian changelog);
- показывает процессы, которые держат `AF_ALG`-сокеты (`/proc/*/fd`, best effort);
- печатает рекомендации по mitigation для разных семейств дистрибутивов.

Дополнительно для Dirty Frag:

- проверяет наличие `esp4`, `esp6`, `rxrpc` (loaded / built-in / unknown);
- выполняет runtime-пробы `socket(AF_NETLINK, NETLINK_XFRM)` и `socket(AF_RXRPC)` без изменения конфигурации системы;
- печатает emergency mitigation (отключение загрузки модулей + попытка выгрузки), если компоненты присутствуют.

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
echo 3 | sudo tee /proc/sys/vm/drop_caches
modprobe -n -v algif_aead
lsmod | grep '^algif_aead\b' || echo 'algif_aead not loaded'
./itsumma-afalg-check
```

Для built-in сценария вместо `modprobe/lsmod` полезно дополнительно проверить:

```bash
dmesg | grep -i 'algif_aead\|initcall_blacklist'
```

## Dirty Frag: базовая mitigation-команда

Команда из публичного runbook Dirty Frag (отключает загрузку `esp4`, `esp6`, `rxrpc` и пытается выгрузить уже загруженные модули).

Если IPSec / XFRM используется (например, через strongSwan), перед выгрузкой модулей рекомендуется выполнить flush:

```bash
sudo ip xfrm state flush
sudo ip xfrm policy flush
echo 3 | sudo tee /proc/sys/vm/drop_caches
```

Если `esp4`/`esp6`/`rxrpc` собраны как built-in (видны только в `modules.builtin`), `modprobe blacklist` и `rmmod` не отключат их: в этом случае требуется обновление/пересборка ядра.

Для strongSwan после установки `libcharon-extra-plugins` включите `kernel-libipsec`:

```bash
sudo sed -i 's/^\s*load\s*=\s*no/load = yes/' /etc/strongswan.d/charon/kernel-libipsec.conf
sudo systemctl restart strongswan || sudo systemctl restart strongswan-starter
```

```bash
lsmod | egrep '^(esp4|esp6|rxrpc)\b' || echo 'esp4/esp6/rxrpc not loaded'
sudo modprobe esp4 esp6 rxrpc || true
sudo modprobe -r esp6 rxrpc
sudo modprobe -r esp4 || true
sudo rmmod -f esp4
sudo sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp6 rxrpc 2>/dev/null; rmmod -f esp4 2>/dev/null; true"
```

Пост-проверка:

```bash
modprobe -n -v esp4 esp6 rxrpc
lsmod | egrep '^(esp4|esp6|rxrpc)\b' || echo 'esp4/esp6/rxrpc not loaded'
./itsumma-afalg-check
```

## Важно

- Утилита носит диагностический характер и не заменяет обновление ядра от вендора.
- Наличие `algif_aead` означает attack surface, но финальный вывод зависит от версии ядра и backport-патчей дистрибутива.
- Если runtime-проба `AF_ALG AEAD` не проходит, в рамках этой проверки вектор считается недоступным.
