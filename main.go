//go:build linux

package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Linux uapi: AF_ALG is 38 on all supported arches.
const afALG = 38
const afRXRPC = 33

const (
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorReset = "\033[0m"
)

const (
	afNetlink   = 16
	netlinkXFRM = 6
)

// sockaddrALG mirrors struct sockaddr_alg from <linux/if_alg.h>.
type sockaddrALG struct {
	Family uint16
	Type   [14]byte
	Feat   uint32
	Mask   uint32
	Name   [64]byte
}

type moduleInfo struct {
	Name     string
	Size     string
	RefCount int
	Holders  []string
}

type afalgProcess struct {
	PID     int
	Comm    string
	Command string
	FDs     []afalgFD
}

type processScanResult struct {
	Processes          []afalgProcess
	InaccessibleFDDirs int
	SocketOpenDenied   int
}

type afalgFD struct {
	FD   string
	Type string
	Name string
}

type distroInfo struct {
	ID      string
	IDLike  []string
	Family  string
	Pretty  string
	Unknown bool
}

type cveAssessment struct {
	Patched bool
	Reason  string
}

var dirtyFragModules = []string{"esp4", "esp6", "rxrpc"}

func normalizeModuleName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}

func kernelRelease() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func stripOSReleaseValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func parseOSRelease() distroInfo {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return distroInfo{Family: "unknown", Pretty: "unknown", Unknown: true}
	}

	values := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = stripOSReleaseValue(value)
	}

	info := distroInfo{
		ID:     strings.ToLower(values["ID"]),
		IDLike: strings.Fields(strings.ToLower(values["ID_LIKE"])),
		Pretty: values["PRETTY_NAME"],
	}
	if info.Pretty == "" {
		info.Pretty = info.ID
	}
	if info.Pretty == "" {
		info.Pretty = "unknown"
	}

	ids := append([]string{info.ID}, info.IDLike...)
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			info.Family = "debian"
		case "rhel", "fedora", "centos", "almalinux", "rocky", "ol", "oracle", "amzn", "amazon":
			info.Family = "rhel"
		case "suse", "opensuse", "sles":
			info.Family = "suse"
		case "arch":
			info.Family = "arch"
		}
		if info.Family != "" {
			return info
		}
	}

	info.Family = "unknown"
	info.Unknown = true
	return info
}

func parseProcModules() (map[string]moduleInfo, error) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make(map[string]moduleInfo)
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) > 0 {
			name := normalizeModuleName(fields[0])
			info := moduleInfo{Name: name}
			if len(fields) > 1 {
				info.Size = fields[1]
			}
			if len(fields) > 2 {
				if n, err := strconv.Atoi(fields[2]); err == nil {
					info.RefCount = n
				}
			}
			if len(fields) > 3 && fields[3] != "-" {
				for _, holder := range strings.Split(strings.TrimSuffix(fields[3], ","), ",") {
					if holder != "" {
						info.Holders = append(info.Holders, normalizeModuleName(holder))
					}
				}
			}
			m[name] = info
		}
	}
	return m, s.Err()
}

func parseModulesBuiltin(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		base := filepath.Base(line)
		if strings.HasSuffix(base, ".ko") {
			out[normalizeModuleName(strings.TrimSuffix(base, ".ko"))] = true
		}
	}
	return out, nil
}

func parseModulesBuiltinModinfo(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	for _, field := range strings.Split(string(b), "\x00") {
		if name, ok := strings.CutPrefix(field, "name:"); ok {
			name = strings.TrimSpace(name)
			if name != "" {
				out[normalizeModuleName(name)] = true
			}
			continue
		}
		if module, _, ok := strings.Cut(field, "."); ok && module != "" {
			out[normalizeModuleName(module)] = true
		}
	}
	return out, nil
}

func tryAFALGAEADBind() error {
	fd, err := syscall.Socket(afALG, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_ALG, SOCK_SEQPACKET): %w", err)
	}
	defer syscall.Close(fd)

	sa := sockaddrALG{Family: afALG}
	copy(sa.Type[:], "aead")
	copy(sa.Name[:], "authencesn(hmac(sha256),cbc(aes))")
	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd),
		uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		return fmt.Errorf("bind(AF_ALG aead): %w", errno)
	}
	return nil
}

func tryXFRMNetlinkProbe() error {
	fd, err := syscall.Socket(afNetlink, syscall.SOCK_RAW, netlinkXFRM)
	if err != nil {
		return fmt.Errorf("socket(AF_NETLINK, NETLINK_XFRM): %w", err)
	}
	defer syscall.Close(fd)
	return nil
}

func tryRXRPCProbe() error {
	fd, err := syscall.Socket(afRXRPC, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket(AF_RXRPC, SOCK_DGRAM): %w", err)
	}
	defer syscall.Close(fd)
	return nil
}

func describeComponent(name string, probeOK bool, proc map[string]moduleInfo, builtin map[string]bool) string {
	if proc != nil {
		if info, ok := proc[name]; ok {
			ref := fmt.Sprintf("refcount=%d", info.RefCount)
			if len(info.Holders) > 0 {
				ref += ", holders=" + strings.Join(info.Holders, ",")
			}
			return "загружаемый модуль (в /proc/modules, " + ref + ")"
		}
	}
	if builtin != nil && builtin[name] {
		return "встроен в образ ядра (перечислен в modules.builtin)"
	}
	if probeOK && builtin == nil {
		return "не в /proc/modules; modules.builtin не прочитан — тип по ядру не уточнён"
	}
	if probeOK {
		return "не в /proc/modules; не найден в modules.builtin — вероятно встроен или иная конфигурация ядра"
	}
	return "не в /proc/modules и не подтверждён в modules.builtin"
}

func componentPresent(name string, proc map[string]moduleInfo, builtin map[string]bool) bool {
	if proc != nil {
		if _, ok := proc[name]; ok {
			return true
		}
	}
	return builtin != nil && builtin[name]
}

func nulString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func socketALGInfo(fd int) (uint16, string, string, error) {
	var buf [128]byte
	addrLen := uint32(len(buf))
	_, _, errno := syscall.Syscall(syscall.SYS_GETSOCKNAME, uintptr(fd),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&addrLen)))
	if errno != 0 {
		return 0, "", "", errno
	}
	family := *(*uint16)(unsafe.Pointer(&buf[0]))
	if family != afALG || addrLen < 24 {
		return family, "", "", nil
	}
	return family, nulString(buf[2:16]), nulString(buf[24:88]), nil
}

func readProcessCommand(pid int) (string, string) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	commBytes, _ := os.ReadFile(filepath.Join(base, "comm"))
	comm := strings.TrimSpace(string(commBytes))

	cmdBytes, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	cmd := strings.TrimSpace(strings.ReplaceAll(string(cmdBytes), "\x00", " "))
	return comm, cmd
}

func scanAFALGProcesses() (processScanResult, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return processScanResult{}, err
	}

	var result processScanResult
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			result.InaccessibleFDDirs++
			continue
		}

		var afalgFDs []afalgFD
		for _, fdEntry := range fds {
			fdPath := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(fdPath)
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}

			f, err := os.Open(fdPath)
			if err != nil {
				result.SocketOpenDenied++
				continue
			}
			family, algType, algName, err := socketALGInfo(int(f.Fd()))
			f.Close()
			if err == nil && family == afALG && (algType == "aead" || algType == "") {
				afalgFDs = append(afalgFDs, afalgFD{
					FD:   fdEntry.Name(),
					Type: algType,
					Name: algName,
				})
			}
		}

		if len(afalgFDs) > 0 {
			comm, cmd := readProcessCommand(pid)
			result.Processes = append(result.Processes, afalgProcess{
				PID:     pid,
				Comm:    comm,
				Command: cmd,
				FDs:     afalgFDs,
			})
		}
	}

	sort.Slice(result.Processes, func(i, j int) bool {
		return result.Processes[i].PID < result.Processes[j].PID
	})
	return result, nil
}

func redIfVulnerable(text string, vulnerable bool) string {
	if vulnerable {
		return colorRed + text + colorReset
	}
	return text
}

func greenIfDisabled(text string, disabled bool) string {
	if disabled {
		return colorGreen + text + colorReset
	}
	return text
}

func formatAFALGFDs(fds []afalgFD) string {
	parts := make([]string, 0, len(fds))
	for _, fd := range fds {
		detail := fd.Type
		if fd.Name != "" {
			if detail != "" {
				detail += "/"
			}
			detail += fd.Name
		}
		if detail == "" {
			parts = append(parts, fd.FD+"(AF_ALG)")
			continue
		}
		parts = append(parts, fd.FD+"("+detail+")")
	}
	return strings.Join(parts, ",")
}

func printAFALGProcesses(scan processScanResult, scanErr error, algif moduleInfo, loaded bool) {
	fmt.Println()
	fmt.Println("Текущие пользователи algif_aead / AF_ALG aead:")
	if scanErr != nil {
		fmt.Printf("  Не удалось просканировать /proc/*/fd: %v\n", scanErr)
	} else if len(scan.Processes) == 0 {
		fmt.Println("  Открытые AF_ALG aead-сокеты не найдены.")
		fmt.Println("  Примечание: использование может быть кратковременным; без root часть /proc/*/fd может быть недоступна.")
	} else {
		for _, p := range scan.Processes {
			name := p.Command
			if name == "" {
				name = p.Comm
			}
			if name == "" {
				name = "<unknown>"
			}
			fmt.Printf("  pid=%d fd=%s %s\n", p.PID, formatAFALGFDs(p.FDs), name)
		}
	}
	if scan.InaccessibleFDDirs > 0 || scan.SocketOpenDenied > 0 {
		fmt.Printf("  Ограничения скана: недоступных /proc/<pid>/fd=%d, fd socket open denied=%d. Для полной картины запустите от root.\n",
			scan.InaccessibleFDDirs, scan.SocketOpenDenied)
	}

	if loaded {
		fmt.Printf("  algif_aead refcount: %d\n", algif.RefCount)
		if len(algif.Holders) > 0 {
			fmt.Printf("  Зависимые модули из /proc/modules: %s\n", strings.Join(algif.Holders, ", "))
		}
		if algif.RefCount > 0 && len(scan.Processes) == 0 {
			fmt.Println("  Refcount > 0, но процесс не найден: модуль может удерживаться ядром/другим модулем или недоступными fd.")
		}
	}
}

func printInitramfsCommand(distro distroInfo) {
	switch distro.Family {
	case "debian":
		fmt.Println("    sudo update-initramfs -u -k all")
	case "rhel":
		fmt.Println("    sudo dracut -f --regenerate-all")
	case "suse":
		fmt.Println("    sudo mkinitrd   # или sudo dracut -f, если система уже на dracut")
	case "arch":
		fmt.Println("    sudo mkinitcpio -P")
	default:
		fmt.Println("    Пересоберите initramfs командой вашего дистрибутива, если algif_aead попадает в initramfs.")
	}
}

func printBootloaderCommand(distro distroInfo) {
	switch distro.Family {
	case "debian":
		fmt.Println("    Обычно: /etc/default/grub -> GRUB_CMDLINE_LINUX, затем sudo update-grub")
	case "rhel":
		fmt.Println("    sudo grubby --info=ALL | grep initcall_blacklist")
		fmt.Println("    sudo grubby --update-kernel=ALL --args=\"initcall_blacklist=algif_aead_init\"")
	case "suse":
		fmt.Println("    Обычно: /etc/default/grub -> GRUB_CMDLINE_LINUX, затем sudo grub2-mkconfig -o /boot/grub2/grub.cfg")
	case "arch":
		fmt.Println("    Обычно: /etc/default/grub -> GRUB_CMDLINE_LINUX, затем sudo grub-mkconfig -o /boot/grub/grub.cfg")
	default:
		fmt.Println("    Добавьте параметр в командную строку ядра через загрузчик вашей системы.")
	}
}

func printVerificationCommands(builtin bool) {
	fmt.Println()
	fmt.Println("  Проверка после reboot:")
	fmt.Println("    cat /proc/cmdline")
	if builtin {
		fmt.Println("    dmesg | grep -i 'algif_aead\\|initcall_blacklist'")
	} else {
		fmt.Println("    modprobe -n -v algif_aead")
		fmt.Println("    lsmod | grep '^algif_aead\\b' || echo 'algif_aead not loaded'")
	}
	fmt.Println("    ./itsumma-afalg-check")
}

func printModuleDisableGuide(distro distroInfo, algif moduleInfo, scan processScanResult) {
	fmt.Println()
	fmt.Println("Руководство по отключению algif_aead:")
	fmt.Printf("  Обнаружен загружаемый модуль algif_aead (%s, refcount=%d).\n", distro.Pretty, algif.RefCount)
	fmt.Println("    sudo sh -c 'cat >/etc/modprobe.d/disable-algif.conf <<\"EOF\"")
	fmt.Println("    # CVE-2026-31431")
	fmt.Println("    blacklist algif_aead")
	fmt.Println("    install algif_aead /bin/false")
	fmt.Println("    EOF'")
	fmt.Println("    echo 3 | sudo tee /proc/sys/vm/drop_caches")
	fmt.Println("    sudo modprobe -r algif_aead 2>/dev/null || sudo rmmod algif_aead 2>/dev/null || true")
	fmt.Println()

	if algif.RefCount > 0 || len(scan.Processes) > 0 {
		fmt.Println("  Модуль сейчас используется:")
		fmt.Println("    1. Остановите процессы из секции \"Текущие пользователи algif_aead / AF_ALG aead\".")
		fmt.Println("    2. Повторите: sudo modprobe -r algif_aead")
		fmt.Println("    3. Если модуль всё ещё загружен, перезагрузите сервер после добавления blacklist/install.")
		fmt.Println()
	}

	fmt.Println("  Если модуль может попадать в initramfs, пересоберите initramfs для этой системы:")
	printInitramfsCommand(distro)
	fmt.Println()

	if distro.Family == "rhel" {
		fmt.Println()
		fmt.Println("  Дополнительная защита через kernel cmdline для RHEL-family:")
		fmt.Println("    sudo grubby --update-kernel=ALL --args=\"modprobe.blacklist=algif_aead module_blacklist=algif_aead\"")
	}

	fmt.Println()
	fmt.Println("  Минимальное требование: добавить blacklist/install и перезагрузить сервер, если модуль уже использовался или не выгружается.")
	printVerificationCommands(false)
}

func printBuiltinDisableGuide(distro distroInfo) {
	fmt.Println()
	fmt.Println("Руководство по отключению algif_aead:")
	fmt.Println(redIfVulnerable("  Обнаружен built-in algif_aead. blacklist/install для modprobe здесь не поможет.", true))
	fmt.Println(redIfVulnerable("  ТРЕБУЕТСЯ ПЕРЕЗАГРУЗКА СЕРВЕРА ПОСЛЕ ДОБАВЛЕНИЯ ПАРАМЕТРА ЯДРА.", true))
	fmt.Println("  Добавьте параметр ядра:")
	fmt.Println("    initcall_blacklist=algif_aead_init")
	fmt.Println("  Команда для этой системы:")
	printBootloaderCommand(distro)
	fmt.Println("    sudo reboot")
	printVerificationCommands(true)
}

func printUnknownDisableGuide(distro distroInfo, probeOK bool) {
	fmt.Println()
	fmt.Println("Руководство по отключению algif_aead:")
	if !probeOK {
		fmt.Println(greenIfDisabled("  AF_ALG AEAD probe не прошёл; algif_aead не подтверждён. Mitigation-команды не печатаются.", true))
		return
	}
	fmt.Printf("  AF_ALG AEAD доступен, но algif_aead не классифицирован как loaded/built-in (%s).\n", distro.Pretty)
	fmt.Println("  Запустите проверку от root и проверьте vendor kernel patch level.")
	fmt.Println("  Если требуется emergency mitigation без точной классификации, используйте module blacklist и затем повторите ./itsumma-afalg-check.")
	fmt.Printf("    sudo sh -c 'printf \"%%s\\n\" \"blacklist algif_aead\" \"install algif_aead /bin/false\" >/etc/modprobe.d/disable-algif.conf'\n")
	printVerificationCommands(false)
}

func printProbeMitigatedFooter() {
	fmt.Println()
	fmt.Println("Дополнительно:")
	fmt.Println(greenIfDisabled("  AF_ALG AEAD-проба не прошла — команды отключения algif_aead не требуются для подтверждения исправления.", true))
	fmt.Println("  Запись algif_aead в modules.builtin отражает сборку ядра, а не факт доступности bind в рантайме.")
}

func printDisableGuide(distro distroInfo, probeOK bool, assessment cveAssessment, algif moduleInfo, loaded bool, builtin bool, scan processScanResult) {
	if !probeOK {
		printProbeMitigatedFooter()
		return
	}
	if assessment.Patched {
		fmt.Println()
		fmt.Println("Руководство по отключению algif_aead:")
		fmt.Println(greenIfDisabled("  Ядро определено как исправленное по vendor backport; аварийное отключение algif_aead не требуется.", true))
		fmt.Println("  Для комплаенса можно оставить контрольную проверку:")
		fmt.Println("    uname -r")
		fmt.Println("    rpm -q --changelog kernel-core | grep -i CVE-2026-31431 | head -n 1")
		return
	}
	if loaded {
		printModuleDisableGuide(distro, algif, scan)
		return
	}
	if builtin {
		printBuiltinDisableGuide(distro)
		return
	}
	printUnknownDisableGuide(distro, probeOK)
}

func printModulePresence(name string, label string, probeOK bool, proc map[string]moduleInfo, builtin map[string]bool, assessment cveAssessment) {
	desc := describeComponent(name, probeOK, proc, builtin)
	line := fmt.Sprintf("  %-14s %s", label+":", desc)
	if name == "algif_aead" && !probeOK {
		line = greenIfDisabled(line+"  [AF_ALG AEAD недоступен, CVE не подтверждён пробой]", true)
	} else if name == "algif_aead" && assessment.Patched {
		line = greenIfDisabled(line+"  [vendor patch detected]", true)
	} else if name == "algif_aead" && componentPresent(name, proc, builtin) {
		line = redIfVulnerable(line+"  [CVE-2026-31431]", true)
	}
	fmt.Println(line)
}

func moduleLoaded(name string, proc map[string]moduleInfo) (moduleInfo, bool) {
	if proc == nil {
		return moduleInfo{}, false
	}
	info, ok := proc[name]
	return info, ok
}

func moduleBuiltin(name string, builtin map[string]bool) bool {
	return builtin != nil && builtin[name]
}

func parseNumericDotted(version string) ([]int, bool) {
	parts := strings.Split(version, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func compareIntSlices(a []int, b []int) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		ai := 0
		if i < len(a) {
			ai = a[i]
		}
		bi := 0
		if i < len(b) {
			bi = b[i]
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func almaLinuxKernelPatched(release string) bool {
	// AlmaLinux ALSA-2026:A003: fixed in 6.12.0-124.52.2.el10_1 and later.
	buildSep := strings.Index(release, "-")
	if buildSep < 0 {
		return false
	}
	rest := release[buildSep+1:]
	elSep := strings.Index(rest, ".el10_1")
	if elSep < 0 {
		return false
	}
	buildVer := rest[:elSep]
	got, ok := parseNumericDotted(buildVer)
	if !ok {
		return false
	}
	minFixed, _ := parseNumericDotted("124.52.2")
	return compareIntSlices(got, minFixed) >= 0
}

func assessCVE202631431(distro distroInfo, release string, probeOK bool, present bool) cveAssessment {
	if !probeOK {
		return cveAssessment{
			Patched: true,
			Reason:  "AF_ALG AEAD socket+bind проба не прошла",
		}
	}
	if !present {
		return cveAssessment{}
	}
	if distro.ID == "almalinux" && almaLinuxKernelPatched(release) {
		return cveAssessment{
			Patched: true,
			Reason:  "ядро AlmaLinux содержит backport-фикс (ALSA-2026:A003, >= 6.12.0-124.52.2.el10_1)",
		}
	}
	if ok, reason := rpmChangelogShowsFix(release); ok {
		return cveAssessment{
			Patched: true,
			Reason:  reason,
		}
	}
	if ok, reason := debChangelogShowsFix(release); ok {
		return cveAssessment{
			Patched: true,
			Reason:  reason,
		}
	}
	return cveAssessment{}
}

func rpmChangelogShowsFix(release string) (bool, string) {
	if _, err := exec.LookPath("rpm"); err != nil {
		return false, ""
	}
	candidates := []string{
		"kernel-core-" + release,
		"kernel-" + release,
		"kernel-core",
		"kernel",
	}
	for _, pkg := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, "rpm", "-q", "--changelog", pkg).Output()
		cancel()
		if err != nil {
			continue
		}
		text := strings.ToLower(string(out))
		if strings.Contains(text, "cve-2026-31431") || strings.Contains(text, "algif_aead - revert to operating out-of-place") {
			return true, "в changelog пакета " + pkg + " найдено исправление CVE-2026-31431"
		}
	}
	return false, ""
}

func changelogMentionsAny(path string, gz bool, needles []string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var r io.Reader = f
	if gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return false
		}
		defer zr.Close()
		r = zr
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return false
	}
	text := strings.ToLower(string(data))
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(text, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func changelogMentionsCVE(path string, gz bool) bool {
	return changelogMentionsAny(path, gz, []string{
		"cve-2026-31431",
		"algif_aead - revert to operating out-of-place",
	})
}

func debChangelogShowsFix(release string) (bool, string) {
	candidates := []string{
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog.Debian.gz"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog.Debian.gz"),
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog.gz"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog.gz"),
	}
	for _, p := range candidates {
		if changelogMentionsCVE(p, true) {
			return true, "в changelog " + p + " найдено исправление CVE-2026-31431"
		}
	}

	// Fallback: sometimes changelog is not compressed.
	plainCandidates := []string{
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog.Debian"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog.Debian"),
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog"),
	}
	for _, p := range plainCandidates {
		if changelogMentionsCVE(p, false) {
			return true, "в changelog " + p + " найдено исправление CVE-2026-31431"
		}
	}
	return false, ""
}

func rpmChangelogShowsDirtyFragFix(release string) (bool, string) {
	if _, err := exec.LookPath("rpm"); err != nil {
		return false, ""
	}
	candidates := []string{
		"kernel-core-" + release,
		"kernel-" + release,
		"kernel-core",
		"kernel",
	}
	needles := []string{
		"dirty frag",
		"xfrm-esp page-cache write",
		"rxrpc page-cache write",
	}
	for _, pkg := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, "rpm", "-q", "--changelog", pkg).Output()
		cancel()
		if err != nil {
			continue
		}
		text := strings.ToLower(string(out))
		for _, n := range needles {
			if strings.Contains(text, n) {
				return true, "в changelog пакета " + pkg + " найдено упоминание фикса Dirty Frag"
			}
		}
	}
	return false, ""
}

func debChangelogShowsDirtyFragFix(release string) (bool, string) {
	needles := []string{
		"dirty frag",
		"xfrm-esp page-cache write",
		"rxrpc page-cache write",
	}
	candidates := []string{
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog.Debian.gz"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog.Debian.gz"),
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog.gz"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog.gz"),
	}
	for _, p := range candidates {
		if changelogMentionsAny(p, true, needles) {
			return true, "в changelog " + p + " найдено упоминание фикса Dirty Frag"
		}
	}
	plainCandidates := []string{
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog.Debian"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog.Debian"),
		filepath.Join("/usr/share/doc", "linux-image-"+release, "changelog"),
		filepath.Join("/usr/share/doc", "linux-image-unsigned-"+release, "changelog"),
	}
	for _, p := range plainCandidates {
		if changelogMentionsAny(p, false, needles) {
			return true, "в changelog " + p + " найдено упоминание фикса Dirty Frag"
		}
	}
	return false, ""
}

func dirtyFragLoadableModules(release string) []string {
	if release == "" || !commandExists("modinfo") {
		return nil
	}
	var loadable []string
	for _, m := range dirtyFragModules {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, "modinfo", "-k", release, "-F", "filename", m).Output()
		cancel()
		if err != nil {
			continue
		}
		path := strings.TrimSpace(string(out))
		if path != "" {
			loadable = append(loadable, m)
		}
	}
	return loadable
}

func assessDirtyFrag(distro distroInfo, release string, xfrmProbeOK bool, rxrpcProbeOK bool, present bool, loadable []string) cveAssessment {
	if !xfrmProbeOK && !rxrpcProbeOK {
		if present || len(loadable) > 0 {
			return cveAssessment{
				Patched: false,
				Reason:  "runtime-пробы недоступны, но компоненты Dirty Frag обнаружены или доступны для загрузки (проверьте от root)",
			}
		}
		return cveAssessment{
			Patched: true,
			Reason:  "xfrm/rxrpc runtime-пробы недоступны и esp4/esp6/rxrpc не обнаружены как loaded/built-in/loadable",
		}
	}
	if ok, reason := rpmChangelogShowsDirtyFragFix(release); ok {
		return cveAssessment{Patched: true, Reason: reason}
	}
	if ok, reason := debChangelogShowsDirtyFragFix(release); ok {
		return cveAssessment{Patched: true, Reason: reason}
	}
	_ = distro
	return cveAssessment{}
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func dpkgInstalled(pkg string) bool {
	if !commandExists("dpkg-query") {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", pkg).Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "install ok installed")
}

func rpmInstalled(pkg string) bool {
	if !commandExists("rpm") {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "rpm", "-q", pkg).Run()
	return err == nil
}

func detectStrongSwan(distro distroInfo) (present bool, details []string) {
	// Best-effort: binaries and/or package presence.
	if commandExists("ipsec") || commandExists("swanctl") {
		present = true
		details = append(details, "найден бинарник ipsec/swanctl")
	}

	switch distro.Family {
	case "debian":
		if dpkgInstalled("strongswan") || dpkgInstalled("strongswan-starter") {
			present = true
			details = append(details, "пакет strongswan установлен (dpkg)")
		}
	case "rhel", "suse", "arch":
		// RPM family and others: try rpm if available; arch often doesn't have rpm.
		if rpmInstalled("strongswan") {
			present = true
			details = append(details, "пакет strongswan установлен (rpm)")
		}
	}

	return present, details
}

func printVulnerabilitySummary(probeOK bool, proc map[string]moduleInfo, builtin map[string]bool, assessment cveAssessment) {
	if !probeOK {
		fmt.Println()
		fmt.Println(greenIfDisabled("CVE-2026-31431: AF_ALG AEAD недоступен (проба socket+bind не прошла) — с точки зрения этой проверки уязвимость исправлена / недоступна для эксплуатации.", true))
		fmt.Println("  Примечание: algif_aead может числиться в modules.builtin или модулях ядра как часть образа; для вердикта используется результат пробы.")
		return
	}
	present := componentPresent("algif_aead", proc, builtin)
	if assessment.Patched {
		fmt.Println()
		fmt.Println(greenIfDisabled("CVE-2026-31431: вектор присутствует, но ядро определяется как исправленное (vendor backport).", true))
		fmt.Printf("  Основание: %s.\n", assessment.Reason)
		return
	}
	if present {
		fmt.Println()
		fmt.Println(redIfVulnerable("CVE-2026-31431: algif_aead доступен на системе — требуется mitigation.", true))
		fmt.Println("  Примечание: наличие algif_aead показывает attack surface; фактическая уязвимость зависит от версии ядра и backport-патчей дистрибутива.")
		return
	}
	fmt.Println()
	fmt.Println("CVE-2026-31431: AF_ALG AEAD bind прошёл, но algif_aead не найден как модуль/builtin; проверьте конфигурацию ядра.")
}

func printDirtyFragSummary(release string, proc map[string]moduleInfo, builtin map[string]bool, xfrmProbeOK bool, rxrpcProbeOK bool, loadable []string, assessment cveAssessment) {
	presentAny := false
	for _, m := range dirtyFragModules {
		if componentPresent(m, proc, builtin) {
			presentAny = true
			break
		}
	}

	fmt.Println()
	fmt.Println("Dirty Frag: xfrm-ESP + RxRPC page-cache write")
	if !presentAny {
		fmt.Println(greenIfDisabled("  Поверхность атаки не подтверждена: esp4/esp6/rxrpc не найдены как loaded/built-in.", true))
		fmt.Println("  Примечание: это не доказательство отсутствия уязвимости в ядре; проверка ориентируется на наличие модулей/компонентов.")
		return
	}
	if assessment.Patched {
		fmt.Println(greenIfDisabled("  Компоненты присутствуют, но ядро определяется как исправленное (vendor backport по changelog).", true))
		fmt.Printf("  Основание: %s.\n", assessment.Reason)
		return
	}
	if !xfrmProbeOK && !rxrpcProbeOK {
		fmt.Println(redIfVulnerable("  Dirty Frag probe не прошёл в текущем контексте, но безопасный статус не подтверждён.", true))
		if assessment.Reason != "" {
			fmt.Printf("  Основание: %s.\n", assessment.Reason)
		}
		if len(loadable) > 0 {
			fmt.Printf("  Потенциально загружаемые компоненты: %s.\n", strings.Join(loadable, ", "))
		}
		return
	}
	if !presentAny && len(loadable) == 0 {
		fmt.Println("  Runtime-векторы доступны, но esp4/esp6/rxrpc не обнаружены как loaded/built-in/loadable; проверьте конфигурацию ядра.")
		return
	}
	fmt.Println(redIfVulnerable("  Обнаружен доступный runtime surface (xfrm/rxrpc) или компоненты esp4/esp6/rxrpc — требуется mitigation или обновление ядра.", true))
	fmt.Printf("  Версия ядра: %s\n", release)
}

func printDirtyFragDisableGuide(distro distroInfo, proc map[string]moduleInfo, builtin map[string]bool, loadable []string, assessment cveAssessment) {
	presentAny := false
	var loadedModules []string
	var builtinModules []string
	for _, m := range dirtyFragModules {
		if componentPresent(m, proc, builtin) {
			presentAny = true
		}
		if _, ok := moduleLoaded(m, proc); ok {
			loadedModules = append(loadedModules, m)
		}
		if moduleBuiltin(m, builtin) {
			builtinModules = append(builtinModules, m)
		}
	}
	if len(loadable) > 0 {
		presentAny = true
	}
	if !presentAny || assessment.Patched {
		return
	}

	fmt.Println()
	fmt.Println("Руководство по mitigation Dirty Frag:")

	if ok, details := detectStrongSwan(distro); ok {
		fmt.Println()
		fmt.Println("  Обнаружен strongSwan / IPSec:")
		if len(details) > 0 {
			fmt.Printf("    Детали: %s\n", strings.Join(details, "; "))
		}
		fmt.Println("    Примечание: если вы отключаете kernel ESP (esp4/esp6), IPSec нужно перевести на userspace.")
		if distro.Family == "debian" && !dpkgInstalled("libcharon-extra-plugins") {
			fmt.Println(redIfVulnerable("    Для strongSwan может потребоваться пакет libcharon-extra-plugins (plugin kernel-libipsec).", true))
			fmt.Println("    Установка (Debian/Ubuntu):")
			fmt.Println("      sudo apt-get update && sudo apt-get install -y libcharon-extra-plugins")
		}
	}

	if len(builtinModules) > 0 {
		fmt.Println(redIfVulnerable("  Обнаружены built-in компоненты Dirty Frag (modules.builtin):", true), strings.Join(builtinModules, ", "))
		fmt.Println("  Для built-in отключение через modprobe/rmmod неприменимо.")
		fmt.Println("  Требуется обновление/пересборка ядра (или vendor-fixed kernel), затем повторная проверка.")
		if len(loadedModules) == 0 {
			fmt.Println("  Загружаемые компоненты Dirty Frag не обнаружены; emergency-команды выгрузки пропущены.")
		}
	}
	if len(loadedModules) == 0 && len(builtinModules) == 0 && len(loadable) > 0 {
		fmt.Printf("  Модули не загружены сейчас, но доступны для загрузки: %s.\n", strings.Join(loadable, ", "))
		fmt.Println("  Рекомендуется добавить modprobe install /bin/false заранее (до потенциальной загрузки).")
		fmt.Println("  Перед любой проверкой через modprobe сначала проверьте, что уже загружено:")
		fmt.Println("    lsmod | egrep '^(esp4|esp6|rxrpc)\\b' || echo 'esp4/esp6/rxrpc not loaded'")
		fmt.Println("  Если выполняете проверку загрузки через modprobe, после неё обязательно выгрузите модули:")
		fmt.Println("    sudo modprobe esp4 esp6 rxrpc || true")
		fmt.Println("    sudo modprobe -r esp6 rxrpc")
		fmt.Println("    sudo modprobe -r esp4 || sudo rmmod -f esp4")
	}

	if len(loadedModules) > 0 {
		fmt.Println()
		fmt.Println("  Перед выгрузкой модулей (если IPSec/xfrm используется) сделайте flush:")
		fmt.Println("    sudo ip xfrm state flush")
		fmt.Println("    sudo ip xfrm policy flush")
		fmt.Println("    echo 3 | sudo tee /proc/sys/vm/drop_caches")
		fmt.Println()
		fmt.Println("  Попробуйте штатную выгрузку через modprobe -r:")
		fmt.Println("    sudo modprobe -r esp6 rxrpc")
		fmt.Println("    sudo modprobe -r esp4 || true")
		fmt.Println("  Если esp4 не выгружается, используйте форс-выгрузку:")
		fmt.Println("    sudo rmmod -f esp4")
		fmt.Println()

		fmt.Println("    sudo sh -c \"printf 'install esp4 /bin/false\\ninstall esp6 /bin/false\\ninstall rxrpc /bin/false\\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp6 rxrpc 2>/dev/null; rmmod -f esp4 2>/dev/null; true\"")
		fmt.Println()
	}

	fmt.Println("  Проверка:")
	fmt.Println("    modprobe -n -v esp4 esp6 rxrpc")
	fmt.Println("    lsmod | egrep '^(esp4|esp6|rxrpc)\\b' || echo 'esp4/esp6/rxrpc not loaded'")
	fmt.Println("    sudo reboot   # если модули не выгружаются или подхватываются ранней загрузкой")
	if distro.Family != "" {
		fmt.Println()
		fmt.Println("  Если модули попадают в initramfs, пересоберите initramfs:")
		printInitramfsCommand(distro)
	}
}

func parseBuiltinIfAvailable(release string, relErr error) map[string]bool {
	if relErr != nil {
		return nil
	}

	out := make(map[string]bool)
	p := filepath.Join("/lib/modules", release, "modules.builtin")
	if m, err := parseModulesBuiltin(p); err == nil {
		for name := range m {
			out[name] = true
		}
	}

	modinfoPath := filepath.Join("/lib/modules", release, "modules.builtin.modinfo")
	if m, err := parseModulesBuiltinModinfo(modinfoPath); err == nil {
		for name := range m {
			out[name] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func preferredProcModules(after map[string]moduleInfo, errAfter error, before map[string]moduleInfo, errBefore error) map[string]moduleInfo {
	if errAfter == nil {
		return after
	}
	if errBefore == nil {
		return before
	}
	return nil
}

func main() {
	release, relErr := kernelRelease()
	builtin := parseBuiltinIfAvailable(release, relErr)
	distro := parseOSRelease()

	procBefore, errProcBefore := parseProcModules()
	probeErr := tryAFALGAEADBind()
	xfrmProbeErr := tryXFRMNetlinkProbe()
	rxrpcProbeErr := tryRXRPCProbe()
	procAfter, errProcAfter := parseProcModules()

	// Prefer post-probe view for autoloaded algif_*.
	proc := preferredProcModules(procAfter, errProcAfter, procBefore, errProcBefore)
	probeOK := probeErr == nil
	processScan, scanErr := scanAFALGProcesses()
	algifInfo, algifLoaded := moduleLoaded("algif_aead", proc)
	algifBuiltin := moduleBuiltin("algif_aead", builtin)
	assessment := assessCVE202631431(distro, release, probeOK, componentPresent("algif_aead", proc, builtin))
	xfrmProbeOK := xfrmProbeErr == nil
	rxrpcProbeOK := rxrpcProbeErr == nil
	dirtyFragPresent := false
	for _, m := range dirtyFragModules {
		if componentPresent(m, proc, builtin) {
			dirtyFragPresent = true
			break
		}
	}
	dirtyFragLoadable := dirtyFragLoadableModules(release)
	dirtyFragAssessment := assessDirtyFrag(distro, release, xfrmProbeOK, rxrpcProbeOK, dirtyFragPresent, dirtyFragLoadable)

	fmt.Println("https://github.com/itsystem/afalg-check")
	fmt.Println("Itsumma Security Check — AF_ALG / CVE-2026-31431; Dirty Frag: xfrm-ESP + RxRPC page-cache write")
	fmt.Println(strings.Repeat("-", 52))
	fmt.Println("AF_ALG probe (socket + bind aead authencesn(hmac(sha256),cbc(aes))):")
	if probeOK {
		fmt.Println("  Поддержка AF_ALG (проба): да")
	} else {
		fmt.Printf("  Поддержка AF_ALG (проба): нет (%v)\n", probeErr)
	}

	if relErr != nil {
		fmt.Printf("  Версия ядра: не удалось прочитать: %v\n", relErr)
	} else {
		fmt.Printf("  Версия ядра: %s\n", release)
		if builtin == nil {
			fmt.Printf("  modules.builtin: нет или не прочитан (%s)\n",
				filepath.Join("/lib/modules", release, "modules.builtin"))
		}
	}

	fmt.Println()
	fmt.Println("Компоненты (af_alg — адресное семейство; algif_aead — типичный модуль для AEAD bind):")
	printModulePresence("af_alg", "af_alg", probeOK, proc, builtin, assessment)
	printModulePresence("algif_aead", "algif_aead", probeOK, proc, builtin, assessment)
	printVulnerabilitySummary(probeOK, proc, builtin, assessment)
	printAFALGProcesses(processScan, scanErr, algifInfo, algifLoaded)
	printDisableGuide(distro, probeOK, assessment, algifInfo, algifLoaded, algifBuiltin, processScan)

	fmt.Println()
	fmt.Println(strings.Repeat("-", 52))
	fmt.Println("Дополнительная проверка — Dirty Frag")
	fmt.Println("Компоненты (esp4/esp6 — xfrm ESP; rxrpc — RxRPC):")
	for _, m := range dirtyFragModules {
		printModulePresence(m, m, true, proc, builtin, cveAssessment{})
	}
	fmt.Println("Dirty Frag runtime probes:")
	if xfrmProbeOK {
		fmt.Println("  XFRM probe (socket AF_NETLINK/NETLINK_XFRM): да")
	} else {
		fmt.Printf("  XFRM probe (socket AF_NETLINK/NETLINK_XFRM): нет (%v)\n", xfrmProbeErr)
	}
	if rxrpcProbeOK {
		fmt.Println("  RXRPC probe (socket AF_RXRPC): да")
	} else {
		fmt.Printf("  RXRPC probe (socket AF_RXRPC): нет (%v)\n", rxrpcProbeErr)
	}
	printDirtyFragSummary(release, proc, builtin, xfrmProbeOK, rxrpcProbeOK, dirtyFragLoadable, dirtyFragAssessment)
	printDirtyFragDisableGuide(distro, proc, builtin, dirtyFragLoadable, dirtyFragAssessment)
}
