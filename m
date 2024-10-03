Return-Path: <kasan-dev+bncBDAOJ6534YNBBVNZ7O3QMGQEGF3GQ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id AAF6998F5CA
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2024 20:05:11 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5df92c75f1asf1034199eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2024 11:05:11 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727978710; x=1728583510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qOmCyWIktKkDCzvClxhwnZklPSslAfcak8rsmP3YEio=;
        b=ve8QMNmZDWqLWsyJFHiV7P9YnlZF2iJHidHdoyvLIcHDUn+RjmmTmfaDNubsWvqsdm
         sMNVK/m82qmH3mO/jgakyp2YAWmkoc9pU+Ip0JYHerTtWsLuPPZSBvmZRwwUP6iHWTzC
         rh3qfqo6V825Zl9PWQZ844A/hEc72DKS6zJfRxZ1WcJtjltgpOH+j6tS/JF3sQOr9QQC
         fKfaFFswnuhI/ttj9TsfDJgmHJDoMswJsv9cVeNr05g6Sj/LRn9aT35RE3VEU+Y03OXq
         +Hanm7iata+ZoWoW1IWkQ/THdNFepkawDLgKTI7hkNlSAXFGQwjmkd5H/kHSiDx2MhwE
         T7kQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727978710; x=1728583510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qOmCyWIktKkDCzvClxhwnZklPSslAfcak8rsmP3YEio=;
        b=cghJn6xB6gJOvoimo+Zv/HYi1CwxyAC7nqnAqWhE/7ebtfGSwhLIVBfkmi+kaKWJcv
         kGy+w+PBHi0EeK1RmTFiJ2GvEyP+IYHA2PtQM+/hZig+G+VZtN+DjoHIWwXXhs0GwRJ2
         +buWzqik+h/WMyT56y9rCwdME0jMr5Of7zfQRQlSgE2QysGb87XzRE1ljyC+bWDqlqE6
         +0dwGhfRxd2d4wG215VfHv5T88braQwfUPpkjrAVnm+tKHpAmOCvIYwmeFrBypUPS3df
         SZg4eGLkoRIYV/fRcaLjp0zZTsGrMllmf3RaxhkLjTRDB3cpZCm15/yVBe4Psex3mkGH
         oaIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727978710; x=1728583510;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qOmCyWIktKkDCzvClxhwnZklPSslAfcak8rsmP3YEio=;
        b=PkmP7AtXywQ4wxOu7hiLWZZoHgkOf7q9VxdEC0K3Bcg5gR0rZPUER71dutcXrJ6UhH
         leGyDgfQESz2qr98iWAasQfCaAPL/fy8gsrU/UvAKYGcHYpYTq7XT6IF9Y2bwcBywmdL
         YloQRLV3Nb2E6SwoHbO0UBxuG9Qr/dY1KOGp36oh/hcUhUm/SmHIAQwmrC2zGsUE006E
         kaLw5qPHIq1Bezr6Psj5ZqKdL87MFHfkXC5dGaF2RhOoZLlDxRiEK2mwK+dRl5E0Jxza
         wCfdkavY+cMCEotSncDGfCyqmkNPxPjirfPsGY7DvRsiwdv4yMlNDabYuhKtCMkbnzz6
         GeZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWyjxp14aMSNDqrudnLwVBC8bI3mADL/F+L4LqoyyNkXAuFeixfyYstoVeDFYYRoVJftR75/A==@lfdr.de
X-Gm-Message-State: AOJu0YxSWI6ceAYfhaKNUkAXmNpl6WX6/R/nhYW+NrBb3Sk615VRjG2/
	RjiKxql5DnGtrjkDv7e4x+GtSweYVeGzEPrawzk00C8mr9iliMfU
X-Google-Smtp-Source: AGHT+IH7nnL5W3BK2V9PebDPEtDzwEX9UOijmw1gwgKMN56J0dw1/cITmoEkK9Du7J7RLZoHe9yF5Q==
X-Received: by 2002:a05:6820:1b88:b0:5ba:ec8b:44b5 with SMTP id 006d021491bc7-5e7b1da0dedmr5071235eaf.3.1727978710094;
        Thu, 03 Oct 2024 11:05:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c88a:0:b0:5e7:af90:76b5 with SMTP id 006d021491bc7-5e7bd58e561ls392250eaf.0.-pod-prod-07-us;
 Thu, 03 Oct 2024 11:05:09 -0700 (PDT)
X-Received: by 2002:a05:6808:22ab:b0:3e3:9126:7642 with SMTP id 5614622812f47-3e3c156fd9amr260875b6e.22.1727978708970;
        Thu, 03 Oct 2024 11:05:08 -0700 (PDT)
Date: Thu, 3 Oct 2024 11:05:07 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn@googlegroups.com>
Subject: booting qemu with KMSAN is stuck
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_64416_1683452301.1727978707961"
X-Original-Sender: snovitoll@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_64416_1683452301.1727978707961
Content-Type: multipart/alternative; 
	boundary="----=_Part_64417_436716256.1727978707961"

------=_Part_64417_436716256.1727978707961
Content-Type: text/plain; charset="UTF-8"

Hello,

I need help with the Linux boot issue with KMSAN.
On x86_64 I've enabled KMSAN and KMSAN_KUNIT_TEST
to work with adding kmsan check in one of kernel function.

Booting is stuck after this line:
"ATTENTION: KMSAN is a debugging tool! Do not use it on production 
machines!"

I couldn't figure out the guidance myself browsing the internet
or looking for the documentation:
https://docs.kernel.org/dev-tools/kmsan.html

Please suggest. Not sure if this is the right group to ask.

Kernel config (linux-next, next-20241002 tag):
https://gist.github.com/novitoll/bdad35d2d1d29d708430194930b4497b

Console log with QEMU cmdline params:
+ qemu-system-x86_64 -m 6G -smp 4 -kernel 
./linux-next/arch/x86/boot/bzImage -append 'console=ttyS0 root=/dev/sda 
earlyprintk=serial net.iframes=0 nokaslr' -drive 
file=./bullseye.img,format=raw -net 
user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10022-:22 -net nic,model=e1000
-enable-kvm -nographic -s -pidfile vm.pid
qemu-system-x86_64: warning: host doesn't support requested feature: 
CPUID.80000001H:ECX.svm [bit 2]
qemu-system-x86_64: warning: host doesn't support requested feature: 
CPUID.80000001H:ECX.svm [bit 2]
qemu-system-x86_64: warning: host doesn't support requested feature: 
CPUID.80000001H:ECX.svm [bit 2]
qemu-system-x86_64: warning: host doesn't support requested feature: 
CPUID.80000001H:ECX.svm [bit 2]
SeaBIOS (version 1.15.0-1)

iPXE (https://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+BFF8B310+BFECB310 CA00

Booting from ROM...
early console in extract_kernel
input_data: 0x0000000015fd72a3
input_len: 0x0000000009c0e693
output: 0x0000000001000000
output_len: 0x0000000017b82df0
kernel_total_size: 0x000000001ec26000
needed_size: 0x000000001ee00000
trampoline_32bit: 0x0000000000000000

Decompressing Linux... Parsing ELF... done.
Booting the kernel (entry_offset: 0x0000000000000112).
[    0.000000][    T0] Linux version 6.12.0-rc1-next-20241002-dirty 
(user@linux) (Ubuntu clang version 14.0.0-1ubuntu1.1, Ubuntu 4
[    0.000000][    T0] Command line: console=ttyS0 root=/dev/sda 
earlyprintk=serial net.iframes=0 nokaslr
[    0.000000][    T0] KERNEL supported cpus:
[    0.000000][    T0]   Intel GenuineIntel
[    0.000000][    T0]   AMD AuthenticAMD
[    0.000000][    T0] BIOS-provided physical RAM map:
[    0.000000][    T0] BIOS-e820: [mem 
0x0000000000000000-0x000000000009fbff] usable
[    0.000000][    T0] BIOS-e820: [mem 
0x000000000009fc00-0x000000000009ffff] reserved
[    0.000000][    T0] BIOS-e820: [mem 
0x00000000000f0000-0x00000000000fffff] reserved
[    0.000000][    T0] BIOS-e820: [mem 
0x0000000000100000-0x00000000bffdffff] usable
[    0.000000][    T0] BIOS-e820: [mem 
0x00000000bffe0000-0x00000000bfffffff] reserved
[    0.000000][    T0] BIOS-e820: [mem 
0x00000000feffc000-0x00000000feffffff] reserved
[    0.000000][    T0] BIOS-e820: [mem 
0x00000000fffc0000-0x00000000ffffffff] reserved
[    0.000000][    T0] BIOS-e820: [mem 
0x0000000100000000-0x00000001bfffffff] usable
[    0.000000][    T0] printk: legacy bootconsole [earlyser0] enabled
[    0.000000][    T0] ERROR: earlyprintk= earlyser already used
[    0.000000][    T0] ERROR: earlyprintk= earlyser already used
[    0.000000][    T0] ERROR: earlyprintk= earlyser already used
[    0.000000][    T0] 
**********************************************************
[    0.000000][    T0] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE 
NOTICE   **
[    0.000000][    T0] **                                                   
   **
[    0.000000][    T0] ** This system shows unhashed kernel memory 
addresses   **
[    0.000000][    T0] ** via the console, logs, and other interfaces. This 
   **
[    0.000000][    T0] ** might reduce the security of your system.         
   **
[    0.000000][    T0] **                                                   
   **
[    0.000000][    T0] ** If you see this message and you are not debugging 
   **
[    0.000000][    T0] ** the kernel, report this immediately to your 
system   **
[    0.000000][    T0] ** administrator!                                   
    **
[    0.000000][    T0] **                                                   
   **
[    0.000000][    T0] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE 
NOTICE   **
[    0.000000][    T0] 
**********************************************************
[    0.000000][    T0] Malformed early option 'vsyscall'
[    0.000000][    T0] NX (Execute Disable) protection: active
[    0.000000][    T0] APIC: Static calls initialized
[    0.000000][    T0] SMBIOS 2.8 present.
[    0.000000][    T0] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 
1.15.0-1 04/01/2014
[    0.000000][    T0] DMI: Memory slots populated: 1/1                     
                                                                            
                                                                            
                                   [34/1773]
[    0.000000][    T0] Hypervisor detected: KVM
[    0.000000][    T0] kvm-clock: Using msrs 4b564d01 and 4b564d00
[    0.000008][    T0] kvm-clock: using sched offset of 1729977656 cycles
[    0.001150][    T0] clocksource: kvm-clock: mask: 0xffffffffffffffff 
max_cycles: 0x1cd42e4dffb, max_idle_ns: 881590591483 ns
[    0.004521][    T0] tsc: Detected 4199.996 MHz processor
[    0.012840][    T0] last_pfn = 0x1c0000 max_arch_pfn = 0x400000000
[    0.013911][    T0] MTRR map: 4 entries (3 fixed + 1 variable; max 19), 
built from 8 variable MTRRs
[    0.015645][    T0] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  WP 
 UC- WT
[    0.017121][    T0] last_pfn = 0xbffe0 max_arch_pfn = 0x400000000
[    0.026479][    T0] found SMP MP-table at [mem 0x000f5ba0-0x000f5baf]
[    0.034297][    T0] ACPI: Early table checksum verification disabled
[    0.035435][    T0] ACPI: RSDP 0x00000000000F59C0 000014 (v00 BOCHS )
[    0.036712][    T0] ACPI: RSDT 0x00000000BFFE1A1C 000034 (v01 BOCHS 
 BXPC     00000001 BXPC 00000001)
[    0.038510][    T0] ACPI: FACP 0x00000000BFFE18B8 000074 (v01 BOCHS 
 BXPC     00000001 BXPC 00000001)
[    0.040317][    T0] ACPI: DSDT 0x00000000BFFE0040 001878 (v01 BOCHS 
 BXPC     00000001 BXPC 00000001)
[    0.042114][    T0] ACPI: FACS 0x00000000BFFE0000 000040
[    0.043169][    T0] ACPI: APIC 0x00000000BFFE192C 000090 (v01 BOCHS 
 BXPC     00000001 BXPC 00000001)
[    0.044966][    T0] ACPI: HPET 0x00000000BFFE19BC 000038 (v01 BOCHS 
 BXPC     00000001 BXPC 00000001)
[    0.046754][    T0] ACPI: WAET 0x00000000BFFE19F4 000028 (v01 BOCHS 
 BXPC     00000001 BXPC 00000001)
[    0.048542][    T0] ACPI: Reserving FACP table memory at [mem 
0xbffe18b8-0xbffe192b]
[    0.050028][    T0] ACPI: Reserving DSDT table memory at [mem 
0xbffe0040-0xbffe18b7]
[    0.051507][    T0] ACPI: Reserving FACS table memory at [mem 
0xbffe0000-0xbffe003f]
[    0.052992][    T0] ACPI: Reserving APIC table memory at [mem 
0xbffe192c-0xbffe19bb]
[    0.054472][    T0] ACPI: Reserving HPET table memory at [mem 
0xbffe19bc-0xbffe19f3]
[    0.055948][    T0] ACPI: Reserving WAET table memory at [mem 
0xbffe19f4-0xbffe1a1b]
[    0.057723][    T0] No NUMA configuration found
[    0.058542][    T0] Faking a node at [mem 
0x0000000000000000-0x00000001bfffffff]
[    0.059969][    T0] Faking node 0 at [mem 
0x0000000000001000-0x00000000ffffffff] (4095MB)
[    0.061531][    T0] Faking node 1 at [mem 
0x0000000100000000-0x00000001bfffffff] (3072MB)
[    0.063745][    T0] NODE_DATA(0) allocated [mem 0xbffda540-0xbffdffff]
[    0.064934][    T0] NODE_DATA(1) allocated [mem 0x1bfff6540-0x1bfffbfff]
[    0.086550][    T0] Zone ranges:
[    0.087104][    T0]   DMA      [mem 
0x0000000000001000-0x0000000000ffffff]
[    0.088180][    T0]   DMA32    [mem 
0x0000000001000000-0x00000000ffffffff]
[    0.089254][    T0]   Normal   [mem 
0x0000000100000000-0x00000001bfffffff]
[    0.090331][    T0]   Device   empty
[    0.090919][    T0] Movable zone start for each node
[    0.091690][    T0] Early memory node ranges
[    0.092347][    T0]   node   0: [mem 
0x0000000000001000-0x000000000009efff]
[    0.093445][    T0]   node   0: [mem 
0x0000000000100000-0x00000000bffdffff]
[    0.094537][    T0]   node   1: [mem 
0x0000000100000000-0x00000001bfffffff]
[    0.095551][    T0] Initmem setup node 0 [mem 
0x0000000000001000-0x00000000bffdffff]
[    0.096562][    T0] Initmem setup node 1 [mem 
0x0000000100000000-0x00000001bfffffff]
[    0.097595][    T0] On node 0, zone DMA: 1 pages in unavailable ranges
[    0.098589][    T0] On node 0, zone DMA: 97 pages in unavailable ranges
[    0.158915][    T0] On node 1, zone Normal: 32 pages in unavailable 
ranges
[    0.160102][    T0] ACPI: PM-Timer IO Port: 0x608
[    0.160700][    T0] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])
[    0.161554][    T0] IOAPIC[0]: apic_id 0, version 17, address 
0xfec00000, GSI 0-23
[    0.162477][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl 
dfl)
[    0.163368][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 high 
level)
[    0.164307][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high 
level)
[    0.165179][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 
high level)
[    0.166072][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 
high level)
[    0.167104][    T0] ACPI: Using ACPI (MADT) for SMP configuration 
information
[    0.168020][    T0] ACPI: HPET id: 0x8086a201 base: 0xfed00000
[    0.168753][    T0] CPU topo: Max. logical packages:   1
[    0.169388][    T0] CPU topo: Max. logical dies:       1
[    0.170105][    T0] CPU topo: Max. dies per package:   1
[    0.170755][    T0] CPU topo: Max. threads per core:   1
[    0.171425][    T0] CPU topo: Num. cores per package:     4
[    0.172098][    T0] CPU topo: Num. threads per package:   4
[    0.172768][    T0] CPU topo: Allowing 4 present CPUs plus 0 hotplug CPUs
[    0.173666][    T0] kvm-guest: APIC: eoi() replaced with 
kvm_guest_apic_eoi_write()
[    0.174647][    T0] PM: hibernation: Registered nosave memory: [mem 
0x00000000-0x00000fff]
[    0.175638][    T0] PM: hibernation: Registered nosave memory: [mem 
0x0009f000-0x0009ffff]
[    0.176618][    T0] PM: hibernation: Registered nosave memory: [mem 
0x000a0000-0x000effff]
[    0.177601][    T0] PM: hibernation: Registered nosave memory: [mem 
0x000f0000-0x000fffff]
[    0.178619][    T0] PM: hibernation: Registered nosave memory: [mem 
0xbffe0000-0xbfffffff]
[    0.179679][    T0] PM: hibernation: Registered nosave memory: [mem 
0xc0000000-0xfeffbfff]
[    0.180693][    T0] PM: hibernation: Registered nosave memory: [mem 
0xfeffc000-0xfeffffff]
[    0.181678][    T0] PM: hibernation: Registered nosave memory: [mem 
0xff000000-0xfffbffff]
[    0.182666][    T0] PM: hibernation: Registered nosave memory: [mem 
0xfffc0000-0xffffffff]
[    0.183685][    T0] [mem 0xc0000000-0xfeffbfff] available for PCI devices
[    0.184579][    T0] Booting paravirtualized kernel on KVM
[    0.185240][    T0] clocksource: refined-jiffies: mask: 0xffffffff 
max_cycles: 0xffffffff, max_idle_ns: 19112604462750000 ns
[    0.423328][    T0] setup_percpu: NR_CPUS:8 nr_cpumask_bits:4 
nr_cpu_ids:4 nr_node_ids:2
[    0.425291][    T0] percpu: Embedded 181 pages/cpu s702280 r8192 d30904 
u1048576
[    0.426789][    T0] kvm-guest: PV spinlocks disabled, no host support
[    0.427805][    T0] Kernel command line: earlyprintk=serial 
net.ifnames=0 sysctl.kernel.hung_task_all_cpu_backtrace=1 ima_policy=tcbr
[    0.444920][    T0] Unknown kernel command line parameters "nokaslr 
spec_store_bypass_disable=prctl", will be passed to user space.
[    0.446895][    T0] Fallback order for Node 0: 0 1
[    0.446923][    T0] Fallback order for Node 1: 1 0
[    0.446943][    T0] Built 2 zonelists, mobility grouping on.  Total 
pages: 1572734
[    0.449582][    T0] Policy zone: Normal
[    0.450385][    T0] mem auto-init: stack:off, heap alloc:off, heap 
free:off
[    0.665319][    T0] stackdepot: allocating hash table via 
alloc_large_system_hash
[    0.666663][    T0] stackdepot hash table entries: 524288 (order: 11, 
8388608 bytes, linear)
[    0.668712][    T0] software IO TLB: area num 4.
[    1.133300][    T0] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, 
Nodes=2
[    1.236347][    T0] allocated 125829120 bytes of page_ext
[    1.239779][    T0] Node 0, zone      DMA: page owner found early 
allocated 2816 pages
[    1.520742][    T0] Node 0, zone    DMA32: page owner found early 
allocated 432511 pages
[    1.732110][    T0] Node 1, zone   Normal: page owner found early 
allocated 310673 pages
[    1.734395][    T0] Kernel/User page tables isolation: enabled
[    1.736587][    T0] Starting KernelMemorySanitizer
[    1.737306][    T0] ATTENTION: KMSAN is a debugging tool! Do not use it 
on production machines!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn%40googlegroups.com.

------=_Part_64417_436716256.1727978707961
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello,<div><br /></div><div>I need help with the Linux boot issue with KMSA=
N.</div><div>On x86_64 I've enabled KMSAN and KMSAN_KUNIT_TEST</div><div>to=
 work with adding kmsan check in one of kernel function.</div><div><br /></=
div><div>Booting is stuck after this line:</div><div>"ATTENTION: KMSAN is a=
 debugging tool! Do not use it on production machines!"</div><div><br /></d=
iv><div>I couldn't figure out the guidance myself browsing the internet</di=
v><div>or looking for the documentation:</div><div>https://docs.kernel.org/=
dev-tools/kmsan.html<br /></div><div><br /></div><div>Please suggest. Not s=
ure if this is the right group to ask.</div><div><br /></div><div>Kernel co=
nfig (linux-next, next-20241002 tag):</div><div>https://gist.github.com/nov=
itoll/bdad35d2d1d29d708430194930b4497b<br /></div><div><br /></div><div>Con=
sole log with QEMU cmdline params:</div><div>+ qemu-system-x86_64 -m 6G -sm=
p 4 -kernel ./linux-next/arch/x86/boot/bzImage -append 'console=3DttyS0 roo=
t=3D/dev/sda earlyprintk=3Dserial net.iframes=3D0 nokaslr' -drive file=3D./=
bullseye.img,format=3Draw -net user,host=3D10.0.2.10,hostfwd=3Dtcp:127.0.0.=
1:10022-:22 -net nic,model=3De1000<br />-enable-kvm -nographic -s -pidfile =
vm.pid<br />qemu-system-x86_64: warning: host doesn't support requested fea=
ture: CPUID.80000001H:ECX.svm [bit 2]<br />qemu-system-x86_64: warning: hos=
t doesn't support requested feature: CPUID.80000001H:ECX.svm [bit 2]<br />q=
emu-system-x86_64: warning: host doesn't support requested feature: CPUID.8=
0000001H:ECX.svm [bit 2]<br />qemu-system-x86_64: warning: host doesn't sup=
port requested feature: CPUID.80000001H:ECX.svm [bit 2]<br />SeaBIOS (versi=
on 1.15.0-1)<br /><br />iPXE (https://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PM=
M+BFF8B310+BFECB310 CA00<br /><br />Booting from ROM...<br />early console =
in extract_kernel<br />input_data: 0x0000000015fd72a3<br />input_len: 0x000=
0000009c0e693<br />output: 0x0000000001000000<br />output_len: 0x0000000017=
b82df0<br />kernel_total_size: 0x000000001ec26000<br />needed_size: 0x00000=
0001ee00000<br />trampoline_32bit: 0x0000000000000000<br /><br />Decompress=
ing Linux... Parsing ELF... done.<br />Booting the kernel (entry_offset: 0x=
0000000000000112).<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] Linux ve=
rsion 6.12.0-rc1-next-20241002-dirty (user@linux) (Ubuntu clang version 14.=
0.0-1ubuntu1.1, Ubuntu 4<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] Co=
mmand line: console=3DttyS0 root=3D/dev/sda earlyprintk=3Dserial net.iframe=
s=3D0 nokaslr<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] KERNEL suppor=
ted cpus:<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] =C2=A0 Intel Genu=
ineIntel<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] =C2=A0 AMD Authent=
icAMD<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] BIOS-provided physica=
l RAM map:<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] BIOS-e820: [mem =
0x0000000000000000-0x000000000009fbff] usable<br />[ =C2=A0 =C2=A00.000000]=
[ =C2=A0 =C2=A0T0] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] r=
eserved<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] BIOS-e820: [mem 0x0=
0000000000f0000-0x00000000000fffff] reserved<br />[ =C2=A0 =C2=A00.000000][=
 =C2=A0 =C2=A0T0] BIOS-e820: [mem 0x0000000000100000-0x00000000bffdffff] us=
able<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] BIOS-e820: [mem 0x0000=
0000bffe0000-0x00000000bfffffff] reserved<br />[ =C2=A0 =C2=A00.000000][ =
=C2=A0 =C2=A0T0] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] res=
erved<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] BIOS-e820: [mem 0x000=
00000fffc0000-0x00000000ffffffff] reserved<br />[ =C2=A0 =C2=A00.000000][ =
=C2=A0 =C2=A0T0] BIOS-e820: [mem 0x0000000100000000-0x00000001bfffffff] usa=
ble<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] printk: legacy bootcons=
ole [earlyser0] enabled<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ERR=
OR: earlyprintk=3D earlyser already used<br />[ =C2=A0 =C2=A00.000000][ =C2=
=A0 =C2=A0T0] ERROR: earlyprintk=3D earlyser already used<br />[ =C2=A0 =C2=
=A00.000000][ =C2=A0 =C2=A0T0] ERROR: earlyprintk=3D earlyser already used<=
br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ***************************=
*******************************<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=
=A0T0] ** =C2=A0 NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE =C2=A0 **=
<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ** =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0**<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ** T=
his system shows unhashed kernel memory addresses =C2=A0 **<br />[ =C2=A0 =
=C2=A00.000000][ =C2=A0 =C2=A0T0] ** via the console, logs, and other inter=
faces. This =C2=A0 =C2=A0**<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0]=
 ** might reduce the security of your system. =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0**<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ** =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0**<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =
=C2=A0T0] ** If you see this message and you are not debugging =C2=A0 =C2=
=A0**<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ** the kernel, report=
 this immediately to your system =C2=A0 **<br />[ =C2=A0 =C2=A00.000000][ =
=C2=A0 =C2=A0T0] ** administrator! =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 **<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ** =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0**<br />[ =C2=A0 =C2=A00.000000][ =
=C2=A0 =C2=A0T0] ** =C2=A0 NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE=
 =C2=A0 **<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] ****************=
******************************************<br />[ =C2=A0 =C2=A00.000000][ =
=C2=A0 =C2=A0T0] Malformed early option 'vsyscall'<br />[ =C2=A0 =C2=A00.00=
0000][ =C2=A0 =C2=A0T0] NX (Execute Disable) protection: active<br />[ =C2=
=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] APIC: Static calls initialized<br />[=
 =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T0] SMBIOS 2.8 present.<br />[ =C2=A0=
 =C2=A00.000000][ =C2=A0 =C2=A0T0] DMI: QEMU Standard PC (i440FX + PIIX, 19=
96), BIOS 1.15.0-1 04/01/2014<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =C2=A0T=
0] DMI: Memory slots populated: 1/1 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0[34/1773]<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =
=C2=A0T0] Hypervisor detected: KVM<br />[ =C2=A0 =C2=A00.000000][ =C2=A0 =
=C2=A0T0] kvm-clock: Using msrs 4b564d01 and 4b564d00<br />[ =C2=A0 =C2=A00=
.000008][ =C2=A0 =C2=A0T0] kvm-clock: using sched offset of 1729977656 cycl=
es<br />[ =C2=A0 =C2=A00.001150][ =C2=A0 =C2=A0T0] clocksource: kvm-clock: =
mask: 0xffffffffffffffff max_cycles: 0x1cd42e4dffb, max_idle_ns: 8815905914=
83 ns<br />[ =C2=A0 =C2=A00.004521][ =C2=A0 =C2=A0T0] tsc: Detected 4199.99=
6 MHz processor<br />[ =C2=A0 =C2=A00.012840][ =C2=A0 =C2=A0T0] last_pfn =
=3D 0x1c0000 max_arch_pfn =3D 0x400000000<br />[ =C2=A0 =C2=A00.013911][ =
=C2=A0 =C2=A0T0] MTRR map: 4 entries (3 fixed + 1 variable; max 19), built =
from 8 variable MTRRs<br />[ =C2=A0 =C2=A00.015645][ =C2=A0 =C2=A0T0] x86/P=
AT: Configuration [0-7]: WB =C2=A0WC =C2=A0UC- UC =C2=A0WB =C2=A0WP =C2=A0U=
C- WT<br />[ =C2=A0 =C2=A00.017121][ =C2=A0 =C2=A0T0] last_pfn =3D 0xbffe0 =
max_arch_pfn =3D 0x400000000<br />[ =C2=A0 =C2=A00.026479][ =C2=A0 =C2=A0T0=
] found SMP MP-table at [mem 0x000f5ba0-0x000f5baf]<br />[ =C2=A0 =C2=A00.0=
34297][ =C2=A0 =C2=A0T0] ACPI: Early table checksum verification disabled<b=
r />[ =C2=A0 =C2=A00.035435][ =C2=A0 =C2=A0T0] ACPI: RSDP 0x00000000000F59C=
0 000014 (v00 BOCHS )<br />[ =C2=A0 =C2=A00.036712][ =C2=A0 =C2=A0T0] ACPI:=
 RSDT 0x00000000BFFE1A1C 000034 (v01 BOCHS =C2=A0BXPC =C2=A0 =C2=A0 0000000=
1 BXPC 00000001)<br />[ =C2=A0 =C2=A00.038510][ =C2=A0 =C2=A0T0] ACPI: FACP=
 0x00000000BFFE18B8 000074 (v01 BOCHS =C2=A0BXPC =C2=A0 =C2=A0 00000001 BXP=
C 00000001)<br />[ =C2=A0 =C2=A00.040317][ =C2=A0 =C2=A0T0] ACPI: DSDT 0x00=
000000BFFE0040 001878 (v01 BOCHS =C2=A0BXPC =C2=A0 =C2=A0 00000001 BXPC 000=
00001)<br />[ =C2=A0 =C2=A00.042114][ =C2=A0 =C2=A0T0] ACPI: FACS 0x0000000=
0BFFE0000 000040<br />[ =C2=A0 =C2=A00.043169][ =C2=A0 =C2=A0T0] ACPI: APIC=
 0x00000000BFFE192C 000090 (v01 BOCHS =C2=A0BXPC =C2=A0 =C2=A0 00000001 BXP=
C 00000001)<br />[ =C2=A0 =C2=A00.044966][ =C2=A0 =C2=A0T0] ACPI: HPET 0x00=
000000BFFE19BC 000038 (v01 BOCHS =C2=A0BXPC =C2=A0 =C2=A0 00000001 BXPC 000=
00001)<br />[ =C2=A0 =C2=A00.046754][ =C2=A0 =C2=A0T0] ACPI: WAET 0x0000000=
0BFFE19F4 000028 (v01 BOCHS =C2=A0BXPC =C2=A0 =C2=A0 00000001 BXPC 00000001=
)<br />[ =C2=A0 =C2=A00.048542][ =C2=A0 =C2=A0T0] ACPI: Reserving FACP tabl=
e memory at [mem 0xbffe18b8-0xbffe192b]<br />[ =C2=A0 =C2=A00.050028][ =C2=
=A0 =C2=A0T0] ACPI: Reserving DSDT table memory at [mem 0xbffe0040-0xbffe18=
b7]<br />[ =C2=A0 =C2=A00.051507][ =C2=A0 =C2=A0T0] ACPI: Reserving FACS ta=
ble memory at [mem 0xbffe0000-0xbffe003f]<br />[ =C2=A0 =C2=A00.052992][ =
=C2=A0 =C2=A0T0] ACPI: Reserving APIC table memory at [mem 0xbffe192c-0xbff=
e19bb]<br />[ =C2=A0 =C2=A00.054472][ =C2=A0 =C2=A0T0] ACPI: Reserving HPET=
 table memory at [mem 0xbffe19bc-0xbffe19f3]<br />[ =C2=A0 =C2=A00.055948][=
 =C2=A0 =C2=A0T0] ACPI: Reserving WAET table memory at [mem 0xbffe19f4-0xbf=
fe1a1b]<br />[ =C2=A0 =C2=A00.057723][ =C2=A0 =C2=A0T0] No NUMA configurati=
on found<br />[ =C2=A0 =C2=A00.058542][ =C2=A0 =C2=A0T0] Faking a node at [=
mem 0x0000000000000000-0x00000001bfffffff]<br />[ =C2=A0 =C2=A00.059969][ =
=C2=A0 =C2=A0T0] Faking node 0 at [mem 0x0000000000001000-0x00000000fffffff=
f] (4095MB)<br />[ =C2=A0 =C2=A00.061531][ =C2=A0 =C2=A0T0] Faking node 1 a=
t [mem 0x0000000100000000-0x00000001bfffffff] (3072MB)<br />[ =C2=A0 =C2=A0=
0.063745][ =C2=A0 =C2=A0T0] NODE_DATA(0) allocated [mem 0xbffda540-0xbffdff=
ff]<br />[ =C2=A0 =C2=A00.064934][ =C2=A0 =C2=A0T0] NODE_DATA(1) allocated =
[mem 0x1bfff6540-0x1bfffbfff]<br />[ =C2=A0 =C2=A00.086550][ =C2=A0 =C2=A0T=
0] Zone ranges:<br />[ =C2=A0 =C2=A00.087104][ =C2=A0 =C2=A0T0] =C2=A0 DMA =
=C2=A0 =C2=A0 =C2=A0[mem 0x0000000000001000-0x0000000000ffffff]<br />[ =C2=
=A0 =C2=A00.088180][ =C2=A0 =C2=A0T0] =C2=A0 DMA32 =C2=A0 =C2=A0[mem 0x0000=
000001000000-0x00000000ffffffff]<br />[ =C2=A0 =C2=A00.089254][ =C2=A0 =C2=
=A0T0] =C2=A0 Normal =C2=A0 [mem 0x0000000100000000-0x00000001bfffffff]<br =
/>[ =C2=A0 =C2=A00.090331][ =C2=A0 =C2=A0T0] =C2=A0 Device =C2=A0 empty<br =
/>[ =C2=A0 =C2=A00.090919][ =C2=A0 =C2=A0T0] Movable zone start for each no=
de<br />[ =C2=A0 =C2=A00.091690][ =C2=A0 =C2=A0T0] Early memory node ranges=
<br />[ =C2=A0 =C2=A00.092347][ =C2=A0 =C2=A0T0] =C2=A0 node =C2=A0 0: [mem=
 0x0000000000001000-0x000000000009efff]<br />[ =C2=A0 =C2=A00.093445][ =C2=
=A0 =C2=A0T0] =C2=A0 node =C2=A0 0: [mem 0x0000000000100000-0x00000000bffdf=
fff]<br />[ =C2=A0 =C2=A00.094537][ =C2=A0 =C2=A0T0] =C2=A0 node =C2=A0 1: =
[mem 0x0000000100000000-0x00000001bfffffff]<br />[ =C2=A0 =C2=A00.095551][ =
=C2=A0 =C2=A0T0] Initmem setup node 0 [mem 0x0000000000001000-0x00000000bff=
dffff]<br />[ =C2=A0 =C2=A00.096562][ =C2=A0 =C2=A0T0] Initmem setup node 1=
 [mem 0x0000000100000000-0x00000001bfffffff]<br />[ =C2=A0 =C2=A00.097595][=
 =C2=A0 =C2=A0T0] On node 0, zone DMA: 1 pages in unavailable ranges<br />[=
 =C2=A0 =C2=A00.098589][ =C2=A0 =C2=A0T0] On node 0, zone DMA: 97 pages in =
unavailable ranges<br />[ =C2=A0 =C2=A00.158915][ =C2=A0 =C2=A0T0] On node =
1, zone Normal: 32 pages in unavailable ranges<br />[ =C2=A0 =C2=A00.160102=
][ =C2=A0 =C2=A0T0] ACPI: PM-Timer IO Port: 0x608<br />[ =C2=A0 =C2=A00.160=
700][ =C2=A0 =C2=A0T0] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])<br=
 />[ =C2=A0 =C2=A00.161554][ =C2=A0 =C2=A0T0] IOAPIC[0]: apic_id 0, version=
 17, address 0xfec00000, GSI 0-23<br />[ =C2=A0 =C2=A00.162477][ =C2=A0 =C2=
=A0T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)<br />[ =C2=
=A0 =C2=A00.163368][ =C2=A0 =C2=A0T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 gl=
obal_irq 5 high level)<br />[ =C2=A0 =C2=A00.164307][ =C2=A0 =C2=A0T0] ACPI=
: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high level)<br />[ =C2=A0 =C2=
=A00.165179][ =C2=A0 =C2=A0T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_i=
rq 10 high level)<br />[ =C2=A0 =C2=A00.166072][ =C2=A0 =C2=A0T0] ACPI: INT=
_SRC_OVR (bus 0 bus_irq 11 global_irq 11 high level)<br />[ =C2=A0 =C2=A00.=
167104][ =C2=A0 =C2=A0T0] ACPI: Using ACPI (MADT) for SMP configuration inf=
ormation<br />[ =C2=A0 =C2=A00.168020][ =C2=A0 =C2=A0T0] ACPI: HPET id: 0x8=
086a201 base: 0xfed00000<br />[ =C2=A0 =C2=A00.168753][ =C2=A0 =C2=A0T0] CP=
U topo: Max. logical packages: =C2=A0 1<br />[ =C2=A0 =C2=A00.169388][ =C2=
=A0 =C2=A0T0] CPU topo: Max. logical dies: =C2=A0 =C2=A0 =C2=A0 1<br />[ =
=C2=A0 =C2=A00.170105][ =C2=A0 =C2=A0T0] CPU topo: Max. dies per package: =
=C2=A0 1<br />[ =C2=A0 =C2=A00.170755][ =C2=A0 =C2=A0T0] CPU topo: Max. thr=
eads per core: =C2=A0 1<br />[ =C2=A0 =C2=A00.171425][ =C2=A0 =C2=A0T0] CPU=
 topo: Num. cores per package: =C2=A0 =C2=A0 4<br />[ =C2=A0 =C2=A00.172098=
][ =C2=A0 =C2=A0T0] CPU topo: Num. threads per package: =C2=A0 4<br />[ =C2=
=A0 =C2=A00.172768][ =C2=A0 =C2=A0T0] CPU topo: Allowing 4 present CPUs plu=
s 0 hotplug CPUs<br />[ =C2=A0 =C2=A00.173666][ =C2=A0 =C2=A0T0] kvm-guest:=
 APIC: eoi() replaced with kvm_guest_apic_eoi_write()<br />[ =C2=A0 =C2=A00=
.174647][ =C2=A0 =C2=A0T0] PM: hibernation: Registered nosave memory: [mem =
0x00000000-0x00000fff]<br />[ =C2=A0 =C2=A00.175638][ =C2=A0 =C2=A0T0] PM: =
hibernation: Registered nosave memory: [mem 0x0009f000-0x0009ffff]<br />[ =
=C2=A0 =C2=A00.176618][ =C2=A0 =C2=A0T0] PM: hibernation: Registered nosave=
 memory: [mem 0x000a0000-0x000effff]<br />[ =C2=A0 =C2=A00.177601][ =C2=A0 =
=C2=A0T0] PM: hibernation: Registered nosave memory: [mem 0x000f0000-0x000f=
ffff]<br />[ =C2=A0 =C2=A00.178619][ =C2=A0 =C2=A0T0] PM: hibernation: Regi=
stered nosave memory: [mem 0xbffe0000-0xbfffffff]<br />[ =C2=A0 =C2=A00.179=
679][ =C2=A0 =C2=A0T0] PM: hibernation: Registered nosave memory: [mem 0xc0=
000000-0xfeffbfff]<br />[ =C2=A0 =C2=A00.180693][ =C2=A0 =C2=A0T0] PM: hibe=
rnation: Registered nosave memory: [mem 0xfeffc000-0xfeffffff]<br />[ =C2=
=A0 =C2=A00.181678][ =C2=A0 =C2=A0T0] PM: hibernation: Registered nosave me=
mory: [mem 0xff000000-0xfffbffff]<br />[ =C2=A0 =C2=A00.182666][ =C2=A0 =C2=
=A0T0] PM: hibernation: Registered nosave memory: [mem 0xfffc0000-0xfffffff=
f]<br />[ =C2=A0 =C2=A00.183685][ =C2=A0 =C2=A0T0] [mem 0xc0000000-0xfeffbf=
ff] available for PCI devices<br />[ =C2=A0 =C2=A00.184579][ =C2=A0 =C2=A0T=
0] Booting paravirtualized kernel on KVM<br />[ =C2=A0 =C2=A00.185240][ =C2=
=A0 =C2=A0T0] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0x=
ffffffff, max_idle_ns: 19112604462750000 ns<br />[ =C2=A0 =C2=A00.423328][ =
=C2=A0 =C2=A0T0] setup_percpu: NR_CPUS:8 nr_cpumask_bits:4 nr_cpu_ids:4 nr_=
node_ids:2<br />[ =C2=A0 =C2=A00.425291][ =C2=A0 =C2=A0T0] percpu: Embedded=
 181 pages/cpu s702280 r8192 d30904 u1048576<br />[ =C2=A0 =C2=A00.426789][=
 =C2=A0 =C2=A0T0] kvm-guest: PV spinlocks disabled, no host support<br />[ =
=C2=A0 =C2=A00.427805][ =C2=A0 =C2=A0T0] Kernel command line: earlyprintk=
=3Dserial net.ifnames=3D0 sysctl.kernel.hung_task_all_cpu_backtrace=3D1 ima=
_policy=3Dtcbr<br />[ =C2=A0 =C2=A00.444920][ =C2=A0 =C2=A0T0] Unknown kern=
el command line parameters "nokaslr spec_store_bypass_disable=3Dprctl", wil=
l be passed to user space.<br />[ =C2=A0 =C2=A00.446895][ =C2=A0 =C2=A0T0] =
Fallback order for Node 0: 0 1<br />[ =C2=A0 =C2=A00.446923][ =C2=A0 =C2=A0=
T0] Fallback order for Node 1: 1 0<br />[ =C2=A0 =C2=A00.446943][ =C2=A0 =
=C2=A0T0] Built 2 zonelists, mobility grouping on. =C2=A0Total pages: 15727=
34<br />[ =C2=A0 =C2=A00.449582][ =C2=A0 =C2=A0T0] Policy zone: Normal<br /=
>[ =C2=A0 =C2=A00.450385][ =C2=A0 =C2=A0T0] mem auto-init: stack:off, heap =
alloc:off, heap free:off<br />[ =C2=A0 =C2=A00.665319][ =C2=A0 =C2=A0T0] st=
ackdepot: allocating hash table via alloc_large_system_hash<br />[ =C2=A0 =
=C2=A00.666663][ =C2=A0 =C2=A0T0] stackdepot hash table entries: 524288 (or=
der: 11, 8388608 bytes, linear)<br />[ =C2=A0 =C2=A00.668712][ =C2=A0 =C2=
=A0T0] software IO TLB: area num 4.<br />[ =C2=A0 =C2=A01.133300][ =C2=A0 =
=C2=A0T0] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D4, Nodes=
=3D2<br />[ =C2=A0 =C2=A01.236347][ =C2=A0 =C2=A0T0] allocated 125829120 by=
tes of page_ext<br />[ =C2=A0 =C2=A01.239779][ =C2=A0 =C2=A0T0] Node 0, zon=
e =C2=A0 =C2=A0 =C2=A0DMA: page owner found early allocated 2816 pages<br /=
>[ =C2=A0 =C2=A01.520742][ =C2=A0 =C2=A0T0] Node 0, zone =C2=A0 =C2=A0DMA32=
: page owner found early allocated 432511 pages<br />[ =C2=A0 =C2=A01.73211=
0][ =C2=A0 =C2=A0T0] Node 1, zone =C2=A0 Normal: page owner found early all=
ocated 310673 pages<br />[ =C2=A0 =C2=A01.734395][ =C2=A0 =C2=A0T0] Kernel/=
User page tables isolation: enabled<br />[ =C2=A0 =C2=A01.736587][ =C2=A0 =
=C2=A0T0] Starting KernelMemorySanitizer<br />[ =C2=A0 =C2=A01.737306][ =C2=
=A0 =C2=A0T0] ATTENTION: KMSAN is a debugging tool! Do not use it on produc=
tion machines!<br /></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/b6b89138-54d0-4f6f-86d3-6ed50fd6e80dn%40googlegroups.com</a>.<b=
r />

------=_Part_64417_436716256.1727978707961--

------=_Part_64416_1683452301.1727978707961--
