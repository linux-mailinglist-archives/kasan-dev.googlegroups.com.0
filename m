Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4VF46BAMGQEWV6WP2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 8185B345D12
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 12:37:23 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id v18sf997752qtx.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 04:37:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616499442; cv=pass;
        d=google.com; s=arc-20160816;
        b=auPb9ZoMAH0o+kb4w3EtxYcFCNWDF0yQIBAMkzs21R1A78lKmAusRIighkk2bsCwmk
         dro4oZoqGcPeuyR2ncVkIbg/K2U04pcFL0RzfyIjbux+Bj9SlUm1CWHkCGrYJCQvOWvl
         2uDOsRwi6wBl6FENhEbSLc0wUJaZwuuRMz66ZAZbuX6ppmyQDHm44jGwSoXIb2ZoychP
         F6ekW1trMepmUTT23FdHmZqzPa2BlddjzZ2BhrfSm11wF2pjCj2yyZLpaPnaf6ZmbeUA
         v8J6O1wNRAOC/450x1964NDnhAc0Clha6poCB5F7e089EnK9Qwqf2e2E1uiDSSw2YwRj
         pPOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=znzqdlGpwAVYAX3zuAaKkNnG6YMTUppkQRqrOHxhulY=;
        b=OU76Yq/BLcFjLRVoTfN1OMuGaSKo7JKgiI5+gGbb6+zjvDpzkcKAc8QWvzWxzfzGIq
         kt6e/WB0lB9yNwY6o2uBhwlDMJPte/hA740G/Sfj9L0OazsXkMtBf4a97O/fe66w1MPy
         PJwA7ai3z9a1Hk9PeH7MDc5ZCnKEDQYa1/R0vgz0ZuoWsx+hUDr6787eV6MdkSP32DLH
         IU7TW6zEWyhXbTm9xJ+qBMlQQOJ2UVUejNnZ3ZCaj3kPdpAcCyHGEe9irEI/+Z5B+Xud
         003v63+8iSy/hPG3aapQTJJoTLZK5EiiqM/Afk08pUCO/r9c9dhsUAer2O5ZLNy9OElv
         Z0LQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o6D3PBtY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=znzqdlGpwAVYAX3zuAaKkNnG6YMTUppkQRqrOHxhulY=;
        b=OzWQdI1nLJaV8xuACk/1JX9y3Ij8Rgb+1UnThTi73j/NSjzgii21qQz58dNFSS+p/G
         L0yMTq5924RT118PNDCluV12QK5K/Z4pN7yfJh+vPG2TFQlXdTm3/na2PyoGmXlsDIHS
         loEqeS1RN8qib1Hp/uyePdCecy24QG6d8tLJMrz00PhNbZLB8jEaS54ITLfcw742pUD7
         MaK9q5cYteEsSqtkLIuwpgQTnkVkM2FrrZsDDRbZoYdhSXLLt6zZ9meD0tGS33UG11yl
         7nM8qfrNsrRIDDIddnM881d1c/2sbgE+JrmKYBFv/5GOVMf4uuYI422HPCK8gDPiS2vW
         X6+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=znzqdlGpwAVYAX3zuAaKkNnG6YMTUppkQRqrOHxhulY=;
        b=qjn2GW9LeFr7JD+7Lpl6yeUrrd+aVjQjPenIzi+6KTKDzf/GVvsT5SstPTD3cb+5jA
         dv66NImviFcrY1d1aABImsnjfJpWnHhcGXkUgSUquM27nIpGvOQz+DWOP0eazKEGS+3d
         6wEuDcpo29zMyWfm/D6b1S3orJgpLrQ+L5HNbW/miQGqQYEC/IEtG5aViobKJJWXLA5U
         qQy4gxoS9GLpSOUahFtTz4G9Ja+Om2EkVwLurnYKpOxLc7P3pDGESgMq+8RE6+587fmh
         DzO5ocZsFd6+x57EJIihMWTg+SDxB0vCAGMZG3NRwzH9jMAbl4AQ2lyMMYGD68pIhPUq
         +yEA==
X-Gm-Message-State: AOAM532q+ejDChODOi7/keS71tqxNIgg15WXMqClI4orW7yWPTjjhPAP
	qmme6k3CoVYPs4uPZF5aMJA=
X-Google-Smtp-Source: ABdhPJwQBSsIRNGHLOsyPboBaAqr3hT8n1H98mfXmjd22RBS11Gj30PsavbYu/ztX+qW7g4dYaf6ig==
X-Received: by 2002:ac8:568b:: with SMTP id h11mr4010822qta.157.1616499442581;
        Tue, 23 Mar 2021 04:37:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:c207:: with SMTP id i7ls8495683qkm.9.gmail; Tue, 23 Mar
 2021 04:37:22 -0700 (PDT)
X-Received: by 2002:a05:620a:661:: with SMTP id a1mr4813401qkh.153.1616499442057;
        Tue, 23 Mar 2021 04:37:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616499442; cv=none;
        d=google.com; s=arc-20160816;
        b=V2iweJjnsH2HOSA1/m4kvFEfZB/JMCJhY4Pg5Kc3RfKqmLRVIjMuhMDGV+XV7IPuB5
         /OO66qb2YNiA99PFthodkIDTXcHvnvfOo01HjXnyy4rfw8PVs4pwwRZaESVBjGGvRWMe
         d+Qa1OU0FQkIDjeVfpxa3/Q82Cea6/bve5FlXOfhdGqc2Q3h4A8Q/IR77Kbf+r1rijp5
         Hu6saGQQqXGRMlS8PaRI0v8NBSagGSGbbqfRC306wbCA9vOeiCcCixvBLrgKg9Jj9SZF
         4z7wvl4Xxx7dI108kmTJ45S4gfzJtZs/NW9l2nmLUKAh9QSpEtngEuSmvCSBTgQoBdiV
         Reug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1uz0YUxgZnaiemlBg5a8RL6IDk2aPOIBaVA+E7NV4XQ=;
        b=rm9Daw+EXvXJchrj68JdpR5hOmZ/rSOC/tAK6hFQ0LF6Ml8yV/P4v5/L2o513NpMrW
         zW82g/MCNIG5zlb+ETMlvum16d8SF+qM8UbD2nriwOCeoGHgOulGbNstQLwpTPoeq3Cw
         lPf6KklG2wGIFFB56+JKD1HD+Tujz15orvPKVX9mfJ/yHQRlTh8HauN1PbWtbDNKhG5j
         lz3w9bIEmh2W1HYm30CVyU2IpiYTu99FGnpHPn/8/YTnu/7+/yFnju+FZkx003/vPx/3
         Z2jgE/nYlP2EoMSVx+tcr4jLRIUyfPUlph3nKOt69Ems5qgcbhG9Kvdjlt3yUgmtCM9H
         o7eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o6D3PBtY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id j17si97569qko.3.2021.03.23.04.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 04:37:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id 125-20020a4a1a830000b02901b6a144a417so4843283oof.13
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 04:37:22 -0700 (PDT)
X-Received: by 2002:a05:6820:273:: with SMTP id c19mr3485825ooe.54.1616499441113;
 Tue, 23 Mar 2021 04:37:21 -0700 (PDT)
MIME-Version: 1.0
References: <ebe1d0bd-39fe-d7a0-9dcc-d8e70895a078@i-love.sakura.ne.jp>
In-Reply-To: <ebe1d0bd-39fe-d7a0-9dcc-d8e70895a078@i-love.sakura.ne.jp>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 12:37:09 +0100
Message-ID: <CANpmjNM60W4nYEYCEt9SJ9f4L194WEk_ORey8s+DbgnokJZ53g@mail.gmail.com>
Subject: Re: [5.12-rc4] int3 problem at kfence_alloc() when allocating memory.
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=o6D3PBtY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 23 Mar 2021 at 09:33, Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
> When I run
>
>   qemu-system-x86_64 -no-reboot -smp 8 -m 4G -kernel arch/x86/boot/bzImag=
e -nographic -append "oops=3Dpanic panic_on_warn=3D1 panic=3D1"
>
> on Ubuntu 20.04.2 LTS running on VMware Workstation on Windows PC, I rand=
omly hit crash at arch_static_branch() when allocating memory.
>
>   # ./scripts/faddr2line vmlinux kmem_cache_alloc_node_trace+0x1a4/0x8b0
>   kmem_cache_alloc_node_trace+0x1a4/0x8b0:
>   arch_static_branch at arch/x86/include/asm/jump_label.h:25

So this is pointing at asm_volatile_goto().

>   (inlined by) kfence_alloc at include/linux/kfence.h:119
>   (inlined by) slab_alloc_node at mm/slub.c:2830
>   (inlined by) kmem_cache_alloc_node_trace at mm/slub.c:2957
>
> Kernel config is at http://I-love.SAKURA.ne.jp/tmp/config-5.12-rc4-kfence=
 . Any ideas?

We're still trying to debug, but thus far have narrowed it down to:

1. A QEMU bug. It only reproduces in x86 emulation mode. When adding
-enable-kvm, it no longer reproduces. I also managed to segfault qemu.

2. A really bad race in jump_labels subsystem that only manifests in
emulation mode? Since we also continuously run on syzbot with various
instances, my guess is that we should have already found it on syzbot,
if this was the case.

I'm currently trying to repro the qemu segfault and also build qemu with AS=
an.


> ---------- Console output ----------
>  c [?7l [2J [0mSeaBIOS (version 1.13.0-1ubuntu1.1)
>
>
> iPXE (http://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+BFF8C8A0+BFECC8A0 CA0=
0
> Press Ctrl-B to configure iPXE (PCI 00:03.0)...
>
>
>
> Booting from ROM.. c [?7l [2J [0m.
> [    0.000000][    T0] Linux version 5.12.0-rc4 (root@syzbot) (gcc (Ubunt=
u 9.3.0-17ubuntu1~20.04) 9.3.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #21 =
SMP PREEMPT Tue Mar 23 08:00:22 UTC 2021
> [    0.000000][    T0] Command line: oops=3Dpanic panic_on_warn=3D1 panic=
=3D1
> [    0.000000][    T0] KERNEL supported cpus:
> [    0.000000][    T0]   Intel GenuineIntel
> [    0.000000][    T0]   AMD AuthenticAMD
> [    0.000000][    T0] x86/fpu: x87 FPU will use FXSAVE
> [    0.000000][    T0] BIOS-provided physical RAM map:
> [    0.000000][    T0] BIOS-e820: [mem 0x0000000000000000-0x000000000009f=
bff] usable
> [    0.000000][    T0] BIOS-e820: [mem 0x000000000009fc00-0x000000000009f=
fff] reserved
> [    0.000000][    T0] BIOS-e820: [mem 0x00000000000f0000-0x00000000000ff=
fff] reserved
> [    0.000000][    T0] BIOS-e820: [mem 0x0000000000100000-0x00000000bffde=
fff] usable
> [    0.000000][    T0] BIOS-e820: [mem 0x00000000bffdf000-0x00000000bffff=
fff] reserved
> [    0.000000][    T0] BIOS-e820: [mem 0x00000000fffc0000-0x00000000fffff=
fff] reserved
> [    0.000000][    T0] BIOS-e820: [mem 0x0000000100000000-0x000000013ffff=
fff] usable
> [    0.000000][    T0] **************************************************=
********
> [    0.000000][    T0] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOT=
ICE   **
> [    0.000000][    T0] **                                                =
      **
> [    0.000000][    T0] ** This system shows unhashed kernel memory addres=
ses   **
> [    0.000000][    T0] ** via the console, logs, and other interfaces. Th=
is    **
> [    0.000000][    T0] ** might reduce the security of your system.      =
      **
> [    0.000000][    T0] **                                                =
      **
> [    0.000000][    T0] ** If you see this message and you are not debuggi=
ng    **
> [    0.000000][    T0] ** the kernel, report this immediately to your sys=
tem   **
> [    0.000000][    T0] ** administrator!                                 =
      **
> [    0.000000][    T0] **                                                =
      **
> [    0.000000][    T0] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOT=
ICE   **
> [    0.000000][    T0] **************************************************=
********
> [    0.000000][    T0] Malformed early option 'vsyscall'
> [    0.000000][    T0] NX (Execute Disable) protection: active
> [    0.000000][    T0] SMBIOS 2.8 present.
> [    0.000000][    T0] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS =
1.13.0-1ubuntu1.1 04/01/2014
> [    0.000000][    T0] last_pfn =3D 0x140000 max_arch_pfn =3D 0x400000000
> [    0.000000][    T0] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  =
WP  UC- WT
> [    0.000000][    T0] last_pfn =3D 0xbffdf max_arch_pfn =3D 0x400000000
> [    0.000000][    T0] found SMP MP-table at [mem 0x000f5c10-0x000f5c1f]
> [    0.000000][    T0] ACPI: Early table checksum verification disabled
> [    0.000000][    T0] ACPI: RSDP 0x00000000000F5BD0 000014 (v00 BOCHS )
> [    0.000000][    T0] ACPI: RSDT 0x00000000BFFE143E 000030 (v01 BOCHS  B=
XPCRSDT 00000001 BXPC 00000001)
> [    0.000000][    T0] ACPI: FACP 0x00000000BFFE12E2 000074 (v01 BOCHS  B=
XPCFACP 00000001 BXPC 00000001)
> [    0.000000][    T0] ACPI: DSDT 0x00000000BFFDFC80 001662 (v01 BOCHS  B=
XPCDSDT 00000001 BXPC 00000001)
> [    0.000000][    T0] ACPI: FACS 0x00000000BFFDFC40 000040
> [    0.000000][    T0] ACPI: APIC 0x00000000BFFE1356 0000B0 (v01 BOCHS  B=
XPCAPIC 00000001 BXPC 00000001)
> [    0.000000][    T0] ACPI: HPET 0x00000000BFFE1406 000038 (v01 BOCHS  B=
XPCHPET 00000001 BXPC 00000001)
> [    0.000000][    T0] No NUMA configuration found
> [    0.000000][    T0] Faking a node at [mem 0x0000000000000000-0x0000000=
13fffffff]
> [    0.000000][    T0] Faking node 0 at [mem 0x0000000000000000-0x0000000=
07fffffff] (2048MB)
> [    0.000000][    T0] Faking node 1 at [mem 0x0000000080000000-0x0000000=
13fffffff] (3072MB)
> [    0.000000][    T0] NODE_DATA(0) allocated [mem 0x7fffb000-0x7fffffff]
> [    0.000000][    T0] NODE_DATA(1) allocated [mem 0x13fff7000-0x13fffbff=
f]
> [    0.000000][    T0] Zone ranges:
> [    0.000000][    T0]   DMA      [mem 0x0000000000001000-0x0000000000fff=
fff]
> [    0.000000][    T0]   DMA32    [mem 0x0000000001000000-0x00000000fffff=
fff]
> [    0.000000][    T0]   Normal   [mem 0x0000000100000000-0x000000013ffff=
fff]
> [    0.000000][    T0]   Device   empty
> [    0.000000][    T0] Movable zone start for each node
> [    0.000000][    T0] Early memory node ranges
> [    0.000000][    T0]   node   0: [mem 0x0000000000001000-0x000000000009=
efff]
> [    0.000000][    T0]   node   0: [mem 0x0000000000100000-0x000000007fff=
ffff]
> [    0.000000][    T0]   node   1: [mem 0x0000000080000000-0x00000000bffd=
efff]
> [    0.000000][    T0]   node   1: [mem 0x0000000100000000-0x000000013fff=
ffff]
> [    0.000000][    T0] Initmem setup node 0 [mem 0x0000000000001000-0x000=
000007fffffff]
> [    0.000000][    T0]   DMA zone: 28770 pages in unavailable ranges
> [    0.000000][    T0] Initmem setup node 1 [mem 0x0000000080000000-0x000=
000013fffffff]
> [    0.000000][    T0]   DMA32 zone: 33 pages in unavailable ranges
> [    0.000000][    T0] ACPI: PM-Timer IO Port: 0x608
> [    0.000000][    T0] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])
> [    0.000000][    T0] IOAPIC[0]: apic_id 0, version 32, address 0xfec000=
00, GSI 0-23
> [    0.000000][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 df=
l dfl)
> [    0.000000][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 hi=
gh level)
> [    0.000000][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 hi=
gh level)
> [    0.000000][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 =
high level)
> [    0.000000][    T0] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 =
high level)
> [    0.000000][    T0] Using ACPI (MADT) for SMP configuration informatio=
n
> [    0.000000][    T0] ACPI: HPET id: 0x8086a201 base: 0xfed00000
> [    0.000000][    T0] smpboot: Allowing 8 CPUs, 0 hotplug CPUs
> [    0.000000][    T0] [mem 0xc0000000-0xfffbffff] available for PCI devi=
ces
> [    0.000000][    T0] Booting paravirtualized kernel on bare hardware
> [    0.000000][    T0] clocksource: refined-jiffies: mask: 0xffffffff max=
_cycles: 0xffffffff, max_idle_ns: 19112604462750000 ns
> [    0.000000][    T0] setup_percpu: NR_CPUS:8 nr_cpumask_bits:8 nr_cpu_i=
ds:8 nr_node_ids:2
> [    0.000000][    T0] percpu: Embedded 51 pages/cpu s178072 r0 d30824 u5=
24288
> [    0.000000][    T0] Built 2 zonelists, mobility grouping on.  Total pa=
ges: 1032040
> [    0.000000][    T0] Policy zone: Normal
> [    0.000000][    T0] Kernel command line: earlyprintk=3Dserial net.ifna=
mes=3D0 sysctl.kernel.hung_task_all_cpu_backtrace=3D1 ima_policy=3Dtcb nf-c=
onntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=3D20000 nf-conntrack-sip=
.ports=3D20000 nf-conntrack-irc.ports=3D20000 nf-conntrack-sane.ports=3D200=
00 binder.debug_mask=3D0 rcupdate.rcu_expedited=3D1 no_hash_pointers root=
=3D/dev/sda console=3DttyS0 vsyscall=3Dnative numa=3Dfake=3D2 kvm-intel.nes=
ted=3D1 spec_store_bypass_disable=3Dprctl nopcid vivid.n_devs=3D16 vivid.mu=
ltiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 netrom.nr_ndevs=3D16 rose.rose_=
ndevs=3D16 dummy_hcd.num=3D8 watchdog_thresh=3D55 workqueue.watchdog_thresh=
=3D140 panic_on_warn=3D1 oops=3Dpanic panic_on_warn=3D1 panic=3D1
> [    0.000000][    T0] mem auto-init: stack:off, heap alloc:on, heap free=
:off
> [    0.000000][    T0] Memory: 4021052K/4193780K available (10248K kernel=
 code, 2509K rwdata, 2804K rodata, 2304K init, 12648K bss, 172472K reserved=
, 0K cma-reserved)
> [    0.000000][    T0] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, C=
PUs=3D8, Nodes=3D2
> [    0.000000][    T0] Running RCU self tests
> [    0.000000][    T0] rcu: Preemptible hierarchical RCU implementation.
> [    0.000000][    T0] rcu:     RCU lockdep checking is enabled.
> [    0.000000][    T0] rcu:     RCU debug extended QS entry/exit.
> [    0.000000][    T0]  All grace periods are expedited (rcu_expedited).
> [    0.000000][    T0]  Trampoline variant of Tasks RCU enabled.
> [    0.000000][    T0]  Tracing variant of Tasks RCU enabled.
> [    0.000000][    T0] rcu: RCU calculated value of scheduler-enlistment =
delay is 10 jiffies.
> [    0.000000][    T0] NR_IRQS: 4352, nr_irqs: 488, preallocated irqs: 16
> [    0.000000][    T0] kfence: initialized - using 2097152 bytes for 255 =
objects at 0xffff88813da00000-0xffff88813dc00000
> [    0.000000][    T0] random: get_random_bytes called from start_kernel+=
0x3a8/0x555 with crng_init=3D0
> [    0.000000][    T0] Console: colour dummy device 80x25
> [    0.000000][    T0] printk: console [ttyS0] enabled
> [    0.000000][    T0] Lock dependency validator: Copyright (c) 2006 Red =
Hat, Inc., Ingo Molnar
> [    0.000000][    T0] ... MAX_LOCKDEP_SUBCLASSES:  8
> [    0.000000][    T0] ... MAX_LOCK_DEPTH:          48
> [    0.000000][    T0] ... MAX_LOCKDEP_KEYS:        8192
> [    0.000000][    T0] ... CLASSHASH_SIZE:          4096
> [    0.000000][    T0] ... MAX_LOCKDEP_ENTRIES:     32768
> [    0.000000][    T0] ... MAX_LOCKDEP_CHAINS:      65536
> [    0.000000][    T0] ... CHAINHASH_SIZE:          32768
> [    0.000000][    T0]  memory used by lock dependency info: 6365 kB
> [    0.000000][    T0]  memory used for stack traces: 4224 kB
> [    0.000000][    T0]  per task-struct memory footprint: 1920 bytes
> [    0.000000][    T0] mempolicy: Enabling automatic NUMA balancing. Conf=
igure with numa_balancing=3D or the kernel.numa_balancing sysctl
> [    0.000000][    T0] ACPI: Core revision 20210105
> [    0.000000][    T0] clocksource: hpet: mask: 0xffffffff max_cycles: 0x=
ffffffff, max_idle_ns: 19112604467 ns
> [    0.010000][    T0] APIC: Switch to symmetric I/O mode setup
> [    0.010000][    T0] ..TIMER: vector=3D0x30 apic1=3D0 pin1=3D2 apic2=3D=
-1 pin2=3D-1
> [    0.090000][    T0] tsc: Unable to calibrate against PIT
> [    0.090000][    T0] tsc: using HPET reference calibration
> [    0.090000][    T0] tsc: Detected 2804.952 MHz processor
> [    0.000401][    T0] tsc: Marking TSC unstable due to TSCs unsynchroniz=
ed
> [    0.000904][    T0] Calibrating delay loop (skipped), value calculated=
 using timer frequency.. 5609.90 BogoMIPS (lpj=3D28049520)
> [    0.001519][    T0] pid_max: default: 32768 minimum: 301
> [    0.006777][    T0] Dentry cache hash table entries: 524288 (order: 10=
, 4194304 bytes, vmalloc)
> [    0.011496][    T0] Inode-cache hash table entries: 262144 (order: 9, =
2097152 bytes, vmalloc)
> [    0.012086][    T0] Mount-cache hash table entries: 8192 (order: 4, 65=
536 bytes, vmalloc)
> [    0.012384][    T0] Mountpoint-cache hash table entries: 8192 (order: =
4, 65536 bytes, vmalloc)
> [    0.037404][    T0] Last level iTLB entries: 4KB 0, 2MB 0, 4MB 0
> [    0.037643][    T0] Last level dTLB entries: 4KB 0, 2MB 0, 4MB 0, 1GB =
0
> [    0.038128][    T0] Spectre V1 : Mitigation: usercopy/swapgs barriers =
and __user pointer sanitization
> [    0.038551][    T0] Spectre V2 : Spectre mitigation: kernel not compil=
ed with retpoline; no mitigation available!
> [    0.038595][    T0] Speculative Store Bypass: Vulnerable
> [    0.044064][    T0] Freeing SMP alternatives memory: 20K
> [    0.184259][    T1] smpboot: CPU0: AMD QEMU Virtual CPU version 2.5+ (=
family: 0x6, model: 0x6, stepping: 0x3)
> [    0.202010][    T1] Running RCU-tasks wait API self tests
> [    0.317124][    T1] Performance Events: PMU not available due to virtu=
alization, using software events only.
> [    0.336553][    T1] rcu: Hierarchical SRCU implementation.
> [    0.341456][   T12] Callback from call_rcu_tasks_trace() invoked.
> [    0.354762][    T1] NMI watchdog: Perf NMI watchdog permanently disabl=
ed
> [    0.361412][    T1] smp: Bringing up secondary CPUs ...
> [    0.368844][    T1] x86: Booting SMP configuration:
> [    0.369145][    T1] .... node  #1, CPUs:      #1
> [    0.000000][    T0] calibrate_delay_direct() dropping max bogoMips est=
imate 2 =3D 34110035
> [    0.567307][    T1]
> [    0.567739][    T1] .... node  #0, CPUs:   #2
> [    0.721337][   T11] Callback from call_rcu_tasks() invoked.
> [    0.732163][    T1]
> [    0.732335][    T1] .... node  #1, CPUs:   #3
> [    0.902206][    T1] .... node  #0, CPUs:   #4
> [    0.000000][    T0] calibrate_delay_direct() dropping max bogoMips est=
imate 1 =3D 34892924
> [    1.072362][    T1]
> [    1.072534][    T1] .... node  #1, CPUs:   #5
> [    0.000000][    T0] calibrate_delay_direct() dropping max bogoMips est=
imate 2 =3D 35422631
> [    1.242006][    T1]
> [    1.242175][    T1] .... node  #0, CPUs:   #6
> [    1.412155][    T1] .... node  #1, CPUs:   #7
> [    0.000000][    T0] calibrate_delay_direct() dropping max bogoMips est=
imate 1 =3D 36153673
> [    1.575671][    T1] smp: Brought up 2 nodes, 8 CPUs
> [    1.575953][    T1] smpboot: Max logical packages: 8
> [    1.576194][    T1] smpboot: Total of 8 processors activated (43713.85=
 BogoMIPS)
> [    1.610950][    T1] devtmpfs: initialized
> [    1.617759][    T1] x86/mm: Memory block size: 128MB
> [    1.655531][    T1] clocksource: jiffies: mask: 0xffffffff max_cycles:=
 0xffffffff, max_idle_ns: 19112604462750000 ns
> [    1.655531][    T1] futex hash table entries: 2048 (order: 6, 262144 b=
ytes, vmalloc)
> [    1.686557][    T1] PM: RTC time: 08:09:43, date: 2021-03-23
> [    1.709490][    T1] thermal_sys: Registered thermal governor 'step_wis=
e'
> [    1.709682][    T1] thermal_sys: Registered thermal governor 'user_spa=
ce'
> [    1.713518][    T1] cpuidle: using governor menu
> [    1.718028][    T1] ACPI: bus type PCI registered
> [    1.724213][    T1] PCI: Using configuration type 1 for base access
> [    1.743957][    T1] mtrr: your CPUs had inconsistent fixed MTRR settin=
gs
> [    1.744571][    T1] mtrr: your CPUs had inconsistent variable MTRR set=
tings
> [    1.744921][    T1] mtrr: your CPUs had inconsistent MTRRdefType setti=
ngs
> [    1.745153][    T1] mtrr: probably your BIOS does not setup all CPUs.
> [    1.745434][    T1] mtrr: corrected configuration.
> [    1.872623][    T1] HugeTLB registered 2.00 MiB page size, pre-allocat=
ed 0 pages
> [    2.671841][    T1] ACPI: Added _OSI(Module Device)
> [    2.672100][    T1] ACPI: Added _OSI(Processor Device)
> [    2.672278][    T1] ACPI: Added _OSI(3.0 _SCP Extensions)
> [    2.672456][    T1] ACPI: Added _OSI(Processor Aggregator Device)
> [    2.672743][    T1] ACPI: Added _OSI(Linux-Dell-Video)
> [    2.673071][    T1] ACPI: Added _OSI(Linux-Lenovo-NV-HDMI-Audio)
> [    2.673071][    T1] ACPI: Added _OSI(Linux-HPI-Hybrid-Graphics)
> [    2.719197][    T1] ACPI: 1 ACPI AML tables successfully acquired and =
loaded
> [    2.750223][    T1] ACPI: Interpreter enabled
> [    2.754114][    T1] ACPI: (supports S0 S3 S5)
> [    2.754429][    T1] ACPI: Using IOAPIC for interrupt routing
> [    2.755490][    T1] PCI: Using host bridge windows from ACPI; if neces=
sary, use "pci=3Dnocrs" and report a bug
> [    2.766423][    T1] ACPI: Enabled 2 GPEs in block 00 to 0F
> [    2.937992][    T1] ACPI: PCI Root Bridge [PCI0] (domain 0000 [bus 00-=
ff])
> [    2.938971][    T1] acpi PNP0A03:00: _OSC: OS supports [ASPM ClockPM S=
egments MSI HPX-Type3]
> [    2.938971][    T1] acpi PNP0A03:00: fail to add MMCONFIG information,=
 can't access extended PCI configuration space under this bridge.
> [    2.940837][    T1] PCI host bridge to bus 0000:00
> [    2.940837][    T1] pci_bus 0000:00: Unknown NUMA node; performance wi=
ll be reduced
> [    2.940837][    T1] pci_bus 0000:00: root bus resource [io  0x0000-0x0=
cf7 window]
> [    2.940837][    T1] pci_bus 0000:00: root bus resource [io  0x0d00-0xf=
fff window]
> [    2.940837][    T1] pci_bus 0000:00: root bus resource [mem 0x000a0000=
-0x000bffff window]
> [    2.940837][    T1] pci_bus 0000:00: root bus resource [mem 0xc0000000=
-0xfebfffff window]
> [    2.940837][    T1] pci_bus 0000:00: root bus resource [mem 0x14000000=
0-0x1bfffffff window]
> [    2.950855][    T1] pci_bus 0000:00: root bus resource [bus 00-ff]
> [    2.953714][    T1] pci 0000:00:00.0: [8086:1237] type 00 class 0x0600=
00
> [    2.964781][    T1] pci 0000:00:01.0: [8086:7000] type 00 class 0x0601=
00
> [    2.970100][    T1] pci 0000:00:01.1: [8086:7010] type 00 class 0x0101=
80
> [    2.978521][    T1] pci 0000:00:01.1: reg 0x20: [io  0xc040-0xc04f]
> [    2.981868][    T1] pci 0000:00:01.1: legacy IDE quirk: reg 0x10: [io =
 0x01f0-0x01f7]
> [    2.982334][    T1] pci 0000:00:01.1: legacy IDE quirk: reg 0x14: [io =
 0x03f6]
> [    2.982607][    T1] pci 0000:00:01.1: legacy IDE quirk: reg 0x18: [io =
 0x0170-0x0177]
> [    2.982859][    T1] pci 0000:00:01.1: legacy IDE quirk: reg 0x1c: [io =
 0x0376]
> [    2.990924][    T1] pci 0000:00:01.3: [8086:7113] type 00 class 0x0680=
00
> [    2.991830][    T1] pci 0000:00:01.3: quirk: [io  0x0600-0x063f] claim=
ed by PIIX4 ACPI
> [    2.992151][    T1] pci 0000:00:01.3: quirk: [io  0x0700-0x070f] claim=
ed by PIIX4 SMB
> [    3.001408][    T1] pci 0000:00:02.0: [1234:1111] type 00 class 0x0300=
00
> [    3.001408][    T1] pci 0000:00:02.0: reg 0x10: [mem 0xfd000000-0xfdff=
ffff pref]
> [    3.005509][    T1] pci 0000:00:02.0: reg 0x18: [mem 0xfebb0000-0xfebb=
0fff]
> [    3.005509][    T1] pci 0000:00:02.0: reg 0x30: [mem 0xfeba0000-0xfeba=
ffff pref]
> [    3.021536][    T1] pci 0000:00:03.0: [8086:100e] type 00 class 0x0200=
00
> [    3.021536][    T1] pci 0000:00:03.0: reg 0x10: [mem 0xfeb80000-0xfeb9=
ffff]
> [    3.021536][    T1] pci 0000:00:03.0: reg 0x14: [io  0xc000-0xc03f]
> [    3.029055][    T1] pci 0000:00:03.0: reg 0x30: [mem 0xfeb00000-0xfeb7=
ffff pref]
> [    3.063161][    T1] ACPI: PCI Interrupt Link [LNKA] (IRQs 5 *10 11)
> [    3.066809][    T1] ACPI: PCI Interrupt Link [LNKB] (IRQs 5 *10 11)
> [    3.071757][    T1] ACPI: PCI Interrupt Link [LNKC] (IRQs 5 10 *11)
> [    3.074313][    T1] ACPI: PCI Interrupt Link [LNKD] (IRQs 5 10 *11)
> [    3.075537][    T1] ACPI: PCI Interrupt Link [LNKS] (IRQs *9)
> [    3.091500][    T1] iommu: Default domain type: Translated
> [    3.101881][    T1] pps_core: LinuxPPS API ver. 1 registered
> [    3.101881][    T1] pps_core: Software ver. 5.3.6 - Copyright 2005-200=
7 Rodolfo Giometti <giometti@linux.it>
> [    3.104455][    T1] EDAC MC: Ver: 3.0.0
> [    3.119015][    T1] PCI: Using ACPI for IRQ routing
> [    3.123356][    T1] hpet: 3 channels of 0 reserved for per-cpu timers
> [    3.123973][    T1] hpet0: at MMIO 0xfed00000, IRQs 2, 8, 0
> [    3.124299][    T1] hpet0: 3 comparators, 64-bit 100.000000 MHz counte=
r
> [    3.137924][    T1] clocksource: Switched to clocksource hpet
> [    3.419603][    T1] VFS: Disk quotas dquot_6.6.0
> [    3.420180][    T1] VFS: Dquot-cache hash table entries: 512 (order 0,=
 4096 bytes)
> [    3.423105][    T1] FS-Cache: Loaded
> [    3.424929][    T1] ACPI: Failed to create genetlink family for ACPI e=
vent
> [    3.425521][    T1] pnp: PnP ACPI init
> [    3.444566][    T1] pnp: PnP ACPI: found 6 devices
> [    3.574862][    T1] clocksource: acpi_pm: mask: 0xffffff max_cycles: 0=
xffffff, max_idle_ns: 2085701024 ns
> [    3.576905][    T1] pci_bus 0000:00: resource 4 [io  0x0000-0x0cf7 win=
dow]
> [    3.577230][    T1] pci_bus 0000:00: resource 5 [io  0x0d00-0xffff win=
dow]
> [    3.577449][    T1] pci_bus 0000:00: resource 6 [mem 0x000a0000-0x000b=
ffff window]
> [    3.577782][    T1] pci_bus 0000:00: resource 7 [mem 0xc0000000-0xfebf=
ffff window]
> [    3.578013][    T1] pci_bus 0000:00: resource 8 [mem 0x140000000-0x1bf=
ffffff window]
> [    3.579844][    T1] pci 0000:00:01.0: PIIX3: Enabling Passive Release
> [    3.580250][    T1] pci 0000:00:00.0: Limiting direct PCI/PCI transfer=
s
> [    3.580549][    T1] pci 0000:00:01.0: Activating ISA DMA hang workarou=
nds
> [    3.581465][    T1] pci 0000:00:02.0: Video device with shadowed ROM a=
t [mem 0x000c0000-0x000dffff]
> [    3.581910][    T1] PCI: CLS 0 bytes, default 64
> [    3.586685][    T1] PCI-DMA: Using software bounce buffering for IO (S=
WIOTLB)
> [    3.586991][    T1] software IO TLB: mapped [mem 0x00000000bbfdf000-0x=
00000000bffdf000] (64MB)
> [    3.666170][    T1] Initialise system trusted keyrings
> [    3.670741][    T1] workingset: timestamp_bits=3D40 max_order=3D20 buc=
ket_order=3D0
> [    3.741277][    T1] zbud: loaded
> [    3.752917][    T1] Key type asymmetric registered
> [    3.753801][    T1] Asymmetric key parser 'x509' registered
> [    3.765090][    T1] input: Power Button as /devices/LNXSYSTM:00/LNXPWR=
BN:00/input/input0
> [    3.774940][    T1] ACPI: button: Power Button [PWRF]
> [    4.077541][    C2] int3: 0000 [#1] PREEMPT SMP
> [    4.077584][    C2] CPU: 2 PID: 215 Comm: kworker/u17:6 Not tainted 5.=
12.0-rc4 #21
> [    4.077591][    C2] Hardware name: QEMU Standard PC (i440FX + PIIX, 19=
96), BIOS 1.13.0-1ubuntu1.1 04/01/2014
> [    4.077623][    C2] Workqueue: events_unbound call_usermodehelper_exec=
_work
> [    4.077762][    C2] RIP: 0010:kmem_cache_alloc_node_trace+0x1a4/0x8b0
> [    4.077768][    C2] Code: c0 48 0f a3 05 05 bf 00 01 0f 82 cd 05 00 00=
 48 83 c4 20 4c 89 e0 5b 5d 41 5c 41 5d 41 5e 41 5f c3 45 31 ed 48 85 ed 74=
 be 66 <66> 66 66 90 48 8b 4d 00 65 48 8b 71 08 48 89 c8 65 48 03 05 74 cf
> [    4.077773][    C2] RSP: 0018:ffffc90000c87b80 EFLAGS: 00000286
> [    4.077780][    C2] RAX: 0000000000000000 RBX: 0000000000000022 RCX: 0=
000000000000001
> [    4.077784][    C2] RDX: 0000000000000000 RSI: 0000000000000dc0 RDI: f=
fff888003842500
> [    4.077787][    C2] RBP: ffff888003842500 R08: 0000000000000000 R09: 0=
000000000040095
> [    4.077790][    C2] R10: 0000000000000001 R11: 0000000000000000 R12: 0=
000000000000dc0
> [    4.077794][    C2] R13: 0000000000000000 R14: 0000000000000dc0 R15: f=
fffffff81239528
> [    4.077813][    C2] FS:  0000000000000000(0000) GS:ffff88807dc80000(00=
00) knlGS:0000000000000000
> [    4.077816][    C2] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    4.077819][    C2] CR2: 0000000000000000 CR3: 0000000002011000 CR4: 0=
0000000000006e0
> [    4.077822][    C2] Call Trace:
> [    4.077825][    C2]  __get_vm_area_node+0x78/0x160
> [    4.077828][    C2]  __vmalloc_node_range+0x64/0x250
> [    4.077830][    C2]  ? kernel_clone+0x96/0x690
> [    4.077833][    C2]  ? kmem_cache_alloc_node+0x844/0x8b0
> [    4.077836][    C2]  copy_process+0x3b9/0x1b20
> [    4.077838][    C2]  ? kernel_clone+0x96/0x690
> [    4.077841][    C2]  kernel_clone+0x96/0x690
> [    4.077843][    C2]  kernel_thread+0x50/0x70
> [    4.077846][    C2]  ? umh_complete+0x30/0x30
> [    4.077849][    C2]  call_usermodehelper_exec_work+0x5f/0x80
> [    4.077851][    C2]  process_one_work+0x235/0x580
> [    4.077856][    C2]  ? process_one_work+0x580/0x580
> [    4.077858][    C2]  worker_thread+0x4b/0x3a0
> [    4.077861][    C2]  ? process_one_work+0x580/0x580
> [    4.077864][    C2]  kthread+0x12c/0x170
> [    4.077866][    C2]  ? __kthread_create_on_node+0x190/0x190
> [    4.077869][    C2]  ret_from_fork+0x1f/0x30
> [    4.087030][    C6] ---[ end trace e5a0f67d864d65ea ]---
> [    4.087030][    C6] RIP: 0010:kmem_cache_alloc_node_trace+0x1a4/0x8b0
> [    4.087030][    C6] Code: c0 48 0f a3 05 05 bf 00 01 0f 82 cd 05 00 00=
 48 83 c4 20 4c 89 e0 5b 5d 41 5c 41 5d 41 5e 41 5f c3 45 31 ed 48 85 ed 74=
 be 66 <66> 66 66 90 48 8b 4d 00 65 48 8b 71 08 48 89 c8 65 48 03 05 74 cf
> [    4.087030][    C6] RSP: 0018:ffffc90000c87b80 EFLAGS: 00000286
> [    4.087030][    C6] RAX: 0000000000000000 RBX: 0000000000000022 RCX: 0=
000000000000001
> [    4.087030][    C6] RDX: 0000000000000000 RSI: 0000000000000dc0 RDI: f=
fff888003842500
> [    4.087030][    C6] RBP: ffff888003842500 R08: 0000000000000000 R09: 0=
000000000040095
> [    4.087030][    C6] R10: 0000000000000001 R11: 0000000000000000 R12: 0=
000000000000dc0
> [    4.087030][    C6] R13: 0000000000000000 R14: 0000000000000dc0 R15: f=
fffffff81239528
> [    4.087030][    C6] FS:  0000000000000000(0000) GS:ffff88807dc80000(00=
00) knlGS:0000000000000000
> [    4.087030][    C6] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    4.087030][    C6] CR2: 0000000000000000 CR3: 0000000002011000 CR4: 0=
0000000000006e0
> [    4.087030][    C6] int3: 0000 [#2] PREEMPT SMP
> [    4.087030][    C6] CPU: 6 PID: 118 Comm: kworker/u17:4 Tainted: G    =
  D           5.12.0-rc4 #21
> [    4.087030][    C6] Hardware name: QEMU Standard PC (i440FX + PIIX, 19=
96), BIOS 1.13.0-1ubuntu1.1 04/01/2014
> [    4.087030][    C6] Workqueue: events_unbound call_usermodehelper_exec=
_work
> [    4.087030][    C6] RIP: 0010:kmem_cache_alloc_node_trace+0x1a4/0x8b0
> [    4.087030][    C6] Code: c0 48 0f a3 05 05 bf 00 01 0f 82 cd 05 00 00=
 48 83 c4 20 4c 89 e0 5b 5d 41 5c 41 5d 41 5e 41 5f c3 45 31 ed 48 85 ed 74=
 be 66 <66> 66 66 90 48 8b 4d 00 65 48 8b 71 08 48 89 c8 65 48 03 05 74 cf
> [    4.087030][    C6] RSP: 0018:ffffc90000a37b80 EFLAGS: 00000286
> [    4.087030][    C6] RAX: 0000000000000000 RBX: 0000000000000022 RCX: 0=
000000000000000
> [    4.087030][    C6] RDX: 0000000000000000 RSI: 0000000000000dc0 RDI: f=
fff888003842500
> [    4.087030][    C6] RBP: ffff888003842500 R08: 0000000000000001 R09: 0=
000000000000000
> [    4.087030][    C6] R10: ffffc90000000000 R11: 0000000000000018 R12: 0=
000000000000dc0
> [    4.087030][    C6] R13: 0000000000000000 R14: 0000000000000dc0 R15: f=
fffffff81239528
> [    4.087030][    C6] FS:  0000000000000000(0000) GS:ffff88807dd80000(00=
00) knlGS:0000000000000000
> [    4.087030][    C6] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    4.087030][    C6] CR2: 0000000000000000 CR3: 0000000002011000 CR4: 0=
0000000000006e0
> [    4.087030][    C6] Call Trace:
> [    4.087030][    C6]  __get_vm_area_node+0x78/0x160
> [    4.087030][    C6]  ? update_load_avg+0x82/0x790
> [    4.087030][    C6]  __vmalloc_node_range+0x64/0x250
> [    4.087030][    C6]  ? kernel_clone+0x96/0x690
> [    4.087030][    C6]  ? kmem_cache_alloc_node+0x762/0x8b0
> [    4.087030][    C6]  copy_process+0x3b9/0x1b20
> [    4.087030][    C6]  ? kernel_clone+0x96/0x690
> [    4.087030][    C6]  kernel_clone+0x96/0x690
> [    4.087030][    C6]  ? lock_acquire+0x196/0x3c0
> [    4.087030][    C6]  ? lock_release+0x1fc/0x2d0
> [    4.087030][    C6]  ? lock_release+0x1fc/0x2d0
> [    4.087030][    C6]  ? lock_acquire+0x196/0x3c0
> [    4.087030][    C6]  kernel_thread+0x50/0x70
> [    4.087030][    C6]  ? umh_complete+0x30/0x30
> [    4.087030][    C6]  call_usermodehelper_exec_work+0x5f/0x80
> [    4.087030][    C6]  process_one_work+0x235/0x580
> [    4.087030][    C6]  ? process_one_work+0x580/0x580
> [    4.087030][    C6]  worker_thread+0x4b/0x3a0
> [    4.087030][    C6]  ? process_one_work+0x580/0x580
> [    4.087030][    C6]  kthread+0x12c/0x170
> [    4.087030][    C6]  ? __kthread_create_on_node+0x190/0x190
> [    4.087030][    C6]  ret_from_fork+0x1f/0x30
> [    4.087030][    C6] ---[ end trace e5a0f67d864d65eb ]---
> [    4.087030][    C6] RIP: 0010:kmem_cache_alloc_node_trace+0x1a4/0x8b0
> [    4.087030][    C6] Code: c0 48 0f a3 05 05 bf 00 01 0f 82 cd 05 00 00=
 48 83 c4 20 4c 89 e0 5b 5d 41 5c 41 5d 41 5e 41 5f c3 45 31 ed 48 85 ed 74=
 be 66 <66> 66 66 90 48 8b 4d 00 65 48 8b 71 08 48 89 c8 65 48 03 05 74 cf
> [    4.087030][    C6] RSP: 0018:ffffc90000c87b80 EFLAGS: 00000286
> [    4.087030][    C6] RAX: 0000000000000000 RBX: 0000000000000022 RCX: 0=
000000000000001
> [    4.087030][    C6] RDX: 0000000000000000 RSI: 0000000000000dc0 RDI: f=
fff888003842500
> [    4.087030][    C6] RBP: ffff888003842500 R08: 0000000000000000 R09: 0=
000000000040095
> [    4.087030][    C6] R10: 0000000000000001 R11: 0000000000000000 R12: 0=
000000000000dc0
> [    4.087030][    C6] R13: 0000000000000000 R14: 0000000000000dc0 R15: f=
fffffff81239528
> [    4.087030][    C6] FS:  0000000000000000(0000) GS:ffff88807dd80000(00=
00) knlGS:0000000000000000
> [    4.087030][    C6] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    4.087030][    C6] CR2: 0000000000000000 CR3: 0000000002011000 CR4: 0=
0000000000006e0
> [    4.087030][    C6] Kernel panic - not syncing: Fatal exception in int=
errupt
> [    4.087030][    C6] Shutting down cpus with NMI
> [    4.087030][    C6] Kernel Offset: disabled
> ---------- Console output ----------

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM60W4nYEYCEt9SJ9f4L194WEk_ORey8s%2BDbgnokJZ53g%40mail.gmai=
l.com.
