Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4N4RKYAMGQEQ3VH4WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB99788BEC8
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 11:07:48 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-6e735084916sf4048592b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 03:07:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711447667; cv=pass;
        d=google.com; s=arc-20160816;
        b=aIx+49dsNNiufqXrpybEiZ5DsrQOpd/V9BPMQjSYl3tUhScU0w9Zo+9v8NHi0KQ/rY
         mP9zGf0giCc9mGV8PqJKpQ3Sggm7TNOff3HY/zMbhVaKHj1Ft7sLIhPOV06uSKoB18m2
         8SC8BsCVdyF8mC22+bR1q8ttFDqW1IsRmCTYUkheogfiIm9xlh7j/Iv1TTPX7K506Ic6
         sQs5g2fAQIuWE+RlWx7VRegObrP2uVT+RRghRU5ImvAaoFpsoxR3HkVWochBVWK6wSF6
         6+cUds433W/SRQi8/8lhlkBAY3ra5TMyN32tEJzmMGU80szmKv3ke3GTTuz/pWcFRBln
         i25Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dnbxBna81vaR0fHD6bkwJZTnRerVbdl6cMI08s3Bq6s=;
        fh=4ApRFD4uWiRppCN4+kLLuffFZumQ8aVwdn+xCo0ZFEQ=;
        b=pgq1vJGq3hFAL7KbF1tJAUO+OPyi2vU9TvUJjC81dxYsyH4RaTdSRxXf4EaBUNxxyJ
         3e60wTUz7GVY2QkMeYapx5PPj7SZ6mW36Rfs1SzeRscWGSqacFPYWrpbYLFi9O52eyss
         zF5qJZrEeR5pvvCFnKmRMOs8QaO3OtG7JfSk5k5B82C3OcG+n8Jb46Nak4MXgXoWhPKN
         9y4MiD6cC8jB8fnoOa3r7f8wd/gtXAy4wts7+8QLS4BHDfUDijplj+AFjtbqACZsfiOv
         f23oSBjt7sAOYQ6GgMRaJwGJdyDXe4s9HXHokIFLDIOP9/9i12z93VhfzN4hWHAXcuQ7
         9vCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wwygphtm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711447667; x=1712052467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dnbxBna81vaR0fHD6bkwJZTnRerVbdl6cMI08s3Bq6s=;
        b=r7wHy3Fz9qapX5zNFvVyL3XlQMKPSeZ3sQebOdbvDRE+3Wg6ysBdSemjVqP0XxBtjh
         lduo3nYN9V72IcKzeAKJ5riENJpVTfONHOAVOeL7qlXGmJKF12IOvUTPFlvQLanfmIXG
         2E5ykR5gpCsdGgoNrv7mXOsng6nm3d3aeSKvMDNgsr/yFLmNSLMWvHTodcTRtyYCJGVj
         9j5+WYoWROAlhPHjgLodpPXx6zVqzCoxgwB2s33wJH7+D62Tq4VGjm4zzjKfF300qmP9
         HF6Ohrv77FDDDnazubit0bSAx+fgIrfEZe6tZaA03W3MW4bRZFqTKn1+q12zVFONrriB
         pbSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711447667; x=1712052467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dnbxBna81vaR0fHD6bkwJZTnRerVbdl6cMI08s3Bq6s=;
        b=OH9MoM1MJR7ptL8e38lJOpMskPf46c1Waofody58MsLSUZAblVAVMoMQK0vwkbPpmi
         DLtnhjv6gTNNA9Q/QK+8B0ep7aFjAv3zomf7JnhQ18Vpjlxa/8S9mE//mPKvdLhbnW56
         qYfUJPosw/cUq7qIYxHDL6x3kUqTxbL+uzY38nXdTHvLJoGR3KJfLMUnGEWK0gGhvEaI
         BmhCOKzDoAhA70t8eeGiVGXLyzkmqmZ9s9bhLWVgtjsF8K8J1s6PpYsaFvs8fx8+aYav
         8tJBWTylPGQYLvUfgT/eDyCFvnBpKVWLitc6Hsx86bQLHJiJsS6fsa/PCNu4/Xwrlwm6
         nt7A==
X-Forwarded-Encrypted: i=2; AJvYcCUSuI106+DEcSd/v9pEfgA8MJtuKyjcDvXjaUuclolQQA+dQR04K1TSkug2Y6laj4vVfG3hBgDuLtdoBX1N6ly1VmsVH4fh2w==
X-Gm-Message-State: AOJu0Ywkve/jf+lxsOcSNanhcqMP4zEEvoHEYPpHk1qCs0jFelcX7stb
	YK/E6VnaQSzmT9UKoz9OSxjx13gVxj/us30YqP/Vz0Q+Vcj1bIA7
X-Google-Smtp-Source: AGHT+IEeZiAB3ZfV8mM9tHfKZy5C/IR5TcX0WoRJEkRy+4ghrXfaU0q8vpBLQnRmqC8GvTYLCX6iiA==
X-Received: by 2002:a05:6a00:890:b0:6ea:7db6:6271 with SMTP id q16-20020a056a00089000b006ea7db66271mr656551pfj.19.1711447666152;
        Tue, 26 Mar 2024 03:07:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:18a2:b0:6ea:afca:4d5c with SMTP id
 x34-20020a056a0018a200b006eaafca4d5cls1107581pfh.0.-pod-prod-02-us; Tue, 26
 Mar 2024 03:07:45 -0700 (PDT)
X-Received: by 2002:a05:6a20:c89b:b0:1a3:72d2:c430 with SMTP id hb27-20020a056a20c89b00b001a372d2c430mr694105pzb.51.1711447664634;
        Tue, 26 Mar 2024 03:07:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711447664; cv=none;
        d=google.com; s=arc-20160816;
        b=tKMaXc2l9dqPQiMdQGeuaKsM13yMqOKWXVKgDLRiXj9wtM0kjy1yOF7CDmpjaiPHRW
         pyRSWcj3w1N4TUhk+7ZrRAH4tVV+Ce/gDTXRR+ir5tDkL94o8KWwD92pqs/CwkMSgEkX
         4pw/F82VrgUsnAno2oL1NynIgh2FJrrCR4k9x2UeLDd+PY1MjTDozyySqILJ0furXsJ/
         2IlcerwPTM96ocyi98bu/C/vK/1GTmeEsXR3ALB5u3mqCPlbtmsCa2b/yJ9uuzz5q4e7
         W4jPpxFr7BQxMqgVIQutG8SGJCYAgm8husA1RbWz8oumB0BKs8jbHO6TBe9rVwyKmJTj
         4mBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9iwAks3CaipTYKLaxqhuuK1RUyeYtyvvIpoAAVZ600Y=;
        fh=FbJ4ULXeQ2WtvrwRq/nqFoHzlIiLeSAHX8Unk6iYQx4=;
        b=dgtxHXnJRCP0Y+9bVa21fJ+i1WjiJDPFCwa+wCr2IR1sLjtiLqwSAMGJeVc9bMT2/g
         5RaXhQjAwxROd2yEgolxt8bQdcRZYwRAup6otSEoux5x67Y7DM8BPd9uegcA24g3PZjP
         RGetQI+EozE3ADB02U1Hec2RLGX0LtBOjy71LdD7pYS/+8lyxyda6cnqFWqajJgi3JZB
         SFlhSZX1iVU/DUx0SNkYyNFmjwDEHH8BvDb7pfNUMBPFfcTgzLK6DBpOU2f+PJywUwg2
         zQUMM0t2ik/VeyPDYaZLAa0Ke8UxbXzspcCPCgXLfdYRVIlzwwUUQjfFnz/suI6Kcg43
         7ENg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wwygphtm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2c.google.com (mail-vs1-xe2c.google.com. [2607:f8b0:4864:20::e2c])
        by gmr-mx.google.com with ESMTPS id y6-20020a17090aa40600b002a05f2a714bsi319204pjp.3.2024.03.26.03.07.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 03:07:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) client-ip=2607:f8b0:4864:20::e2c;
Received: by mail-vs1-xe2c.google.com with SMTP id ada2fe7eead31-47822e4dc24so481383137.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 03:07:44 -0700 (PDT)
X-Received: by 2002:a05:6102:3a71:b0:478:260b:87f with SMTP id
 bf17-20020a0561023a7100b00478260b087fmr609828vsb.25.1711447663205; Tue, 26
 Mar 2024 03:07:43 -0700 (PDT)
MIME-Version: 1.0
References: <bd455761-3dbf-4f44-a0e3-dff664284fcc@molgen.mpg.de>
In-Reply-To: <bd455761-3dbf-4f44-a0e3-dff664284fcc@molgen.mpg.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Mar 2024 11:07:04 +0100
Message-ID: <CANpmjNMAfLDZtHaZBZk_tZ-oM5FgYTSOgfbJLTFN7JE-mq0u_A@mail.gmail.com>
Subject: Re: BUG: unable to handle page fault for address: 0000000000030368
To: Paul Menzel <pmenzel@molgen.mpg.de>
Cc: kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wwygphtm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as
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

On Tue, 26 Mar 2024 at 10:23, Paul Menzel <pmenzel@molgen.mpg.de> wrote:
>
> Dear Linux folks,
>
>
> Trying KCSAN the first time =E2=80=93 configuration attached =E2=80=93, i=
t fails to boot
> on the Dell XPS 13 9360 and QEMU q35. I couldn=E2=80=99t get logs on the =
Dell
> XPS 13 9360, so here are the QEMU ones:

If there's a bad access somewhere which is instrumented by KCSAN, it
will unfortunately still crash inside KCSAN.

What happens if you compile with CONFIG_KCSAN_EARLY_ENABLE=3Dn? It
disables KCSAN (but otherwise the kernel image is the same) and
requires turning it on manually with "echo on >
/sys/kernel/debug/kcsan" after boot.

If it still crashes, then there's definitely a bug elsewhere. If it
doesn't crash, and only crashes with KCSAN enabled, my guess is that
KCSAN's delays of individual threads are perturbing execution to
trigger previously undetected bugs.

At least I can't explain it any other way.

> ```
> $ qemu-system-x86_64 -M q35 -enable-kvm -smp cpus=3D2 -m 1G -serial stdio
> -net nic -net user,hostfwd=3Dtcp::22222-:22 -kernel
> boot/vmlinuz-6.9.0-rc1+ -append "root=3D/dev/sda1 console=3DttyS0"
> [    0.000000] Linux version 6.9.0-rc1+
> (build@bohemianrhapsody.molgen.mpg.de) (gcc (Debian 13.2.0-19) 13.2.0,
> GNU ld (GNU Binutils for Debian) 2.42) #75 SMP PREEMPT_DYNAMIC Tue Mar
> 26 07:03:41 CET 2024
> [    0.000000] Command line: root=3D/dev/sda1 console=3DttyS0
> [    0.000000] BIOS-provided physical RAM map:
> [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usa=
ble
> [    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff]
> reserved
> [    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff]
> reserved
> [    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000003ffdefff] usa=
ble
> [    0.000000] BIOS-e820: [mem 0x000000003ffdf000-0x000000003fffffff]
> reserved
> [    0.000000] BIOS-e820: [mem 0x00000000b0000000-0x00000000bfffffff]
> reserved
> [    0.000000] BIOS-e820: [mem 0x00000000fed1c000-0x00000000fed1ffff]
> reserved
> [    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff]
> reserved
> [    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff]
> reserved
> [    0.000000] NX (Execute Disable) protection: active
> [    0.000000] APIC: Static calls initialized
> [    0.000000] SMBIOS 3.0.0 present.
> [    0.000000] DMI: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
> 1.16.3-debian-1.16.3-2 04/01/2014
> [    0.000000] Hypervisor detected: KVM
> [    0.000000] kvm-clock: Using msrs 4b564d01 and 4b564d00
> [    0.000001] kvm-clock: using sched offset of 1376980956 cycles
> [    0.000006] clocksource: kvm-clock: mask: 0xffffffffffffffff
> max_cycles: 0x1cd42e4dffb, max_idle_ns: 881590591483 ns
> [    0.000014] tsc: Detected 2904.008 MHz processor
> [    0.004273] last_pfn =3D 0x3ffdf max_arch_pfn =3D 0x400000000
> [    0.004315] MTRR map: 4 entries (3 fixed + 1 variable; max 19), built
> from 8 variable MTRRs
> [    0.004323] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  WP  UC-
> WT
> [    0.012972] found SMP MP-table at [mem 0x000f5480-0x000f548f]
> [    0.013243] ACPI: Early table checksum verification disabled
> [    0.013252] ACPI: RSDP 0x00000000000F52C0 000014 (v00 BOCHS )
> [    0.013265] ACPI: RSDT 0x000000003FFE2357 000038 (v01 BOCHS  BXPC
> 00000001 BXPC 00000001)
> [    0.013283] ACPI: FACP 0x000000003FFE2147 0000F4 (v03 BOCHS  BXPC
> 00000001 BXPC 00000001)
> [    0.013304] ACPI: DSDT 0x000000003FFE0040 002107 (v01 BOCHS  BXPC
> 00000001 BXPC 00000001)
> [    0.013319] ACPI: FACS 0x000000003FFE0000 000040
> [    0.013331] ACPI: APIC 0x000000003FFE223B 000080 (v03 BOCHS  BXPC
> 00000001 BXPC 00000001)
> [    0.013346] ACPI: HPET 0x000000003FFE22BB 000038 (v01 BOCHS  BXPC
> 00000001 BXPC 00000001)
> [    0.013361] ACPI: MCFG 0x000000003FFE22F3 00003C (v01 BOCHS  BXPC
> 00000001 BXPC 00000001)
> [    0.013375] ACPI: WAET 0x000000003FFE232F 000028 (v01 BOCHS  BXPC
> 00000001 BXPC 00000001)
> [    0.013388] ACPI: Reserving FACP table memory at [mem
> 0x3ffe2147-0x3ffe223a]
> [    0.013393] ACPI: Reserving DSDT table memory at [mem
> 0x3ffe0040-0x3ffe2146]
> [    0.013398] ACPI: Reserving FACS table memory at [mem
> 0x3ffe0000-0x3ffe003f]
> [    0.013402] ACPI: Reserving APIC table memory at [mem
> 0x3ffe223b-0x3ffe22ba]
> [    0.013407] ACPI: Reserving HPET table memory at [mem
> 0x3ffe22bb-0x3ffe22f2]
> [    0.013411] ACPI: Reserving MCFG table memory at [mem
> 0x3ffe22f3-0x3ffe232e]
> [    0.013416] ACPI: Reserving WAET table memory at [mem
> 0x3ffe232f-0x3ffe2356]
> [    0.013746] No NUMA configuration found
> [    0.013750] Faking a node at [mem 0x0000000000000000-0x000000003ffdeff=
f]
> [    0.013762] NODE_DATA(0) allocated [mem 0x3ffb4000-0x3ffdefff]
> [    0.015042] Zone ranges:
> [    0.015047]   DMA      [mem 0x0000000000001000-0x0000000000ffffff]
> [    0.015056]   DMA32    [mem 0x0000000001000000-0x000000003ffdefff]
> [    0.015067]   Normal   empty
> [    0.015073]   Device   empty
> [    0.015080] Movable zone start for each node
> [    0.015113] Early memory node ranges
> [    0.015116]   node   0: [mem 0x0000000000001000-0x000000000009efff]
> [    0.015122]   node   0: [mem 0x0000000000100000-0x000000003ffdefff]
> [    0.015128] Initmem setup node 0 [mem
> 0x0000000000001000-0x000000003ffdefff]
> [    0.015177] On node 0, zone DMA: 1 pages in unavailable ranges
> [    0.015913] On node 0, zone DMA: 97 pages in unavailable ranges
> [    0.028914] On node 0, zone DMA32: 33 pages in unavailable ranges
> [    0.029456] ACPI: PM-Timer IO Port: 0x608
> [    0.029493] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])
> [    0.029547] IOAPIC[0]: apic_id 0, version 17, address 0xfec00000, GSI
> 0-23
> [    0.029558] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)
> [    0.029564] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 high level=
)
> [    0.029569] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high level=
)
> [    0.029575] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 high lev=
el)
> [    0.029580] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 high lev=
el)
> [    0.029597] ACPI: Using ACPI (MADT) for SMP configuration information
> [    0.029602] ACPI: HPET id: 0x8086a201 base: 0xfed00000
> [    0.029624] CPU topo: Max. logical packages:   1
> [    0.029628] CPU topo: Max. logical dies:       1
> [    0.029631] CPU topo: Max. dies per package:   1
> [    0.029644] CPU topo: Max. threads per core:   1
> [    0.029647] CPU topo: Num. cores per package:     2
> [    0.029650] CPU topo: Num. threads per package:   2
> [    0.029653] CPU topo: Allowing 2 present CPUs plus 0 hotplug CPUs
> [    0.029679] kvm-guest: APIC: eoi() replaced with
> kvm_guest_apic_eoi_write()
> [    0.029726] PM: hibernation: Registered nosave memory: [mem
> 0x00000000-0x00000fff]
> [    0.029734] PM: hibernation: Registered nosave memory: [mem
> 0x0009f000-0x0009ffff]
> [    0.029738] PM: hibernation: Registered nosave memory: [mem
> 0x000a0000-0x000effff]
> [    0.029742] PM: hibernation: Registered nosave memory: [mem
> 0x000f0000-0x000fffff]
> [    0.029749] [mem 0x40000000-0xafffffff] available for PCI devices
> [    0.029753] Booting paravirtualized kernel on KVM
> [    0.029758] clocksource: refined-jiffies: mask: 0xffffffff
> max_cycles: 0xffffffff, max_idle_ns: 7645519600211568 ns
> [    0.035898] setup_percpu: NR_CPUS:8192 nr_cpumask_bits:2 nr_cpu_ids:2
> nr_node_ids:1
> [    0.036314] percpu: Embedded 65 pages/cpu s229376 r8192 d28672 u104857=
6
> [    0.036436] kvm-guest: PV spinlocks disabled, no host support
> [    0.036440] Kernel command line: root=3D/dev/sda1 console=3DttyS0
> [    0.036669] Dentry cache hash table entries: 131072 (order: 8,
> 1048576 bytes, linear)
> [    0.036739] Inode-cache hash table entries: 65536 (order: 7, 524288
> bytes, linear)
> [    0.036830] Fallback order for Node 0: 0
> [    0.036839] Built 1 zonelists, mobility grouping on.  Total pages: 257=
759
> [    0.036844] Policy zone: DMA32
> [    0.036875] mem auto-init: stack:all(zero), heap alloc:on, heap free:o=
ff
> [    0.042521] Memory: 260860K/1048052K available (22528K kernel code,
> 2386K rwdata, 6124K rodata, 6304K init, 8064K bss, 70584K reserved, 0K
> cma-reserved)
> [    0.056267] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D2,=
 Nodes=3D1
> [    0.056279] kmemleak: Kernel memory leak detector disabled
> [    0.056484] Kernel/User page tables isolation: enabled
> [    0.056631] ftrace: allocating 43400 entries in 170 pages
> [    0.065090] ftrace: allocated 170 pages with 4 groups
> [    0.066107] Dynamic Preempt: voluntary
> [    0.066496] rcu: Preemptible hierarchical RCU implementation.
> [    0.066500] rcu:     RCU restricting CPUs from NR_CPUS=3D8192 to nr_cp=
u_ids=3D2.
> [    0.066505]  Trampoline variant of Tasks RCU enabled.
> [    0.066508]  Rude variant of Tasks RCU enabled.
> [    0.066510]  Tracing variant of Tasks RCU enabled.
> [    0.066513] rcu: RCU calculated value of scheduler-enlistment delay
> is 25 jiffies.
> [    0.066517] rcu: Adjusting geometry for rcu_fanout_leaf=3D16, nr_cpu_i=
ds=3D2
> [    0.066535] RCU Tasks: Setting shift to 1 and lim to 1
> rcu_task_cb_adjust=3D1.
> [    0.066541] RCU Tasks Rude: Setting shift to 1 and lim to 1
> rcu_task_cb_adjust=3D1.
> [    0.066546] RCU Tasks Trace: Setting shift to 1 and lim to 1
> rcu_task_cb_adjust=3D1.
> [    0.079398] NR_IRQS: 524544, nr_irqs: 440, preallocated irqs: 16
> [    0.079764] rcu: srcu_init: Setting srcu_struct sizes based on
> contention.
> [    0.091718] Console: colour VGA+ 80x25
> [    0.091774] printk: legacy console [ttyS0] enabled
> [    0.232004] ACPI: Core revision 20230628
> [    0.233211] clocksource: hpet: mask: 0xffffffff max_cycles:
> 0xffffffff, max_idle_ns: 19112604467 ns
> [    0.234715] APIC: Switch to symmetric I/O mode setup
> [    0.235721] x2apic enabled
> [    0.236578] APIC: Switched APIC routing to: physical x2apic
> [    0.239656] ..TIMER: vector=3D0x30 apic1=3D0 pin1=3D2 apic2=3D-1 pin2=
=3D-1
> [    0.241221] clocksource: tsc-early: mask: 0xffffffffffffffff
> max_cycles: 0x29dc0d988f1, max_idle_ns: 440795328788 ns
> [    0.243872] Calibrating delay loop (skipped) preset value.. 5808.01
> BogoMIPS (lpj=3D11616032)
> [    0.246030] Last level iTLB entries: 4KB 0, 2MB 0, 4MB 0
> [    0.247870] Last level dTLB entries: 4KB 0, 2MB 0, 4MB 0, 1GB 0
> [    0.248788] Spectre V1 : Mitigation: usercopy/swapgs barriers and
> __user pointer sanitization
> [    0.250127] Spectre V2 : Mitigation: Retpolines
> [    0.251176] Spectre V2 : Spectre v2 / SpectreRSB mitigation: Filling
> RSB on context switch
> [    0.251868] Spectre V2 : Spectre v2 / SpectreRSB : Filling RSB on VMEX=
IT
> [    0.253483] Speculative Store Bypass: Vulnerable
> [    0.255878] MDS: Vulnerable: Clear CPU buffers attempted, no microcode
> [    0.257191] MMIO Stale Data: Unknown: No mitigations
> [    0.258243] x86/fpu: x87 FPU will use FXSAVE
> [    0.327550] Freeing SMP alternatives memory: 36K
> [    0.327884] pid_max: default: 32768 minimum: 301
> [    0.330232] LSM: initializing
> lsm=3Dcapability,landlock,apparmor,tomoyo,bpf,ima,evm
> [    0.332326] landlock: Up and running.
> [    0.333534] AppArmor: AppArmor initialized
> [    0.334523] TOMOYO Linux initialized
> [    0.335895] LSM support for eBPF active
> [    0.337311] Mount-cache hash table entries: 2048 (order: 2, 16384
> bytes, linear)
> [    0.339886] Mountpoint-cache hash table entries: 2048 (order: 2,
> 16384 bytes, linear)
> [    0.344459] kcsan: enabled early
> [    0.345245] kcsan: non-strict mode configured - use
> CONFIG_KCSAN_STRICT=3Dy to see all data races
> [    0.375873] BUG: unable to handle page fault for address:
> 0000000000030368
> [    0.377316] #PF: supervisor read access in kernel mode
> [    0.378506] #PF: error_code(0x0000) - not-present page
> [    0.379647] PGD 0 P4D 0
> [    0.379861] Oops: 0000 [#1] PREEMPT SMP PTI
> [    0.379861] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 6.9.0-rc1+ #75
> [    0.379861] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
> 1.16.3-debian-1.16.3-2 04/01/2014
> [    0.379861] RIP: 0010:kcsan_setup_watchpoint+0x3cc/0x400
> [    0.379861] Code: 8b 04 24 4c 89 c2 48 31 c2 e9 69 fe ff ff 45 31 c0
> e9 c3 fd ff ff 4c 89 c2 31 c0 e9 57 fe ff ff 45 0f b6 04 24 e9 af fd ff
> ff <45> 8b 04 24 e9 a6 fd ff ff 85 c9 74 08 f0 48 ff 05 b7 a2 6e 02 b9
> [    0.379861] RSP: 0000:ffff9fed80003de0 EFLAGS: 00010046
> [    0.379861] RAX: 0000000000000000 RBX: ffff8c2d3ec302c0 RCX:
> 0000000000000030
> [    0.379861] RDX: 0000000000000001 RSI: ffffffff995ff0f0 RDI:
> 0000000000000000
> [    0.379861] RBP: 0000000000000004 R08: 00000000aaaaaaab R09:
> 0000000000000000
> [    0.379861] R10: 0000000000030368 R11: 0008000000030368 R12:
> 0000000000030368
> [    0.379861] R13: 0000000000000031 R14: 0000000000000000 R15:
> 0000000000000000
> [    0.379861] FS:  0000000000000000(0000) GS:ffff8c2d3ec00000(0000)
> knlGS:0000000000000000
> [    0.379861] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    0.379861] CR2: 0000000000030368 CR3: 0000000030a20000 CR4:
> 00000000000006f0
> [    0.379861] Call Trace:
> [    0.379861]  <IRQ>
> [    0.379861]  ? __die+0x23/0x70
> [    0.379861]  ? page_fault_oops+0x173/0x4f0
> [    0.379861]  ? exc_page_fault+0x81/0x190
> [    0.379861]  ? asm_exc_page_fault+0x26/0x30
> [    0.379861]  ? perf_event_task_tick+0x40/0x130
> [    0.379861]  ? kcsan_setup_watchpoint+0x3cc/0x400
> [    0.379861]  ? update_load_avg+0x7e/0x7e0
> [    0.379861]  ? __hrtimer_run_queues+0x3e/0x4b0
> [    0.379861]  ? hrtimer_active+0x88/0xc0
> [    0.379861]  perf_event_task_tick+0x40/0x130
> [    0.379861]  scheduler_tick+0xe3/0x2a0
> [    0.379861]  update_process_times+0xb4/0xe0
> [    0.379861]  tick_periodic+0x4e/0x110
> [    0.379861]  tick_handle_periodic+0x39/0x90
> [    0.379861]  ? __pfx_timer_interrupt+0x10/0x10
> [    0.379861]  timer_interrupt+0x18/0x30
> [    0.379861]  __handle_irq_event_percpu+0x7b/0x280
> [    0.379861]  handle_irq_event+0x78/0xf0
> [    0.379861]  handle_edge_irq+0x11e/0x400
> [    0.379861]  __common_interrupt+0x3f/0xa0
> [    0.379861]  common_interrupt+0x80/0xa0
> [    0.379861]  </IRQ>
> [    0.379861]  <TASK>
> [    0.379861]  asm_common_interrupt+0x26/0x40
> [    0.379861] RIP: 0010:__tsan_read4+0x34/0x110
> [    0.379861] Code: 4c 8b 1c 24 48 b9 ff ff ff ff ff ff 01 00 48 c1 e8
> 09 49 21 ca 25 f8 01 00 00 4c 8d 80 60 e8 cc 9b 48 05 78 e8 cc 9b 4d 8b
> 08 <4d> 85 c9 79 2a 4c 89 ca 4c 89 ce 48 c1 ea 31 48 21 ce 81 e2 ff 3f
> [    0.379861] RSP: 0000:ffff9fed80013e18 EFLAGS: 00000296
> [    0.379861] RAX: ffffffff9bcce890 RBX: 000000012dbb5ed6 RCX:
> 0001ffffffffffff
> [    0.379861] RDX: 0000000000098472 RSI: ffffffff9b65df00 RDI:
> ffffffff9b043f64
> [    0.379861] RBP: 0000000000b13f20 R08: ffffffff9bcce878 R09:
> 0000000000000000
> [    0.379861] R10: 0001ffff9b043f64 R11: ffffffff9b65df00 R12:
> 00000000fffedb23
> [    0.379861] R13: 0000000000000000 R14: ffff8c2d3ec00000 R15:
> 00000000002c4fc8
> [    0.379861]  ? setup_boot_APIC_clock+0x180/0x8f0
> [    0.379861]  ? setup_boot_APIC_clock+0x180/0x8f0
> [    0.379861]  setup_boot_APIC_clock+0x180/0x8f0
> [    0.379861]  native_smp_prepare_cpus+0x2b/0xc0
> [    0.379861]  kernel_init_freeable+0x41e/0x7d0
> [    0.379861]  ? __pfx_kernel_init+0x10/0x10
> [    0.379861]  kernel_init+0x1f/0x230
> [    0.379861]  ret_from_fork+0x34/0x50
> [    0.379861]  ? __pfx_kernel_init+0x10/0x10
> [    0.379861]  ret_from_fork_asm+0x1a/0x30
> [    0.379861]  </TASK>
> [    0.379861] Modules linked in:
> [    0.379861] CR2: 0000000000030368
> [    0.379861] ---[ end trace 0000000000000000 ]---
> [    0.379861] RIP: 0010:kcsan_setup_watchpoint+0x3cc/0x400
> [    0.379861] Code: 8b 04 24 4c 89 c2 48 31 c2 e9 69 fe ff ff 45 31 c0
> e9 c3 fd ff ff 4c 89 c2 31 c0 e9 57 fe ff ff 45 0f b6 04 24 e9 af fd ff
> ff <45> 8b 04 24 e9 a6 fd ff ff 85 c9 74 08 f0 48 ff 05 b7 a2 6e 02 b9
> [    0.379861] RSP: 0000:ffff9fed80003de0 EFLAGS: 00010046
> [    0.379861] RAX: 0000000000000000 RBX: ffff8c2d3ec302c0 RCX:
> 0000000000000030
> [    0.379861] RDX: 0000000000000001 RSI: ffffffff995ff0f0 RDI:
> 0000000000000000
> [    0.379861] RBP: 0000000000000004 R08: 00000000aaaaaaab R09:
> 0000000000000000
> [    0.379861] R10: 0000000000030368 R11: 0008000000030368 R12:
> 0000000000030368
> [    0.379861] R13: 0000000000000031 R14: 0000000000000000 R15:
> 0000000000000000
> [    0.379861] FS:  0000000000000000(0000) GS:ffff8c2d3ec00000(0000)
> knlGS:0000000000000000
> [    0.379861] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    0.379861] CR2: 0000000000030368 CR3: 0000000030a20000 CR4:
> 00000000000006f0
> [    0.379861] Kernel panic - not syncing: Fatal exception in interrupt
> [    0.379861] ---[ end Kernel panic - not syncing: Fatal exception in
> interrupt ]---
> ```
>
>
> Kind regards,
>
> Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMAfLDZtHaZBZk_tZ-oM5FgYTSOgfbJLTFN7JE-mq0u_A%40mail.gmail.=
com.
