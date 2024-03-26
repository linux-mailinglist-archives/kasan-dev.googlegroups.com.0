Return-Path: <kasan-dev+bncBD2OL34CV4HBBO4GROYAMGQEKMCNESI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FA6788C276
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 13:44:46 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-513e7ff16a8sf4220924e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 05:44:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711457085; cv=pass;
        d=google.com; s=arc-20160816;
        b=ytv0peuQNrgns/SDPauB6ZUXh7iw6GTvdp8/vDoFBtAs8lqrM/uj0FYKYwc0HOaaSo
         HrYVpRdcR/7mzkAkF1G1O8JXFks0fOzDeYV2beL0TGH7zsgK/8xrcT9B64bDRufgu4E/
         WmfO/5u1VUZLj4plzoBuBAgHOnMdh/Q7RywQJdXWgIHmPm332v4yRhmKbdtyVHL+1lnH
         YD+OHbHwLkpUr6vUSy9cHL0rPUrW7FRwFlG1BGiV7d0wCdjYiF+yszrLalYihY9UO09L
         h4RyYWhuy7F9ixliyitFFv18c1zYetVJPwUkmvd+N9YbC21MgUcvFUpo16hhSQRyTP0i
         zRqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=y0Y3jLYwz9svnCIeOYNvC5owIQomSR5rnl1N1NrWJzw=;
        fh=mKhuwQUhWzaV/2V64t6SnNHVMSO1H19rJmd/nGFJCeM=;
        b=lnsLpnFx74DVAxVTjSDWTx9Ll+sPc0S5spON8dqsFLi5nFCephrLnOaGihxlpjturB
         eSMyqE+OpR0lAlrLibdFRbDX8wk8OAWkVId6PcD3HEhWWO4ymHWk7yQdwBNo6DAzZ7ng
         E7MfmxmdwuK42Nm/CVyJtq9ULVhhsDLtVDIUPIWMpXux/5eRRP0FYg9KEqZsqbUEVqBQ
         zQ55wAaiSVFjKbw3mtj1gfFX1pZZ/W52n069x/3cMNc/HrmvB5aJ5WtI/AG+09JWecni
         ND3LDY3hxhB1nwtkfl7tmvef5N33L6yJIZ19rahKINBDZEuTSyL+7lITEVEe3R/utJ1j
         OXaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as permitted sender) smtp.mailfrom=pmenzel@molgen.mpg.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711457085; x=1712061885; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=y0Y3jLYwz9svnCIeOYNvC5owIQomSR5rnl1N1NrWJzw=;
        b=HO3ySuVsoGjP4AT3xUTMFbaMJNyWARoTwuDVx+/rkADBcmRZp+3yW81RiyFj80/VMV
         bM9oFrZvDYl7Vb4HavO2uGEFbuhOunVhOP0xGlBeBmutdo+ZoJXq0jj3ymIe+SZAowE0
         c4sIbdVFN/KyuThHiOzUakRE0cUs2Vl1m1q0ZuLmPF0WtPlRj4EJE4VsoGzN2bYADsN+
         mI35y/DWKTq/yGosHGwCLSZlBrdH5BxcaAdjNp2H4J4tAeRT0arwPqTZ4Q4MDLIh9E+P
         GefeQqsOSNnoCKSHTgwBzzOeIWZS2QlwovICvcplLFw/aV7OH99WwGlncLaiyoN30Lwq
         t+OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711457085; x=1712061885;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y0Y3jLYwz9svnCIeOYNvC5owIQomSR5rnl1N1NrWJzw=;
        b=r+Ft4wNIyIUWrjb2la7ZRtXYOH9onlPcXmSW4CfPJG4kw3lKzNlcgI6z98javlxgnz
         CPalrY+xCJ891FMlE/NGlIGDz+QW+F7K7q4L4C8XkgV1GdTB71P20iBxMQPT8W3KGLF7
         x2NY2DaYgZ+/tcOkRlQty8vYeHvxi2BJ6axIjtm75YjS6MCApfgf3eBV4uSnP5EOwCS2
         5AocHX5iyAEhlm75oKsynvf5NPVEisFUbLVmWbEmobBGXRwkEr4CvF6ccl8ewzsSzEYs
         aXp+vB7CstE5vCoaiy7O08n/1zQAUvniOsWch9I8SrHUcyP9nIL4p7J550BsCo0JXkmv
         fyMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVA9iKr+JDm8ztIC6pjZX+BqTdJt59N5/emVZutRAfGpWDkqhUqwif4kMzFOgUGXTR1q9oftKefnIHbvtbFE8RKlu+FpWovfg==
X-Gm-Message-State: AOJu0Yx8MhZdBjCBkenSz6XZQRAAhGxYHFSpIQS3EUUm/HVKUQh0Uk4U
	ZhnTwTWxXe4d/pJvDF+9oWU/XqYt2T6isxYZXA2nk8AVXMy6Pz47
X-Google-Smtp-Source: AGHT+IHI/3QtdUhAuYirXdlWwZsRZtw6OPHbVCKBRdOjkmyx4bJ+LiNUDhRGVWajUt3Nwnhmy8wPyg==
X-Received: by 2002:a05:6512:3082:b0:515:bacd:adbf with SMTP id z2-20020a056512308200b00515bacdadbfmr803547lfd.34.1711457084089;
        Tue, 26 Mar 2024 05:44:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4c08:0:b0:513:ea9a:5aaf with SMTP id t8-20020ac24c08000000b00513ea9a5aafls1457130lfq.2.-pod-prod-02-eu;
 Tue, 26 Mar 2024 05:44:42 -0700 (PDT)
X-Received: by 2002:a19:4312:0:b0:513:9b6d:ab0e with SMTP id q18-20020a194312000000b005139b6dab0emr816347lfa.5.1711457081766;
        Tue, 26 Mar 2024 05:44:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711457081; cv=none;
        d=google.com; s=arc-20160816;
        b=E/0VI8CS7xGHDVyXOw394h5vmZ/KaKCVwF61MzJfUd0nT+7UDIPBQQL0AkDKvu7Adf
         KeFXWSYIjChIP1nuE3cp5qOBdFoyPIN0FThOmOohI6EGI/VT+myuQPmqhkTPNRqJpVU+
         0EeY25aWukHcJKkNpptae5uCbxQ4dlU0tFOkT3b7TGuaoKfELY2aXWoY2d+pDKB8ejGL
         XdgoXn3tziMDugL3ZxSshGaRBcWDhMrKzfutwjOqWtGDJ9Vkl751tRg6CGouS7348Knd
         G2NGq9Kaal/A3Xd/0yIc9fPmtElZkr/S69+lGaWiFR5YEAIJgwdnDhhP8W1KVHjxpVmJ
         sj0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=PpPZRcAqwzpaQzj7/tooThgFcIsUjei4Xq6upJolZ5I=;
        fh=cGeuCYcpo0sb7GsL/Y46jyTPIFVNaqHc/0lAAbP3BJg=;
        b=alUJOdmS/4bZacPgkb/gAKnHuIWZOdY3HETGLsXXVbc3S994Abog/T4SJoNAOlXl8g
         qTxIqUxiFZobRRqt0/xqa21Fv7y93JVhaOdJU/hVrcQn0OvLDLhntwMFsbHhgdxJGS8K
         NukMZn7+zsLeW0xx083vueRHjBzQbE5+UTm+YQdh/AjLQJdFkLZWFpFnkvDi1Pdye4eV
         xqKf2ZFAkrv1rI+H5zkF4caah5lESMR+KkzpptLhonEQMViC37ANELT3JOLczkuQdyoG
         yaAy4VtenOKYorQaEDs8qzrVkSGc471+LCw1NOWghZ+ZYJpb16dZvrgeBuSaN+ndNp8e
         LMDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as permitted sender) smtp.mailfrom=pmenzel@molgen.mpg.de
Received: from mx3.molgen.mpg.de (mx3.molgen.mpg.de. [141.14.17.11])
        by gmr-mx.google.com with ESMTPS id g7-20020a05600c4ec700b0041466c64287si120311wmq.1.2024.03.26.05.44.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Mar 2024 05:44:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as permitted sender) client-ip=141.14.17.11;
Received: from [141.14.220.34] (g34.guest.molgen.mpg.de [141.14.220.34])
	(using TLSv1.3 with cipher TLS_AES_128_GCM_SHA256 (128/128 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: pmenzel)
	by mx.molgen.mpg.de (Postfix) with ESMTPSA id B909A61E5FE01;
	Tue, 26 Mar 2024 13:44:33 +0100 (CET)
Message-ID: <05ba71e6-6b4e-4496-9183-c75bfc8b64cd@molgen.mpg.de>
Date: Tue, 26 Mar 2024 13:44:32 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: BUG: unable to handle page fault for address: 0000000000030368
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>,
 Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Ingo Molnar <mingo@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 LKML <linux-kernel@vger.kernel.org>
References: <bd455761-3dbf-4f44-a0e3-dff664284fcc@molgen.mpg.de>
 <CANpmjNMAfLDZtHaZBZk_tZ-oM5FgYTSOgfbJLTFN7JE-mq0u_A@mail.gmail.com>
Content-Language: en-US
From: Paul Menzel <pmenzel@molgen.mpg.de>
In-Reply-To: <CANpmjNMAfLDZtHaZBZk_tZ-oM5FgYTSOgfbJLTFN7JE-mq0u_A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pmenzel@molgen.mpg.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of pmenzel@molgen.mpg.de designates 141.14.17.11 as
 permitted sender) smtp.mailfrom=pmenzel@molgen.mpg.de
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

[Cc: +X86 maintainers]

Dear Marco,


Thank you for your quick reply. (Note, that your mailer wrapped the=20
pasted lines.)

Am 26.03.24 um 11:07 schrieb Marco Elver:
> On Tue, 26 Mar 2024 at 10:23, Paul Menzel wrote:

>> Trying KCSAN the first time =E2=80=93 configuration attached =E2=80=93, =
it fails to boot
>> on the Dell XPS 13 9360 and QEMU q35. I couldn=E2=80=99t get logs on the=
 Dell
>> XPS 13 9360, so here are the QEMU ones:
>=20
> If there's a bad access somewhere which is instrumented by KCSAN, it
> will unfortunately still crash inside KCSAN.
>=20
> What happens if you compile with CONFIG_KCSAN_EARLY_ENABLE=3Dn? It
> disables KCSAN (but otherwise the kernel image is the same) and
> requires turning it on manually with "echo on >
> /sys/kernel/debug/kcsan" after boot.
>=20
> If it still crashes, then there's definitely a bug elsewhere. If it
> doesn't crash, and only crashes with KCSAN enabled, my guess is that
> KCSAN's delays of individual threads are perturbing execution to
> trigger previously undetected bugs.

Such a Linux kernel booted with a warning on the Dell XPS 13 9360 (but=20
booted with *no* warning on QEMU q35) [1], but enabling KCSAN on the=20
laptop hangs the laptop right away. I couldn=E2=80=99t get any logs of the =
laptop.

> At least I can't explain it any other way.

How do you test KCSAN?



Kind regards,

Paul


>> ```
>> $ qemu-system-x86_64 -M q35 -enable-kvm -smp cpus=3D2 -m 1G -serial stdi=
o -net nic -net user,hostfwd=3Dtcp::22222-:22 -kernel boot/vmlinuz-6.9.0-rc=
1+ -append "root=3D/dev/sda1 console=3DttyS0"
>> [    0.000000] Linux version 6.9.0-rc1+ (build@bohemianrhapsody.molgen.m=
pg.de) (gcc (Debian 13.2.0-19) 13.2.0, GNU ld (GNU Binutils for Debian) 2.4=
2) #75 SMP PREEMPT_DYNAMIC Tue Mar 26 07:03:41 CET 2024
>> [    0.000000] Command line: root=3D/dev/sda1 console=3DttyS0
>> [    0.000000] BIOS-provided physical RAM map:
>> [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] us=
able
>> [    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x0000000000100000-0x000000003ffdefff] us=
able
>> [    0.000000] BIOS-e820: [mem 0x000000003ffdf000-0x000000003fffffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000b0000000-0x00000000bfffffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000fed1c000-0x00000000fed1ffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] re=
served
>> [    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] re=
served
>> [    0.000000] NX (Execute Disable) protection: active
>> [    0.000000] APIC: Static calls initialized
>> [    0.000000] SMBIOS 3.0.0 present.
>> [    0.000000] DMI: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-deb=
ian-1.16.3-2 04/01/2014
>> [    0.000000] Hypervisor detected: KVM
>> [    0.000000] kvm-clock: Using msrs 4b564d01 and 4b564d00
>> [    0.000001] kvm-clock: using sched offset of 1376980956 cycles
>> [    0.000006] clocksource: kvm-clock: mask: 0xffffffffffffffff max_cycl=
es: 0x1cd42e4dffb, max_idle_ns: 881590591483 ns
>> [    0.000014] tsc: Detected 2904.008 MHz processor
>> [    0.004273] last_pfn =3D 0x3ffdf max_arch_pfn =3D 0x400000000
>> [    0.004315] MTRR map: 4 entries (3 fixed + 1 variable; max 19), built=
 from 8 variable MTRRs
>> [    0.004323] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  WP  UC-=
 WT
>> [    0.012972] found SMP MP-table at [mem 0x000f5480-0x000f548f]
>> [    0.013243] ACPI: Early table checksum verification disabled
>> [    0.013252] ACPI: RSDP 0x00000000000F52C0 000014 (v00 BOCHS )
>> [    0.013265] ACPI: RSDT 0x000000003FFE2357 000038 (v01 BOCHS  BXPC 000=
00001 BXPC 00000001)
>> [    0.013283] ACPI: FACP 0x000000003FFE2147 0000F4 (v03 BOCHS  BXPC 000=
00001 BXPC 00000001)
>> [    0.013304] ACPI: DSDT 0x000000003FFE0040 002107 (v01 BOCHS  BXPC 000=
00001 BXPC 00000001)
>> [    0.013319] ACPI: FACS 0x000000003FFE0000 000040
>> [    0.013331] ACPI: APIC 0x000000003FFE223B 000080 (v03 BOCHS  BXPC 000=
00001 BXPC 00000001)
>> [    0.013346] ACPI: HPET 0x000000003FFE22BB 000038 (v01 BOCHS  BXPC 000=
00001 BXPC 00000001)
>> [    0.013361] ACPI: MCFG 0x000000003FFE22F3 00003C (v01 BOCHS  BXPC 000=
00001 BXPC 00000001)
>> [    0.013375] ACPI: WAET 0x000000003FFE232F 000028 (v01 BOCHS  BXPC 000=
00001 BXPC 00000001)
>> [    0.013388] ACPI: Reserving FACP table memory at [mem 0x3ffe2147-0x3f=
fe223a]
>> [    0.013393] ACPI: Reserving DSDT table memory at [mem 0x3ffe0040-0x3f=
fe2146]
>> [    0.013398] ACPI: Reserving FACS table memory at [mem 0x3ffe0000-0x3f=
fe003f]
>> [    0.013402] ACPI: Reserving APIC table memory at [mem 0x3ffe223b-0x3f=
fe22ba]
>> [    0.013407] ACPI: Reserving HPET table memory at [mem 0x3ffe22bb-0x3f=
fe22f2]
>> [    0.013411] ACPI: Reserving MCFG table memory at [mem 0x3ffe22f3-0x3f=
fe232e]
>> [    0.013416] ACPI: Reserving WAET table memory at [mem 0x3ffe232f-0x3f=
fe2356]
>> [    0.013746] No NUMA configuration found
>> [    0.013750] Faking a node at [mem 0x0000000000000000-0x000000003ffdef=
ff]
>> [    0.013762] NODE_DATA(0) allocated [mem 0x3ffb4000-0x3ffdefff]
>> [    0.015042] Zone ranges:
>> [    0.015047]   DMA      [mem 0x0000000000001000-0x0000000000ffffff]
>> [    0.015056]   DMA32    [mem 0x0000000001000000-0x000000003ffdefff]
>> [    0.015067]   Normal   empty
>> [    0.015073]   Device   empty
>> [    0.015080] Movable zone start for each node
>> [    0.015113] Early memory node ranges
>> [    0.015116]   node   0: [mem 0x0000000000001000-0x000000000009efff]
>> [    0.015122]   node   0: [mem 0x0000000000100000-0x000000003ffdefff]
>> [    0.015128] Initmem setup node 0 [mem 0x0000000000001000-0x000000003f=
fdefff]
>> [    0.015177] On node 0, zone DMA: 1 pages in unavailable ranges
>> [    0.015913] On node 0, zone DMA: 97 pages in unavailable ranges
>> [    0.028914] On node 0, zone DMA32: 33 pages in unavailable ranges
>> [    0.029456] ACPI: PM-Timer IO Port: 0x608
>> [    0.029493] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])
>> [    0.029547] IOAPIC[0]: apic_id 0, version 17, address 0xfec00000, GSI=
 0-23
>> [    0.029558] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)
>> [    0.029564] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 high leve=
l)
>> [    0.029569] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high leve=
l)
>> [    0.029575] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 high le=
vel)
>> [    0.029580] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 high le=
vel)
>> [    0.029597] ACPI: Using ACPI (MADT) for SMP configuration information
>> [    0.029602] ACPI: HPET id: 0x8086a201 base: 0xfed00000
>> [    0.029624] CPU topo: Max. logical packages:   1
>> [    0.029628] CPU topo: Max. logical dies:       1
>> [    0.029631] CPU topo: Max. dies per package:   1
>> [    0.029644] CPU topo: Max. threads per core:   1
>> [    0.029647] CPU topo: Num. cores per package:     2
>> [    0.029650] CPU topo: Num. threads per package:   2
>> [    0.029653] CPU topo: Allowing 2 present CPUs plus 0 hotplug CPUs
>> [    0.029679] kvm-guest: APIC: eoi() replaced with kvm_guest_apic_eoi_w=
rite()
>> [    0.029726] PM: hibernation: Registered nosave memory: [mem 0x0000000=
0-0x00000fff]
>> [    0.029734] PM: hibernation: Registered nosave memory: [mem 0x0009f00=
0-0x0009ffff]
>> [    0.029738] PM: hibernation: Registered nosave memory: [mem 0x000a000=
0-0x000effff]
>> [    0.029742] PM: hibernation: Registered nosave memory: [mem 0x000f000=
0-0x000fffff]
>> [    0.029749] [mem 0x40000000-0xafffffff] available for PCI devices
>> [    0.029753] Booting paravirtualized kernel on KVM
>> [    0.029758] clocksource: refined-jiffies: mask: 0xffffffff max_cycles=
: 0xffffffff, max_idle_ns: 7645519600211568 ns
>> [    0.035898] setup_percpu: NR_CPUS:8192 nr_cpumask_bits:2 nr_cpu_ids:2=
 nr_node_ids:1
>> [    0.036314] percpu: Embedded 65 pages/cpu s229376 r8192 d28672 u10485=
76
>> [    0.036436] kvm-guest: PV spinlocks disabled, no host support
>> [    0.036440] Kernel command line: root=3D/dev/sda1 console=3DttyS0
>> [    0.036669] Dentry cache hash table entries: 131072 (order: 8, 104857=
6 bytes, linear)
>> [    0.036739] Inode-cache hash table entries: 65536 (order: 7, 524288 b=
ytes, linear)
>> [    0.036830] Fallback order for Node 0: 0
>> [    0.036839] Built 1 zonelists, mobility grouping on.  Total pages: 25=
7759
>> [    0.036844] Policy zone: DMA32
>> [    0.036875] mem auto-init: stack:all(zero), heap alloc:on, heap free:=
off
>> [    0.042521] Memory: 260860K/1048052K available (22528K kernel code, 2=
386K rwdata, 6124K rodata, 6304K init, 8064K bss, 70584K reserved, 0K cma-r=
eserved)
>> [    0.056267] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0, CPUs=3D2=
, Nodes=3D1
>> [    0.056279] kmemleak: Kernel memory leak detector disabled
>> [    0.056484] Kernel/User page tables isolation: enabled
>> [    0.056631] ftrace: allocating 43400 entries in 170 pages
>> [    0.065090] ftrace: allocated 170 pages with 4 groups
>> [    0.066107] Dynamic Preempt: voluntary
>> [    0.066496] rcu: Preemptible hierarchical RCU implementation.
>> [    0.066500] rcu:     RCU restricting CPUs from NR_CPUS=3D8192 to nr_c=
pu_ids=3D2.
>> [    0.066505]  Trampoline variant of Tasks RCU enabled.
>> [    0.066508]  Rude variant of Tasks RCU enabled.
>> [    0.066510]  Tracing variant of Tasks RCU enabled.
>> [    0.066513] rcu: RCU calculated value of scheduler-enlistment delay i=
s 25 jiffies.
>> [    0.066517] rcu: Adjusting geometry for rcu_fanout_leaf=3D16, nr_cpu_=
ids=3D2
>> [    0.066535] RCU Tasks: Setting shift to 1 and lim to 1 rcu_task_cb_ad=
just=3D1.
>> [    0.066541] RCU Tasks Rude: Setting shift to 1 and lim to 1 rcu_task_=
cb_adjust=3D1.
>> [    0.066546] RCU Tasks Trace: Setting shift to 1 and lim to 1 rcu_task=
_cb_adjust=3D1.
>> [    0.079398] NR_IRQS: 524544, nr_irqs: 440, preallocated irqs: 16
>> [    0.079764] rcu: srcu_init: Setting srcu_struct sizes based on conten=
tion.
>> [    0.091718] Console: colour VGA+ 80x25
>> [    0.091774] printk: legacy console [ttyS0] enabled
>> [    0.232004] ACPI: Core revision 20230628
>> [    0.233211] clocksource: hpet: mask: 0xffffffff max_cycles: 0xfffffff=
f, max_idle_ns: 19112604467 ns
>> [    0.234715] APIC: Switch to symmetric I/O mode setup
>> [    0.235721] x2apic enabled
>> [    0.236578] APIC: Switched APIC routing to: physical x2apic
>> [    0.239656] ..TIMER: vector=3D0x30 apic1=3D0 pin1=3D2 apic2=3D-1 pin2=
=3D-1
>> [    0.241221] clocksource: tsc-early: mask: 0xffffffffffffffff max_cycl=
es: 0x29dc0d988f1, max_idle_ns: 440795328788 ns
>> [    0.243872] Calibrating delay loop (skipped) preset value.. 5808.01 B=
ogoMIPS (lpj=3D11616032)
>> [    0.246030] Last level iTLB entries: 4KB 0, 2MB 0, 4MB 0
>> [    0.247870] Last level dTLB entries: 4KB 0, 2MB 0, 4MB 0, 1GB 0
>> [    0.248788] Spectre V1 : Mitigation: usercopy/swapgs barriers and __u=
ser pointer sanitization
>> [    0.250127] Spectre V2 : Mitigation: Retpolines
>> [    0.251176] Spectre V2 : Spectre v2 / SpectreRSB mitigation: Filling =
RSB on context switch
>> [    0.251868] Spectre V2 : Spectre v2 / SpectreRSB : Filling RSB on VME=
XIT
>> [    0.253483] Speculative Store Bypass: Vulnerable
>> [    0.255878] MDS: Vulnerable: Clear CPU buffers attempted, no microcod=
e
>> [    0.257191] MMIO Stale Data: Unknown: No mitigations
>> [    0.258243] x86/fpu: x87 FPU will use FXSAVE
>> [    0.327550] Freeing SMP alternatives memory: 36K
>> [    0.327884] pid_max: default: 32768 minimum: 301
>> [    0.330232] LSM: initializing lsm=3Dcapability,landlock,apparmor,tomo=
yo,bpf,ima,evm
>> [    0.332326] landlock: Up and running.
>> [    0.333534] AppArmor: AppArmor initialized
>> [    0.334523] TOMOYO Linux initialized
>> [    0.335895] LSM support for eBPF active
>> [    0.337311] Mount-cache hash table entries: 2048 (order: 2, 16384 byt=
es, linear)
>> [    0.339886] Mountpoint-cache hash table entries: 2048 (order: 2, 1638=
4 bytes, linear)
>> [    0.344459] kcsan: enabled early
>> [    0.345245] kcsan: non-strict mode configured - use CONFIG_KCSAN_STRI=
CT=3Dy to see all data races
>> [    0.375873] BUG: unable to handle page fault for address: 00000000000=
30368
>> [    0.377316] #PF: supervisor read access in kernel mode
>> [    0.378506] #PF: error_code(0x0000) - not-present page
>> [    0.379647] PGD 0 P4D 0
>> [    0.379861] Oops: 0000 [#1] PREEMPT SMP PTI
>> [    0.379861] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 6.9.0-rc1+ #75
>> [    0.379861] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS =
1.16.3-debian-1.16.3-2 04/01/2014
>> [    0.379861] RIP: 0010:kcsan_setup_watchpoint+0x3cc/0x400
>> [    0.379861] Code: 8b 04 24 4c 89 c2 48 31 c2 e9 69 fe ff ff 45 31 c0 =
e9 c3 fd ff ff 4c 89 c2 31 c0 e9 57 fe ff ff 45 0f b6 04 24 e9 af fd ff ff =
<45> 8b 04 24 e9 a6 fd ff ff 85 c9 74 08 f0 48 ff 05 b7 a2 6e 02 b9
>> [    0.379861] RSP: 0000:ffff9fed80003de0 EFLAGS: 00010046
>> [    0.379861] RAX: 0000000000000000 RBX: ffff8c2d3ec302c0 RCX: 00000000=
00000030
>> [    0.379861] RDX: 0000000000000001 RSI: ffffffff995ff0f0 RDI: 00000000=
00000000
>> [    0.379861] RBP: 0000000000000004 R08: 00000000aaaaaaab R09: 00000000=
00000000
>> [    0.379861] R10: 0000000000030368 R11: 0008000000030368 R12: 00000000=
00030368
>> [    0.379861] R13: 0000000000000031 R14: 0000000000000000 R15: 00000000=
00000000
>> [    0.379861] FS:  0000000000000000(0000) GS:ffff8c2d3ec00000(0000) knl=
GS:0000000000000000
>> [    0.379861] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> [    0.379861] CR2: 0000000000030368 CR3: 0000000030a20000 CR4: 00000000=
000006f0
>> [    0.379861] Call Trace:
>> [    0.379861]  <IRQ>
>> [    0.379861]  ? __die+0x23/0x70
>> [    0.379861]  ? page_fault_oops+0x173/0x4f0
>> [    0.379861]  ? exc_page_fault+0x81/0x190
>> [    0.379861]  ? asm_exc_page_fault+0x26/0x30
>> [    0.379861]  ? perf_event_task_tick+0x40/0x130
>> [    0.379861]  ? kcsan_setup_watchpoint+0x3cc/0x400
>> [    0.379861]  ? update_load_avg+0x7e/0x7e0
>> [    0.379861]  ? __hrtimer_run_queues+0x3e/0x4b0
>> [    0.379861]  ? hrtimer_active+0x88/0xc0
>> [    0.379861]  perf_event_task_tick+0x40/0x130
>> [    0.379861]  scheduler_tick+0xe3/0x2a0
>> [    0.379861]  update_process_times+0xb4/0xe0
>> [    0.379861]  tick_periodic+0x4e/0x110
>> [    0.379861]  tick_handle_periodic+0x39/0x90
>> [    0.379861]  ? __pfx_timer_interrupt+0x10/0x10
>> [    0.379861]  timer_interrupt+0x18/0x30
>> [    0.379861]  __handle_irq_event_percpu+0x7b/0x280
>> [    0.379861]  handle_irq_event+0x78/0xf0
>> [    0.379861]  handle_edge_irq+0x11e/0x400
>> [    0.379861]  __common_interrupt+0x3f/0xa0
>> [    0.379861]  common_interrupt+0x80/0xa0
>> [    0.379861]  </IRQ>
>> [    0.379861]  <TASK>
>> [    0.379861]  asm_common_interrupt+0x26/0x40
>> [    0.379861] RIP: 0010:__tsan_read4+0x34/0x110
>> [    0.379861] Code: 4c 8b 1c 24 48 b9 ff ff ff ff ff ff 01 00 48 c1 e8 =
09 49 21 ca 25 f8 01 00 00 4c 8d 80 60 e8 cc 9b 48 05 78 e8 cc 9b 4d 8b 08 =
<4d> 85 c9 79 2a 4c 89 ca 4c 89 ce 48 c1 ea 31 48 21 ce 81 e2 ff 3f
>> [    0.379861] RSP: 0000:ffff9fed80013e18 EFLAGS: 00000296
>> [    0.379861] RAX: ffffffff9bcce890 RBX: 000000012dbb5ed6 RCX: 0001ffff=
ffffffff
>> [    0.379861] RDX: 0000000000098472 RSI: ffffffff9b65df00 RDI: ffffffff=
9b043f64
>> [    0.379861] RBP: 0000000000b13f20 R08: ffffffff9bcce878 R09: 00000000=
00000000
>> [    0.379861] R10: 0001ffff9b043f64 R11: ffffffff9b65df00 R12: 00000000=
fffedb23
>> [    0.379861] R13: 0000000000000000 R14: ffff8c2d3ec00000 R15: 00000000=
002c4fc8
>> [    0.379861]  ? setup_boot_APIC_clock+0x180/0x8f0
>> [    0.379861]  ? setup_boot_APIC_clock+0x180/0x8f0
>> [    0.379861]  setup_boot_APIC_clock+0x180/0x8f0
>> [    0.379861]  native_smp_prepare_cpus+0x2b/0xc0
>> [    0.379861]  kernel_init_freeable+0x41e/0x7d0
>> [    0.379861]  ? __pfx_kernel_init+0x10/0x10
>> [    0.379861]  kernel_init+0x1f/0x230
>> [    0.379861]  ret_from_fork+0x34/0x50
>> [    0.379861]  ? __pfx_kernel_init+0x10/0x10
>> [    0.379861]  ret_from_fork_asm+0x1a/0x30
>> [    0.379861]  </TASK>
>> [    0.379861] Modules linked in:
>> [    0.379861] CR2: 0000000000030368
>> [    0.379861] ---[ end trace 0000000000000000 ]---
>> [    0.379861] RIP: 0010:kcsan_setup_watchpoint+0x3cc/0x400
>> [    0.379861] Code: 8b 04 24 4c 89 c2 48 31 c2 e9 69 fe ff ff 45 31 c0 =
e9 c3 fd ff ff 4c 89 c2 31 c0 e9 57 fe ff ff 45 0f b6 04 24 e9 af fd ff ff =
<45> 8b 04 24 e9 a6 fd ff ff 85 c9 74 08 f0 48 ff 05 b7 a2 6e 02 b9
>> [    0.379861] RSP: 0000:ffff9fed80003de0 EFLAGS: 00010046
>> [    0.379861] RAX: 0000000000000000 RBX: ffff8c2d3ec302c0 RCX: 00000000=
00000030
>> [    0.379861] RDX: 0000000000000001 RSI: ffffffff995ff0f0 RDI: 00000000=
00000000
>> [    0.379861] RBP: 0000000000000004 R08: 00000000aaaaaaab R09: 00000000=
00000000
>> [    0.379861] R10: 0000000000030368 R11: 0008000000030368 R12: 00000000=
00030368
>> [    0.379861] R13: 0000000000000031 R14: 0000000000000000 R15: 00000000=
00000000
>> [    0.379861] FS:  0000000000000000(0000) GS:ffff8c2d3ec00000(0000) knl=
GS:0000000000000000
>> [    0.379861] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> [    0.379861] CR2: 0000000000030368 CR3: 0000000030a20000 CR4: 00000000=
000006f0
>> [    0.379861] Kernel panic - not syncing: Fatal exception in interrupt
>> [    0.379861] ---[ end Kernel panic - not syncing: Fatal exception in i=
nterrupt ]---
>> ```

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/05ba71e6-6b4e-4496-9183-c75bfc8b64cd%40molgen.mpg.de.
