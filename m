Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2V5XCPQMGQEPOFQE7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EDA5699423
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 13:17:47 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-527501b56ffsf17914267b3.15
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 04:17:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676549866; cv=pass;
        d=google.com; s=arc-20160816;
        b=xbuT+9RSt07LQBfzcRHSs1BBp9gMnu7yg726qU1Vq1dU5316SByDU7achivTw0oF2f
         Ja7SUgk3bcIpTHckkBVavsZSqU1evQVQX2gpaUAiW3Gi9nAt7gw/QWkx3voeyFQLgkGw
         NSvsDQqKHBLnY8KIIxkM2IEeHQvbKXo1CqgtgA62Lh/E+4zz29Isuc1jPpx43wZWTBQ4
         BqheFUFGzS+3Xb80qIlqXl4DAjBJdZ6qavtgCcLkSYuWDgWAlblNkf5qVfbn3HMTJ0iY
         akv2V8BLxBK0ejzeIZNIQQwyv6HAvwlka1jOhjY9GL5YAgL86nakq+RMhosNb9D00jz6
         Bexw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E/jTniYjIrnYoEr3KRJvgYB98Z4hdwZuwYke0y8YatQ=;
        b=aWSKCC4jYiv9/iwiY0DMU0+xmoRGVWkk9d0SU2W3NZXEgIi050T3eI0/+KrrcWlzZP
         I+3157afEEJ18bdzPAzNWiv3eYj/dHfuIzZdtYvRVSzAuon/AtELDKdCYRYdSXM8TKCO
         joCMh+EycoeI/CPDr2X7iRFo3IaMtRDGK3jJjNyd0eJvpdPYElV1NhBec4K0WNk5AxDN
         H0VK0gEoRnpQDg+CV+ordLzo4Vn8lfRxz4ChuCWp/iAPaMflxxn8BNZmmXBN/cn+3rls
         T3IlT6Ca1IFQQAtLsa0tJIwqW1LaJ1yl8adqpk+l+2R4CdqSVAievPLePf4B/dBGpbSC
         CHGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BwFxiUvL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E/jTniYjIrnYoEr3KRJvgYB98Z4hdwZuwYke0y8YatQ=;
        b=bOIldsDms3RZca3fcCR7tgIeejK/vJ45ttrVw008QuU7i/zkJFS3MmiNc9vo5TrEQA
         DUs2ZbztsJekoeukC1IlrQ+UJUMGtt55ad7X61iui1lOfBz4wow9YZzVGVCPpMA1TXkG
         ap9a+hkinsoJ1Drx9ziv4pwNb0/J5t+shZuTDFbW5PBQyYqWKb1W8X/vZiTC62263wKB
         K5yOJZuKioCL9cJp63Y6C8c/0JbYhwUQX97ntw5RlQFacZpXlRQIyv8enDY9dpv4CeIM
         +ziTYPh7CBa+6V00ZaBh0n8nZNucexvLF79nJ+RY2bt9lU0sRXHr+0TD1jXa0VTpfggn
         3B7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=E/jTniYjIrnYoEr3KRJvgYB98Z4hdwZuwYke0y8YatQ=;
        b=g9RVHtaMkMUxza7kUl4P1x1/5flowGQ6FwEMWE4xL29pLrn6TGNU3aVQ0g6jQWJe6S
         Vu1BYm1kfdfaVECC3cz+xN/vg3o9DNt94lWtKcgABcsuhaC5EeN/zza8ilQMylPC/IOL
         2SVSWRZM+9j1t0EUgl4qgWXp9Ne2bcHUC5DM8zJ43dvIltPb/ZXdy/vBQxkVPnmZMfL8
         RDRsvtCc/ROQBaswKyqjiCrn1dQtlaW63ITfXZ7ig7UnCBnDkJ0n2Kog/eQnTa/+4ssw
         qJkqkjOUGL+PXe/ph+N9TL85NbvXhcBRQCMJG14IEYkepLtpNiuqfRi/tD5d61epn3LN
         k9DQ==
X-Gm-Message-State: AO0yUKVlDE9qTpZwMrhumqIZLO0CV1Ptrop7YMrOC53hUNq+CzrEokTh
	pePILQDALjeboSOmw2g0PCjqFQ==
X-Google-Smtp-Source: AK7set8+H/xoFJlngSyqL9MxFETBC/CnthnjeArCX6sIwkcmIu+kgF5QIEfyLRsMUSaLpfQ2jMCCQA==
X-Received: by 2002:a5b:3ca:0:b0:928:7f5b:fdce with SMTP id t10-20020a5b03ca000000b009287f5bfdcemr482132ybp.47.1676549866178;
        Thu, 16 Feb 2023 04:17:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:4cc8:0:b0:52e:eb33:90c6 with SMTP id z191-20020a814cc8000000b0052eeb3390c6ls816312ywa.9.-pod-prod-gmail;
 Thu, 16 Feb 2023 04:17:45 -0800 (PST)
X-Received: by 2002:a0d:d301:0:b0:527:b0f3:b2c7 with SMTP id v1-20020a0dd301000000b00527b0f3b2c7mr3988736ywd.51.1676549865451;
        Thu, 16 Feb 2023 04:17:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676549865; cv=none;
        d=google.com; s=arc-20160816;
        b=Ivt8Zgs3+ckUFe/dswl9DSKLA28dDn9LyCqXIZBnx0CVnPNo7iFkU4twAtcmbdh/8o
         PK0HgkDPLONgRzuU3nvzDIHtzX02qAHtudbDMsemW7HCK70gCidjAWF2chKTgavv5PKZ
         uu+IKLLFF1nE3BbRovx/Hw/kapIYqDfgdQqWDpnMNhYSpFnSMxwrIGG1wba2pAxspiEF
         u0zSLTQ2rzooFDdIoF17GmCzv4y1klW384rOt0VMF5b/Ttr1nvZ7xORZAsMcrww8SzRv
         d3iTOBQNJ3zD39YsXNerd/Ir83v4GrYqqZmsOokb7vkLs2GgH7gNUK/1NYxGP/VaTrAB
         aQXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kKetw1FKB0l1/O0VGIOBIy83NDOmUM2G2EzyQfB0t8E=;
        b=B0ByUoLki25b+Ezc8tEdjbY1XyrohBsAuIu8VVPQIAzciExosnpPOBuKX5CcdJRWPt
         gJPhLez8sEzGHhNqZdffFyhnRSiwYLZiZqPWmgbjx3tUS5Z871yZlk2PnugFlrnOU/Rv
         zM+gc5Yuam0Gjy4s5fFDMu4N3Mc2Z2q9MFl4Rgije2zDA4WD2xS/ajDR1uhbMzugVMiH
         5QKxU/fiMuOl0v82Nu0ZH34JW3BspIQ3NDfBJD/I8+xPvOU5tS5B4WqhhomGMyhQg5TK
         beULDr1YTckn9PgpOY+QL39nQf8+EyBbVW1zcmJO9R/BhMhkp958NOSq7wC6KEqJjmQA
         4h2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BwFxiUvL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2a.google.com (mail-vk1-xa2a.google.com. [2607:f8b0:4864:20::a2a])
        by gmr-mx.google.com with ESMTPS id 188-20020a8104c5000000b0050646ae9a2fsi131163ywe.4.2023.02.16.04.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 04:17:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) client-ip=2607:f8b0:4864:20::a2a;
Received: by mail-vk1-xa2a.google.com with SMTP id n22so1066203vkm.11
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 04:17:45 -0800 (PST)
X-Received: by 2002:a1f:13d4:0:b0:3ea:78fc:6dd8 with SMTP id
 203-20020a1f13d4000000b003ea78fc6dd8mr983810vkt.21.1676549864979; Thu, 16 Feb
 2023 04:17:44 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
In-Reply-To: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Feb 2023 13:17:08 +0100
Message-ID: <CANpmjNOnU+vsOzXJZ_usj81NE371jUJoqtyvFvi_g9_QjZ=F-g@mail.gmail.com>
Subject: Re: next: x86_64: kunit test crashed and kernel panic
To: Naresh Kamboju <naresh.kamboju@linaro.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	regressions@lists.linux.dev, Anders Roxell <anders.roxell@linaro.org>, 
	Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BwFxiUvL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as
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

+Cc Andrey, Alex

On Thu, 16 Feb 2023 at 13:13, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> Following kernel panic noticed while running KUNIT testing on qemu-x86_64
> with KASAN enabled kernel.
>
> CONFIG_KASAN=y
> CONFIG_KUNIT=y
> CONFIG_KUNIT_ALL_TESTS=y
>
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>
> Boot log:
> ---------
> <5>[    0.000000] Linux version 6.2.0-rc8-next-20230216
> (tuxmake@tuxmake) (x86_64-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0, GNU
> ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC @1676522550
> <6>[    0.000000] Command line: console=ttyS0,115200 rootwait
> root=/dev/sda debug verbose console_msg_format=syslog earlycon
> <6>[    0.000000] x86/fpu: x87 FPU will use FXSAVE
> <6>[    0.000000] signal: max sigframe size: 1440
> ...
> <6>[    0.001000] kasan: KernelAddressSanitizer initialized
> ...
> <6>[   16.570308] KTAP version 1
> <6>[   16.570801] 1..62
> <6>[   16.574277]     KTAP version 1
> ...
> <6>[   38.688296]     ok 16 kmalloc_uaf_16
> <3>[   38.692992]     # kmalloc_oob_in_memset: EXPECTATION FAILED at
> mm/kasan/kasan_test.c:558
> <3>[   38.692992]     KASAN failure expected in \"memset(ptr, 0, size
> + KASAN_GRANULE_SIZE)\", but none occurred
> <6>[   38.695659]     not ok 17 kmalloc_oob_in_memset
> <3>[   38.702362]     # kmalloc_oob_memset_2: EXPECTATION FAILED at
> mm/kasan/kasan_test.c:505
> <3>[   38.702362]     KASAN failure expected in \"memset(ptr + size -
> 1, 0, 2)\", but none occurred
> <6>[   38.704750]     not ok 18 kmalloc_oob_memset_2
> <3>[   38.710076]     # kmalloc_oob_memset_4: EXPECTATION FAILED at
> mm/kasan/kasan_test.c:518
> <3>[   38.710076]     KASAN failure expected in \"memset(ptr + size -
> 3, 0, 4)\", but none occurred
> <6>[   38.712349]     not ok 19 kmalloc_oob_memset_4
> <3>[   38.718545]     # kmalloc_oob_memset_8: EXPECTATION FAILED at
> mm/kasan/kasan_test.c:531
> <3>[   38.718545]     KASAN failure expected in \"memset(ptr + size -
> 7, 0, 8)\", but none occurred
> <6>[   38.721274]     not ok 20 kmalloc_oob_memset_8
> <3>[   38.726201]     # kmalloc_oob_memset_16: EXPECTATION FAILED at
> mm/kasan/kasan_test.c:544
> <3>[   38.726201]     KASAN failure expected in \"memset(ptr + size -
> 15, 0, 16)\", but none occurred
> <6>[   38.728269]     not ok 21 kmalloc_oob_memset_16
> <4>[   38.735350] general protection fault, probably for non-canonical
> address 0xa0de1c2100000008: 0000 [#1] PREEMPT SMP KASAN PTI
> <4>[   38.737084] CPU: 0 PID: 131 Comm: kunit_try_catch Tainted: G
> B            N 6.2.0-rc8-next-20230216 #1
> <4>[   38.738232] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
> BIOS 1.14.0-2 04/01/2014
> <4>[   38.739202] RIP: 0010:__stack_depot_save+0x16b/0x4a0
> <4>[   38.740158] Code: 29 c8 89 c3 48 8b 05 bc ef 4a 03 89 de 23 35
> ac ef 4a 03 4c 8d 04 f0 4d 8b 20 4d 85 e4 75 0b eb 77 4d 8b 24 24 4d
> 85 e4 74 6e <41> 39 5c 24 08 75 f0 41 3b 54 24 0c 75 e9 31 c0 49 8b 7c
> c4 18 49
> <4>[   38.742135] RSP: 0000:ffff88815b409a00 EFLAGS: 00000286
> <4>[   38.743055] RAX: ffff88815a600000 RBX: 00000000a0de1c21 RCX:
> 000000000000000e
> <4>[   38.744084] RDX: 000000000000000e RSI: 00000000000e1c21 RDI:
> 00000000282127a7
> <4>[   38.745061] RBP: ffff88815b409a58 R08: ffff88815ad0e108 R09:
> 0000000005d4305e
> <4>[   38.746039] R10: ffffed1020693eb9 R11: ffff88815b409ff8 R12:
> a0de1c2100000000
> <4>[   38.747012] R13: 0000000000000001 R14: 0000000000000800 R15:
> ffff88815b409a68
> <4>[   38.748039] FS:  0000000000000000(0000)
> GS:ffff88815b400000(0000) knlGS:0000000000000000
> <4>[   38.749066] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> <4>[   38.749848] CR2: a0de1c2100000008 CR3: 000000012c2ae000 CR4:
> 00000000000006f0
> <4>[   38.750769] DR0: ffffffff97419b80 DR1: ffffffff97419b81 DR2:
> ffffffff97419b82
> <4>[   38.751712] DR3: ffffffff97419b83 DR6: 00000000ffff0ff0 DR7:
> 0000000000000600
> <4>[   38.752692] Call Trace:
> <4>[   38.753288]  <IRQ>
> <4>[   38.753795]  kasan_save_stack+0x4c/0x60
> <4>[   38.754479]  ? kasan_save_stack+0x3c/0x60
> <4>[   38.755112]  ? kasan_set_track+0x29/0x40
> <4>[   38.756690]  ? kasan_save_free_info+0x32/0x50
> <4>[   38.757186]  ? ____kasan_slab_free+0x175/0x1d0
> <4>[   38.757830]  ? __kasan_slab_free+0x16/0x20
> <4>[   38.758525]  ? __kmem_cache_free+0x18c/0x300
> <4>[   38.759187]  ? kfree+0x7c/0x120
> <4>[   38.759756]  ? free_kthread_struct+0x78/0xa0
> <4>[   38.760516]  ? free_task+0x96/0xa0
> <4>[   38.761127]  ? __put_task_struct+0x1a2/0x1f0
> <4>[   38.761843]  ? delayed_put_task_struct+0xec/0x110
> <4>[   38.762595]  ? rcu_core+0x4e3/0x1010
> <4>[   38.763180]  ? rcu_core_si+0x12/0x20
> <4>[   38.763842]  ? __do_softirq+0x18f/0x502
> <4>[   38.764464]  ? __irq_exit_rcu+0xa1/0xe0
> <4>[   38.764982]  ? irq_exit_rcu+0x12/0x20
> <4>[   38.765760]  ? sysvec_apic_timer_interrupt+0x7d/0xa0
> <4>[   38.766544]  ? asm_sysvec_apic_timer_interrupt+0x1f/0x30
> <4>[   38.767391]  ? memmove+0x3c/0x1c0
> <4>[   38.767994]  ? kunit_try_run_case+0x8e/0x130
> <4>[   38.768718]  ? kunit_generic_run_threadfn_adapter+0x33/0x50
> <4>[   38.769477]  ? kthread+0x17f/0x1b0
> <4>[   38.769871]  ? ret_from_fork+0x2c/0x50
> <4>[   38.770841]  ? kfree+0x7c/0x120
> <4>[   38.771470]  kasan_set_track+0x29/0x40
> <4>[   38.772101]  kasan_save_free_info+0x32/0x50
> <4>[   38.772855]  ____kasan_slab_free+0x175/0x1d0
> <4>[   38.773536]  ? free_kthread_struct+0x78/0xa0
> <4>[   38.774175]  __kasan_slab_free+0x16/0x20
> <4>[   38.774865]  __kmem_cache_free+0x18c/0x300
> <4>[   38.775553]  kfree+0x7c/0x120
> <4>[   38.776137]  free_kthread_struct+0x78/0xa0
> <4>[   38.776840]  free_task+0x96/0xa0
> <4>[   38.777220]  __put_task_struct+0x1a2/0x1f0
> <4>[   38.778103]  delayed_put_task_struct+0xec/0x110
> <4>[   38.778786]  rcu_core+0x4e3/0x1010
> <4>[   38.779450]  ? __pfx_rcu_core+0x10/0x10
> <4>[   38.780147]  ? __pfx_read_tsc+0x10/0x10
> <4>[   38.780750]  ? __do_softirq+0x11f/0x502
> <4>[   38.781480]  rcu_core_si+0x12/0x20
> <4>[   38.782073]  __do_softirq+0x18f/0x502
> <4>[   38.782755]  ? __pfx___do_softirq+0x10/0x10
> <4>[   38.783442]  ? trace_preempt_on+0x20/0xa0
> <4>[   38.784070]  ? __irq_exit_rcu+0x17/0xe0
> <4>[   38.784767]  __irq_exit_rcu+0xa1/0xe0
> <4>[   38.785377]  irq_exit_rcu+0x12/0x20
> <4>[   38.786028]  sysvec_apic_timer_interrupt+0x7d/0xa0
> <4>[   38.786781]  </IRQ>
> <4>[   38.787107]  <TASK>
> <4>[   38.787639]  asm_sysvec_apic_timer_interrupt+0x1f/0x30
> <4>[   38.788698] RIP: 0010:memmove+0x3c/0x1c0
> <4>[   38.789436] Code: 49 39 f8 0f 8f b5 00 00 00 48 83 fa 20 0f 82
> 01 01 00 00 0f 1f 44 00 00 48 81 fa a8 02 00 00 72 05 40 38 fe 74 48
> 48 83 ea 20 <48> 83 ea 20 4c 8b 1e 4c 8b 56 08 4c 8b 4e 10 4c 8b 46 18
> 48 8d 76
> <4>[   38.791297] RSP: 0000:ffff888103507e08 EFLAGS: 00000286
> <4>[   38.792130] RAX: ffff8881033e9000 RBX: ffff8881033e9000 RCX:
> 0000000000000000
> <4>[   38.792969] RDX: fffffffffff8727e RSI: ffff888103461d64 RDI:
> ffff888103461d60
> <4>[   38.793818] RBP: ffff888103507eb8 R08: 0000000100000000 R09:
> 0000000000000000
> <4>[   38.794643] R10: 0000000000000000 R11: 0000000000000000 R12:
> 1ffff110206a0fc2
> <4>[   38.795458] R13: ffff888100327b60 R14: ffff888103507e90 R15:
> fffffffffffffffe
> <4>[   38.796558]  ? kmalloc_memmove_negative_size+0xeb/0x1f0
> <4>[   38.797376]  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10
> <4>[   38.798257]  ? __kasan_check_write+0x18/0x20
> <4>[   38.798923]  ? _raw_spin_lock_irqsave+0xa2/0x110
> <4>[   38.799617]  ? _raw_spin_unlock_irqrestore+0x2c/0x60
> <4>[   38.800491]  ? trace_preempt_on+0x20/0xa0
> <4>[   38.801150]  ? __kthread_parkme+0x4f/0xd0
> <4>[   38.801778]  kunit_try_run_case+0x8e/0x130
> <4>[   38.802505]  ? __pfx_kunit_try_run_case+0x10/0x10
> <4>[   38.803197]  ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10
> <4>[   38.803997]  kunit_generic_run_threadfn_adapter+0x33/0x50
> <4>[   38.804749]  kthread+0x17f/0x1b0
> <4>[   38.805377]  ? __pfx_kthread+0x10/0x10
> <4>[   38.806025]  ret_from_fork+0x2c/0x50
> <4>[   38.806716]  </TASK>
> <4>[   38.807261] Modules linked in:
> <4>[   38.809163] ---[ end trace 0000000000000000 ]---
> <4>[   38.809731] RIP: 0010:__stack_depot_save+0x16b/0x4a0
> <4>[   38.810988] Code: 29 c8 89 c3 48 8b 05 bc ef 4a 03 89 de 23 35
> ac ef 4a 03 4c 8d 04 f0 4d 8b 20 4d 85 e4 75 0b eb 77 4d 8b 24 24 4d
> 85 e4 74 6e <41> 39 5c 24 08 75 f0 41 3b 54 24 0c 75 e9 31 c0 49 8b 7c
> c4 18 49
> <4>[   38.812911] RSP: 0000:ffff88815b409a00 EFLAGS: 00000286
> <4>[   38.813435] RAX: ffff88815a600000 RBX: 00000000a0de1c21 RCX:
> 000000000000000e
> <4>[   38.815407] RDX: 000000000000000e RSI: 00000000000e1c21 RDI:
> 00000000282127a7
> <4>[   38.816630] RBP: ffff88815b409a58 R08: ffff88815ad0e108 R09:
> 0000000005d4305e
> <4>[   38.817540] R10: ffffed1020693eb9 R11: ffff88815b409ff8 R12:
> a0de1c2100000000
> <4>[   38.818685] R13: 0000000000000001 R14: 0000000000000800 R15:
> ffff88815b409a68
> <4>[   38.819949] FS:  0000000000000000(0000)
> GS:ffff88815b400000(0000) knlGS:0000000000000000
> <4>[   38.821375] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> <4>[   38.822431] CR2: a0de1c2100000008 CR3: 000000012c2ae000 CR4:
> 00000000000006f0
> <4>[   38.823562] DR0: ffffffff97419b80 DR1: ffffffff97419b81 DR2:
> ffffffff97419b82
> <4>[   38.824702] DR3: ffffffff97419b83 DR6: 00000000ffff0ff0 DR7:
> 0000000000000600
> <0>[   38.826157] Kernel panic - not syncing: Fatal exception in interrupt
> <0>[   38.828641] Kernel Offset: 0x12400000 from 0xffffffff81000000
> (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
> <0>[   38.830146] ---[ end Kernel panic - not syncing: Fatal exception
> in interrupt ]---
>
>
> links:
> ----
> https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230216/testrun/14817835/suite/log-parser-test/test/check-kernel-panic/log
> https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230216/testrun/14817835/suite/log-parser-test/tests/
> https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230216/testrun/14817835/suite/log-parser-test/test/check-kernel-panic/details/
>
>
> steps to reproduce:
> ---
> tuxrun  \
>  --runtime podman  \
>  --device qemu-x86_64  \
>  --kernel https://storage.tuxsuite.com/public/linaro/lkft/builds/2Lo0yXyxgpsuMQhyLdw5jKk9nSj/bzImage
>  \
>  --modules https://storage.tuxsuite.com/public/linaro/lkft/builds/2Lo0yXyxgpsuMQhyLdw5jKk9nSj/modules.tar.xz
>  \
>  --rootfs https://storage.tuxsuite.com/public/linaro/lkft/oebuilds/2LUxobLpTjiRrzSKqqYOwhong7e/images/intel-corei7-64/lkft-tux-image-intel-corei7-64-20230209111930.rootfs.ext4.gz
>  \
>  --parameters SKIPFILE=skipfile-lkft.yaml  \
>  --image docker.io/lavasoftware/lava-dispatcher:2023.01.0020.gc1598238f  \
>  --tests kunit  \
>  --timeouts boot=15 kunit=30
>
> --
> Linaro LKFT
> https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOnU%2BvsOzXJZ_usj81NE371jUJoqtyvFvi_g9_QjZ%3DF-g%40mail.gmail.com.
