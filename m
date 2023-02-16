Return-Path: <kasan-dev+bncBCT6537ZTEKRB6V3XCPQMGQEEA2EZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0335B69940B
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 13:13:48 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-16e2b623700sf1089622fac.19
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 04:13:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676549626; cv=pass;
        d=google.com; s=arc-20160816;
        b=lZ1V7QUZMShR0LLgJIaAgcW6Z26YBKLOjRbyp/x2EmtTh7fRK2jArDpQgHyybTx0jE
         5Lwdws1C+w5JwsRm2hywlN1v6CwPrkvnQVdLFWS5HIBWlawEE633s1pAcfFJLRCR8y/1
         iGS0dTdlZVjyNG1/R8zgniCnw/9EPQ05eNj/SxtI2TcFrMxAf9PURvmZqhscK4sbgXNh
         WuQC6HDoCsq39QpP8LfR5u1lhbMpKTKM3adXLdw049ZViAIowidtiAWDa6aez55ZVuVD
         BhBKktKA3hgTaDk5R1KnoVh5Yu2waj9ZxMMAmVCPfvyeOI+cWieXpIQ5pX3wtioxoRl8
         JOLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=KGXNwmUY9cBgjKY3Q+gSq1RxDaMEZbymwvDsocZLLL8=;
        b=xWMRQsrQHX2Ne9aqf+Twu2nS8hPAXa/lQfdK45AFbMpV1j8Ghitn14vY4+Bbpg+chp
         SlUYOMY/Ndwm2x48Wi+Big2USYEzUN7UvrFjxuCgHRD1leQ05eH8tXOKQJJGkUWa27SU
         aXT822FPwXcdbhhB9a4vtdoIala054LmApIG1O5Lo226PqJzM2BJITTCvzHLbhPEFQLd
         38l1DKaP/Vfd5KDakChpjJe6JCUQB3p7Fi2FuFVvU2jPjlXwJ1b8Cz5Ybhe8JGdzHMHJ
         ngyEvDSst4DKDtE1V/J+rFoYyfkPrC35C5dBf260vKeL8gokiwT0bUtlLhIlIq1S1giS
         4sug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SoDnVhC4;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KGXNwmUY9cBgjKY3Q+gSq1RxDaMEZbymwvDsocZLLL8=;
        b=WGjl2i8mM6IzlOMU8OFIeZI9Lp8Tkn1/rK4XjZu5BxYAC3fQOlsgYYtPnXXu2UmVqr
         NySLKkWOn7tklWYgzk4GctONkl1VMlmRnBjMTYZ9j9TP6ePdlVLu9ZfLu3uOx3t6RTIc
         xImMxyCP3kNo1R+v9TBlf6DbKZ22Le+KoLSJpCeWKgM1i+8heZBqKOZOdXG2CKTgjKp+
         aI2r8eOIAYD2S6m4Mmoo5dDye+ZKQluu3WpSke2FvMgJN/t55NTWjD9yYulP24dLw3t0
         nJmHmGrMYOwUBESKmtHVlnJGkPzZxCKcVW2qv/3rPKU8FurCuGfYniK8Uc6xkXmjZBIJ
         pAjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KGXNwmUY9cBgjKY3Q+gSq1RxDaMEZbymwvDsocZLLL8=;
        b=SkR2UiZkQnmR/u3B4ori7GnsKsE3tk1a6xtaRWaGjxShFCgQ1AFdci9kVhMpnu8qmH
         Z2HK9CEdVeIKMv1D73PaZ86q0NLrmkbWcrlp3QSdIhVv1Zq8xabWC5Bi8r/s6NT1BkPR
         hOvumjyKeQ4uhOejsij/OxAgvBxUK5HFk7gx1lSOpQ3MiCMsDd+4Gk7ENcc6QKPdQ+9K
         Hyjl/hwu3P7LLXUpX1iVb77GD1s9hHM8AhzZxNXiSdiT9EQcKgr93PcqZ7RwgOlHxRSb
         JIj5sVogNqdbuN6CDCdJdM5OE0mEYQDOFjQ54QTSm1hxOGVm/qO9IyG8lFD9UcmIY6SZ
         egkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUDCn/Q7f51r9wTNuSwGI3/N9KbQVjEC7F6uo1ryMCCJblOF6Ax
	okAZJEB5KXvrmzyBUfmEfJ8=
X-Google-Smtp-Source: AK7set94LFBZ/bF+k4DnOzlTJWlwHsiKqYWojLl7mtJuFzpnP/upNVYoHfUXA48X9iHNUBSD2LU+YQ==
X-Received: by 2002:a05:6808:1903:b0:37d:6e92:eb4d with SMTP id bf3-20020a056808190300b0037d6e92eb4dmr126476oib.147.1676549626508;
        Thu, 16 Feb 2023 04:13:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1204:0:b0:37b:7b50:657d with SMTP id 4-20020aca1204000000b0037b7b50657dls607983ois.8.-pod-prod-gmail;
 Thu, 16 Feb 2023 04:13:46 -0800 (PST)
X-Received: by 2002:a05:6808:43:b0:378:2b0c:493f with SMTP id v3-20020a056808004300b003782b0c493fmr2137171oic.19.1676549625960;
        Thu, 16 Feb 2023 04:13:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676549625; cv=none;
        d=google.com; s=arc-20160816;
        b=qlY9c66bvFU05DUW60aeLgGhUlndzPzdLoXWn/rTzRtwoPss6B+v8TK0esF5pNytNZ
         wlgJQOl2zuEgE88YBZpsGDA1WYzs/gT7TUG0ZnOwcCUn6v9EYDmo9uLlwGL1Vgj+m1XZ
         nndw0PqblOaPDIytJtyRDsGeFSN4mQuKgjKZwS02V5QAiJzklXETEPQ2eEuryHQNXkt3
         tm94WOm82Ot7scCkN40JAmSD7tG0Yo7QZegoyhUGV+kyWOiUJMFMdc3u/lmpSHTdubUX
         n3GfuhX957B0bt7aJ2iXMO6CAYpbhpElHT1hsrVxZ6GNY8sADQwTuJyN4ax9BND2UNOE
         3+bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=W8yheI6Ev2vCWCjtqaZ1PTSNedyk7XdbtOBVzcTh5Mo=;
        b=JseCxzaPVXmBq5NUzWcbXmRXddOOlQVTa9wuuDnBMCiVu0vFICfb/6rURcrflFqodd
         KkuFiGaGyaOj6Cw+31slBpeHY/5+rqMtiq7rjwAiKVgOtUZd/L7mPVlmDnhnhCIa1QZU
         v7u0nXggVM5LbxabE+GSrOwdPe2w5CLl+p/05nghnI2QwJWt4Qp8yv0Gexvnl/FJZeXK
         BIKEZCXDzMcKyDZNzyjTNhvBO4l0ESydOob1nVlStgUoZry4m2vs29Ua7kFq949CQwvH
         4BkrUIc2DDqTJx6otXQOVOhdaCCMFKgrVKagcwx1DAFNRacQtcNk6Rl8g0jyCw6YzEKO
         HOHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=SoDnVhC4;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ua1-x935.google.com (mail-ua1-x935.google.com. [2607:f8b0:4864:20::935])
        by gmr-mx.google.com with ESMTPS id be15-20020a056808218f00b0037fa165aa27si3408oib.1.2023.02.16.04.13.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 04:13:45 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::935 as permitted sender) client-ip=2607:f8b0:4864:20::935;
Received: by mail-ua1-x935.google.com with SMTP id bx25so382417uab.9
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 04:13:45 -0800 (PST)
X-Received: by 2002:ab0:7552:0:b0:68a:751e:a4a with SMTP id
 k18-20020ab07552000000b0068a751e0a4amr625307uaq.9.1676549624973; Thu, 16 Feb
 2023 04:13:44 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Thu, 16 Feb 2023 17:43:33 +0530
Message-ID: <CA+G9fYvZqytp3gMnC4-no9EB=Jnzqmu44i8JQo6apiZat-xxPg@mail.gmail.com>
Subject: next: x86_64: kunit test crashed and kernel panic
To: kasan-dev <kasan-dev@googlegroups.com>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	regressions@lists.linux.dev
Cc: Marco Elver <elver@google.com>, Anders Roxell <anders.roxell@linaro.org>, 
	Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=SoDnVhC4;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Following kernel panic noticed while running KUNIT testing on qemu-x86_64
with KASAN enabled kernel.

CONFIG_KASAN=y
CONFIG_KUNIT=y
CONFIG_KUNIT_ALL_TESTS=y

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

Boot log:
---------
<5>[    0.000000] Linux version 6.2.0-rc8-next-20230216
(tuxmake@tuxmake) (x86_64-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0, GNU
ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC @1676522550
<6>[    0.000000] Command line: console=ttyS0,115200 rootwait
root=/dev/sda debug verbose console_msg_format=syslog earlycon
<6>[    0.000000] x86/fpu: x87 FPU will use FXSAVE
<6>[    0.000000] signal: max sigframe size: 1440
...
<6>[    0.001000] kasan: KernelAddressSanitizer initialized
...
<6>[   16.570308] KTAP version 1
<6>[   16.570801] 1..62
<6>[   16.574277]     KTAP version 1
...
<6>[   38.688296]     ok 16 kmalloc_uaf_16
<3>[   38.692992]     # kmalloc_oob_in_memset: EXPECTATION FAILED at
mm/kasan/kasan_test.c:558
<3>[   38.692992]     KASAN failure expected in \"memset(ptr, 0, size
+ KASAN_GRANULE_SIZE)\", but none occurred
<6>[   38.695659]     not ok 17 kmalloc_oob_in_memset
<3>[   38.702362]     # kmalloc_oob_memset_2: EXPECTATION FAILED at
mm/kasan/kasan_test.c:505
<3>[   38.702362]     KASAN failure expected in \"memset(ptr + size -
1, 0, 2)\", but none occurred
<6>[   38.704750]     not ok 18 kmalloc_oob_memset_2
<3>[   38.710076]     # kmalloc_oob_memset_4: EXPECTATION FAILED at
mm/kasan/kasan_test.c:518
<3>[   38.710076]     KASAN failure expected in \"memset(ptr + size -
3, 0, 4)\", but none occurred
<6>[   38.712349]     not ok 19 kmalloc_oob_memset_4
<3>[   38.718545]     # kmalloc_oob_memset_8: EXPECTATION FAILED at
mm/kasan/kasan_test.c:531
<3>[   38.718545]     KASAN failure expected in \"memset(ptr + size -
7, 0, 8)\", but none occurred
<6>[   38.721274]     not ok 20 kmalloc_oob_memset_8
<3>[   38.726201]     # kmalloc_oob_memset_16: EXPECTATION FAILED at
mm/kasan/kasan_test.c:544
<3>[   38.726201]     KASAN failure expected in \"memset(ptr + size -
15, 0, 16)\", but none occurred
<6>[   38.728269]     not ok 21 kmalloc_oob_memset_16
<4>[   38.735350] general protection fault, probably for non-canonical
address 0xa0de1c2100000008: 0000 [#1] PREEMPT SMP KASAN PTI
<4>[   38.737084] CPU: 0 PID: 131 Comm: kunit_try_catch Tainted: G
B            N 6.2.0-rc8-next-20230216 #1
<4>[   38.738232] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
BIOS 1.14.0-2 04/01/2014
<4>[   38.739202] RIP: 0010:__stack_depot_save+0x16b/0x4a0
<4>[   38.740158] Code: 29 c8 89 c3 48 8b 05 bc ef 4a 03 89 de 23 35
ac ef 4a 03 4c 8d 04 f0 4d 8b 20 4d 85 e4 75 0b eb 77 4d 8b 24 24 4d
85 e4 74 6e <41> 39 5c 24 08 75 f0 41 3b 54 24 0c 75 e9 31 c0 49 8b 7c
c4 18 49
<4>[   38.742135] RSP: 0000:ffff88815b409a00 EFLAGS: 00000286
<4>[   38.743055] RAX: ffff88815a600000 RBX: 00000000a0de1c21 RCX:
000000000000000e
<4>[   38.744084] RDX: 000000000000000e RSI: 00000000000e1c21 RDI:
00000000282127a7
<4>[   38.745061] RBP: ffff88815b409a58 R08: ffff88815ad0e108 R09:
0000000005d4305e
<4>[   38.746039] R10: ffffed1020693eb9 R11: ffff88815b409ff8 R12:
a0de1c2100000000
<4>[   38.747012] R13: 0000000000000001 R14: 0000000000000800 R15:
ffff88815b409a68
<4>[   38.748039] FS:  0000000000000000(0000)
GS:ffff88815b400000(0000) knlGS:0000000000000000
<4>[   38.749066] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<4>[   38.749848] CR2: a0de1c2100000008 CR3: 000000012c2ae000 CR4:
00000000000006f0
<4>[   38.750769] DR0: ffffffff97419b80 DR1: ffffffff97419b81 DR2:
ffffffff97419b82
<4>[   38.751712] DR3: ffffffff97419b83 DR6: 00000000ffff0ff0 DR7:
0000000000000600
<4>[   38.752692] Call Trace:
<4>[   38.753288]  <IRQ>
<4>[   38.753795]  kasan_save_stack+0x4c/0x60
<4>[   38.754479]  ? kasan_save_stack+0x3c/0x60
<4>[   38.755112]  ? kasan_set_track+0x29/0x40
<4>[   38.756690]  ? kasan_save_free_info+0x32/0x50
<4>[   38.757186]  ? ____kasan_slab_free+0x175/0x1d0
<4>[   38.757830]  ? __kasan_slab_free+0x16/0x20
<4>[   38.758525]  ? __kmem_cache_free+0x18c/0x300
<4>[   38.759187]  ? kfree+0x7c/0x120
<4>[   38.759756]  ? free_kthread_struct+0x78/0xa0
<4>[   38.760516]  ? free_task+0x96/0xa0
<4>[   38.761127]  ? __put_task_struct+0x1a2/0x1f0
<4>[   38.761843]  ? delayed_put_task_struct+0xec/0x110
<4>[   38.762595]  ? rcu_core+0x4e3/0x1010
<4>[   38.763180]  ? rcu_core_si+0x12/0x20
<4>[   38.763842]  ? __do_softirq+0x18f/0x502
<4>[   38.764464]  ? __irq_exit_rcu+0xa1/0xe0
<4>[   38.764982]  ? irq_exit_rcu+0x12/0x20
<4>[   38.765760]  ? sysvec_apic_timer_interrupt+0x7d/0xa0
<4>[   38.766544]  ? asm_sysvec_apic_timer_interrupt+0x1f/0x30
<4>[   38.767391]  ? memmove+0x3c/0x1c0
<4>[   38.767994]  ? kunit_try_run_case+0x8e/0x130
<4>[   38.768718]  ? kunit_generic_run_threadfn_adapter+0x33/0x50
<4>[   38.769477]  ? kthread+0x17f/0x1b0
<4>[   38.769871]  ? ret_from_fork+0x2c/0x50
<4>[   38.770841]  ? kfree+0x7c/0x120
<4>[   38.771470]  kasan_set_track+0x29/0x40
<4>[   38.772101]  kasan_save_free_info+0x32/0x50
<4>[   38.772855]  ____kasan_slab_free+0x175/0x1d0
<4>[   38.773536]  ? free_kthread_struct+0x78/0xa0
<4>[   38.774175]  __kasan_slab_free+0x16/0x20
<4>[   38.774865]  __kmem_cache_free+0x18c/0x300
<4>[   38.775553]  kfree+0x7c/0x120
<4>[   38.776137]  free_kthread_struct+0x78/0xa0
<4>[   38.776840]  free_task+0x96/0xa0
<4>[   38.777220]  __put_task_struct+0x1a2/0x1f0
<4>[   38.778103]  delayed_put_task_struct+0xec/0x110
<4>[   38.778786]  rcu_core+0x4e3/0x1010
<4>[   38.779450]  ? __pfx_rcu_core+0x10/0x10
<4>[   38.780147]  ? __pfx_read_tsc+0x10/0x10
<4>[   38.780750]  ? __do_softirq+0x11f/0x502
<4>[   38.781480]  rcu_core_si+0x12/0x20
<4>[   38.782073]  __do_softirq+0x18f/0x502
<4>[   38.782755]  ? __pfx___do_softirq+0x10/0x10
<4>[   38.783442]  ? trace_preempt_on+0x20/0xa0
<4>[   38.784070]  ? __irq_exit_rcu+0x17/0xe0
<4>[   38.784767]  __irq_exit_rcu+0xa1/0xe0
<4>[   38.785377]  irq_exit_rcu+0x12/0x20
<4>[   38.786028]  sysvec_apic_timer_interrupt+0x7d/0xa0
<4>[   38.786781]  </IRQ>
<4>[   38.787107]  <TASK>
<4>[   38.787639]  asm_sysvec_apic_timer_interrupt+0x1f/0x30
<4>[   38.788698] RIP: 0010:memmove+0x3c/0x1c0
<4>[   38.789436] Code: 49 39 f8 0f 8f b5 00 00 00 48 83 fa 20 0f 82
01 01 00 00 0f 1f 44 00 00 48 81 fa a8 02 00 00 72 05 40 38 fe 74 48
48 83 ea 20 <48> 83 ea 20 4c 8b 1e 4c 8b 56 08 4c 8b 4e 10 4c 8b 46 18
48 8d 76
<4>[   38.791297] RSP: 0000:ffff888103507e08 EFLAGS: 00000286
<4>[   38.792130] RAX: ffff8881033e9000 RBX: ffff8881033e9000 RCX:
0000000000000000
<4>[   38.792969] RDX: fffffffffff8727e RSI: ffff888103461d64 RDI:
ffff888103461d60
<4>[   38.793818] RBP: ffff888103507eb8 R08: 0000000100000000 R09:
0000000000000000
<4>[   38.794643] R10: 0000000000000000 R11: 0000000000000000 R12:
1ffff110206a0fc2
<4>[   38.795458] R13: ffff888100327b60 R14: ffff888103507e90 R15:
fffffffffffffffe
<4>[   38.796558]  ? kmalloc_memmove_negative_size+0xeb/0x1f0
<4>[   38.797376]  ? __pfx_kmalloc_memmove_negative_size+0x10/0x10
<4>[   38.798257]  ? __kasan_check_write+0x18/0x20
<4>[   38.798923]  ? _raw_spin_lock_irqsave+0xa2/0x110
<4>[   38.799617]  ? _raw_spin_unlock_irqrestore+0x2c/0x60
<4>[   38.800491]  ? trace_preempt_on+0x20/0xa0
<4>[   38.801150]  ? __kthread_parkme+0x4f/0xd0
<4>[   38.801778]  kunit_try_run_case+0x8e/0x130
<4>[   38.802505]  ? __pfx_kunit_try_run_case+0x10/0x10
<4>[   38.803197]  ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10
<4>[   38.803997]  kunit_generic_run_threadfn_adapter+0x33/0x50
<4>[   38.804749]  kthread+0x17f/0x1b0
<4>[   38.805377]  ? __pfx_kthread+0x10/0x10
<4>[   38.806025]  ret_from_fork+0x2c/0x50
<4>[   38.806716]  </TASK>
<4>[   38.807261] Modules linked in:
<4>[   38.809163] ---[ end trace 0000000000000000 ]---
<4>[   38.809731] RIP: 0010:__stack_depot_save+0x16b/0x4a0
<4>[   38.810988] Code: 29 c8 89 c3 48 8b 05 bc ef 4a 03 89 de 23 35
ac ef 4a 03 4c 8d 04 f0 4d 8b 20 4d 85 e4 75 0b eb 77 4d 8b 24 24 4d
85 e4 74 6e <41> 39 5c 24 08 75 f0 41 3b 54 24 0c 75 e9 31 c0 49 8b 7c
c4 18 49
<4>[   38.812911] RSP: 0000:ffff88815b409a00 EFLAGS: 00000286
<4>[   38.813435] RAX: ffff88815a600000 RBX: 00000000a0de1c21 RCX:
000000000000000e
<4>[   38.815407] RDX: 000000000000000e RSI: 00000000000e1c21 RDI:
00000000282127a7
<4>[   38.816630] RBP: ffff88815b409a58 R08: ffff88815ad0e108 R09:
0000000005d4305e
<4>[   38.817540] R10: ffffed1020693eb9 R11: ffff88815b409ff8 R12:
a0de1c2100000000
<4>[   38.818685] R13: 0000000000000001 R14: 0000000000000800 R15:
ffff88815b409a68
<4>[   38.819949] FS:  0000000000000000(0000)
GS:ffff88815b400000(0000) knlGS:0000000000000000
<4>[   38.821375] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
<4>[   38.822431] CR2: a0de1c2100000008 CR3: 000000012c2ae000 CR4:
00000000000006f0
<4>[   38.823562] DR0: ffffffff97419b80 DR1: ffffffff97419b81 DR2:
ffffffff97419b82
<4>[   38.824702] DR3: ffffffff97419b83 DR6: 00000000ffff0ff0 DR7:
0000000000000600
<0>[   38.826157] Kernel panic - not syncing: Fatal exception in interrupt
<0>[   38.828641] Kernel Offset: 0x12400000 from 0xffffffff81000000
(relocation range: 0xffffffff80000000-0xffffffffbfffffff)
<0>[   38.830146] ---[ end Kernel panic - not syncing: Fatal exception
in interrupt ]---


links:
----
https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230216/testrun/14817835/suite/log-parser-test/test/check-kernel-panic/log
https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230216/testrun/14817835/suite/log-parser-test/tests/
https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230216/testrun/14817835/suite/log-parser-test/test/check-kernel-panic/details/


steps to reproduce:
---
tuxrun  \
 --runtime podman  \
 --device qemu-x86_64  \
 --kernel https://storage.tuxsuite.com/public/linaro/lkft/builds/2Lo0yXyxgpsuMQhyLdw5jKk9nSj/bzImage
 \
 --modules https://storage.tuxsuite.com/public/linaro/lkft/builds/2Lo0yXyxgpsuMQhyLdw5jKk9nSj/modules.tar.xz
 \
 --rootfs https://storage.tuxsuite.com/public/linaro/lkft/oebuilds/2LUxobLpTjiRrzSKqqYOwhong7e/images/intel-corei7-64/lkft-tux-image-intel-corei7-64-20230209111930.rootfs.ext4.gz
 \
 --parameters SKIPFILE=skipfile-lkft.yaml  \
 --image docker.io/lavasoftware/lava-dispatcher:2023.01.0020.gc1598238f  \
 --tests kunit  \
 --timeouts boot=15 kunit=30

--
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvZqytp3gMnC4-no9EB%3DJnzqmu44i8JQo6apiZat-xxPg%40mail.gmail.com.
