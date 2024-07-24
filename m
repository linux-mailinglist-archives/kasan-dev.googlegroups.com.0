Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBDW2QS2QMGQEDAOWUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D014093B522
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 18:34:23 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-52efd4afebesf4754065e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 09:34:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721838863; cv=pass;
        d=google.com; s=arc-20160816;
        b=d09j39K5BTu8R+rilJ4JTOCvbIJMhJbC2Z2BOxRu2a5ptmEq6md/UVYTHmDCdIhZdM
         ixz7cZvIdSuENL+otpFpRD0P0zqgIEfAYov6GU4XTkW8kb0hM8FO6H83yTyiXZ5k9TIq
         oB2ql8hVfw4lgdmeYnhRME+RsKEnv+ptqdSmsDh1r8wJHSODFdIL+SDNZKR81B7ZhIFc
         V/SSpOPV8IWT/hGMoGSVP/CenuiieTFcqlBMnpfNb9DZRsM+xWFrxpOnvase/lip40Ne
         dORP4OUntTYr6r57zzXw/V/dJ/4vMqsIZGcD09xE1P+mig0k0yyGFFeBXZe/UU+RzEpf
         FMHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=E22rrBmQ0+BojMDOPo4i4BSAP4l+szGH/54XyX/oafI=;
        fh=zgj1rIeeOy6XyOocfOpUG2jL83xCu5ne/GtwDSbFTg0=;
        b=UEH0A9v8mIChKd+xSNJBdgV/Gb+Efq/em8XS+es5f90D4jWoHkpAEi5wDXeJu+nWJu
         JX0pWkYAMEaTUxvNxtb+y2UeEAtMGY2CDXLHiOJvYlG1hsu8gq7U0hds2vD+zISJ5nsu
         eOqC4hs/LczRIs5PQYEg0ykb8eIu7ryut9EICAkJ4QqShpTbHw5UwgagD74CgOFcFJP8
         IifHvLQc7o0woFtcHKoxa5KzUAiQguGWw5z0QIqDjHFctzXkWzn7nyffuSXuC3ieCHwm
         iiicH3PGhcUKOSXSy1lxuTZfva1CJ+WIDa+/+W/s/R1JWA45S/r3F+bZk2vnM5jgl2s0
         XQ3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=taoVU30V;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721838863; x=1722443663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E22rrBmQ0+BojMDOPo4i4BSAP4l+szGH/54XyX/oafI=;
        b=CxhFpRb6i2V24Nt2JOk0/0Nwc38hmFI5t8UDh5tMWSYRx2UTLIiPg/wkKyDk4oOKjU
         Q3CL4QugW+dWVyTNqOyhJ/vSu1ERK9qjCj2iJaeHIsuoDTI+QMIYituMyLcSQ9gbaGfx
         karxwIUI0HaOPMqFhR3fqS4HEufG6bV5G0101R41bxhEsPguS3U7QU9uL4xvg7+CEnlm
         l4x2kR7ObacE2aVdyxeWrHbWUERS4aktgh4zQp6OhjjXSZerbzS5cYjrAHvXaQOYlivm
         dHFefR0+gIDZZ/1Ui5R5teNH2qdiXZc40c5vLsC7S5/3ZgP1msgO1o+AIn48b/yQNTRh
         uzhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721838863; x=1722443663;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=E22rrBmQ0+BojMDOPo4i4BSAP4l+szGH/54XyX/oafI=;
        b=pT3FH6W0qkgiuDeR8I/qZZfci0WasPQuX0StepQZHzSB7iX2Tqnb01VnCzE+jx4l4X
         LkIv82/IDvuv/zIvLLbDV9v7xiuDzrq99Cc52A8U4nQT5Mq7fWNhMddhssB5Q179umFd
         SgYuYf+Seg0nHHPN4SP5YjjqOjuphly5crDd8V1sT2mtQ94lUN2Q9D6ufuFIWUwcLvqU
         /Fc7gJg8R84UbAFIZevHtv7wnifzm/UZrdnzuGPFMm5MyVOo/9LMGLdQYhoyMNxnjLRF
         zaQyYhFAStezPKoW0M45EJG8c2aBJK0R3vElGx0FclmWGi2o7b6p1BD+mguzvGD1v8EC
         3SjA==
X-Forwarded-Encrypted: i=2; AJvYcCXQZRCRz0fKTiiRT4qlT9HEKGZjY7WEi4CG/vV3cTS4Ytv5/uCuR3reMohvnj6Xtpy15cThu/dZAWGAwupr0VWGD9WcoyYR+Q==
X-Gm-Message-State: AOJu0Yz5UmnFkItLKUU1U/OzBGEMJY6OdelIzj1XKKEGCPB+TSDPWKT2
	IPgNmxrwsyFszr6CvKxJeSts1pxA8J84QwbjqASXarpdFehDgrV/
X-Google-Smtp-Source: AGHT+IE5VExkXPI1D/g4E3DI5bQ/r70IBrJqJgHwMkFiMEWfCvxnhuAvhCmDoKTRKhxVyoRVokYQig==
X-Received: by 2002:a05:6512:3d90:b0:52e:98f6:c21f with SMTP id 2adb3069b0e04-52fd3f02b0cmr242444e87.16.1721838862260;
        Wed, 24 Jul 2024 09:34:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a5:b0:52e:6e57:6ad5 with SMTP id
 2adb3069b0e04-52fd423de28ls27407e87.2.-pod-prod-04-eu; Wed, 24 Jul 2024
 09:34:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpaem2XF5YHTsbuMWg19z3IA59Lr7KW5bQV/bl4wQsWMK+DyE0PIYmwF/Cuc+0ok6n/jU22M8yzT6hXEFMPJz0cGovBPfVv49XvA==
X-Received: by 2002:a05:6512:3d90:b0:52e:98f6:c21f with SMTP id 2adb3069b0e04-52fd3f02b0cmr242383e87.16.1721838860204;
        Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721838860; cv=none;
        d=google.com; s=arc-20160816;
        b=OKI8GBQUhTbFtSyN5sb3l5QQjN81oH69/BOyLY1hK52oPqCJiA8M71cgyEmGCpxalr
         Sf2zkW1TA+jVYWdH2JxaL+kT0wQlTo8ApbW7O5/S3ePohS7yos6c5Cn8lW80aEGUp1zn
         Ihqhr4TAI3a7Lf6BstXJX6QvGZF7NgLAxgkClCnBPxQ58JDcsVwFf1DR9TJAen7W1z5z
         ZXEzDnpuya4xbY6/bDyaZYffjE+RgnyWgrXf7xCBeWgvDxl3s1WIYSZ5ybJPA6ogj1fR
         DaJFcTv1lMYUpx6+WbJ865vqA4n0bQ2YFy/5GARcbsjIwIahLkAKOffQ/btmOWnvFbUz
         5Y9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=BIn9I8OgB+Zl6a/4DmM7/3n8midQ/Rf950bAiHb/5Tg=;
        fh=l+uIinWewJLGFO8VtQwZ3Ji291WpGSlzqA6q9ddCYHM=;
        b=nOmrvGrtTyiXvdbkcZhNcvrUoK9Tv39u+LP/W4L/u+iGunT3gOXxBKWJleV2PkqpD9
         HSkkdoMugRM1yrgiMEfS13AHYlB9wnWWyK4NW4IJ/i7ZFFMWnYKGmd7CXUsziyMiwAnX
         tzGCExua8DXLRzGpuv/vBfSdzVb0PTKDG1VB2w/tRRom9GVHCL62Cu4nNUpgn8Xo92G5
         +UYLd30IDgiN4C04tzwyAXppqMfw079QmJ9t5b3uJGrtSoBFOzmLSYMSlwFMgGAf1uwC
         cSQevJpdiEAYDe1zp+1OHT6EZDhNcclD3v//bwhzcB//nmHrLyRWdL4T/Bjxi0xEmGjN
         t02Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=taoVU30V;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52f003c15adsi181738e87.5.2024.07.24.09.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4266edcc54cso405e9.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2024 09:34:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqL344mcbQ7+CzacdtFq4maAueCgOvl9NA7fPJFRbWw4FGxTA7kuEedp/kX5NMtpflperio26MzB5cuUIkHFsKVrwUFJbfvDqb7A==
X-Received: by 2002:a05:600c:3b8e:b0:426:6413:b681 with SMTP id 5b1f17b1804b1-427f7c550a3mr1839245e9.6.1721838858696;
        Wed, 24 Jul 2024 09:34:18 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:7aec:12da:2527:71ba])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-427fc95707esm11705295e9.0.2024.07.24.09.34.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jul 2024 09:34:18 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v2 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Date: Wed, 24 Jul 2024 18:34:11 +0200
Message-Id: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAAMtoWYC/6tWKk4tykwtVrJSqFYqSi3LLM7MzwNyjHQUlJIzE
 vPSU3UzU4B8JSMDIxMDcyNj3ezE4sQ83ZLipKLkUt0kc0PTREsDwzRzczMloJaCotS0zAqwcdG
 xtbUAu8f5PF4AAAA=
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=taoVU30V;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Hi!

This is v2 of a series that I started, uuuh, almost a year ago.
(Sorry...)
v1 was at:
https://lore.kernel.org/lkml/20230825211426.3798691-1-jannh@google.com/

The purpose of the series is to allow KASAN to detect use-after-free
access in SLAB_TYPESAFE_BY_RCU slab caches, by essentially making them
behave as if the cache was not SLAB_TYPESAFE_BY_RCU but instead every
kfree() in the cache was a kfree_rcu().
This is gated behind a config flag that is supposed to only be enabled
in fuzzing/testing builds where the performance impact doesn't matter.

Patch 1/2 is new; it's some necessary prep work for the main patch to
work, though the KASAN integration maybe is a bit ugly.
Patch 2/2 is a rebased version of the old patch, with some changes to
how the config is wired up, with poison/unpoison logic added as
suggested by dvyukov@ back then, with cache destruction fixed using
rcu_barrier() as pointed out by dvyukov@ and the test robot, and a test
added as suggested by elver@.

Output of the new kunit testcase I added to the KASAN test suite:
==================================================================
BUG: KASAN: slab-use-after-free in kmem_cache_rcu_uaf+0x3ae/0x4d0
Read of size 1 at addr ffff88810d3c8000 by task kunit_try_catch/225

CPU: 7 PID: 225 Comm: kunit_try_catch Tainted: G    B            N 6.10.0-00003-gf0fc688e25ed #422
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
Call Trace:
 <TASK>
 dump_stack_lvl+0x53/0x70
 print_report+0xce/0x670
[...]
 kasan_report+0xa5/0xe0
[...]
 kmem_cache_rcu_uaf+0x3ae/0x4d0
[...]
 kunit_try_run_case+0x1b3/0x490
[...]
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
[...]
 ret_from_fork+0x34/0x70
[...]
 ret_from_fork_asm+0x1a/0x30
 </TASK>

Allocated by task 225:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 __kasan_slab_alloc+0x6e/0x70
 kmem_cache_alloc_noprof+0xef/0x2b0
 kmem_cache_rcu_uaf+0x10d/0x4d0
 kunit_try_run_case+0x1b3/0x490
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
 ret_from_fork+0x34/0x70
 ret_from_fork_asm+0x1a/0x30

Freed by task 0:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 kasan_save_free_info+0x3b/0x60
 __kasan_slab_free+0x47/0x70
 slab_free_after_rcu_debug+0xee/0x240
 rcu_core+0x676/0x15b0
 handle_softirqs+0x22f/0x690
 irq_exit_rcu+0x84/0xb0
 sysvec_apic_timer_interrupt+0x6a/0x80
 asm_sysvec_apic_timer_interrupt+0x1a/0x20

Last potentially related work creation:
 kasan_save_stack+0x33/0x60
 __kasan_record_aux_stack+0x8e/0xa0
 __call_rcu_common.constprop.0+0x70/0xa70
 kmem_cache_rcu_uaf+0x16e/0x4d0
 kunit_try_run_case+0x1b3/0x490
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
 ret_from_fork+0x34/0x70
 ret_from_fork_asm+0x1a/0x30

The buggy address belongs to the object at ffff88810d3c8000
 which belongs to the cache test_cache of size 200
The buggy address is located 0 bytes inside of
 freed 200-byte region [ffff88810d3c8000, ffff88810d3c80c8)

The buggy address belongs to the physical page:
page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x10d3c8
head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
flags: 0x200000000000040(head|node=0|zone=2)
page_type: 0xffffefff(slab)
raw: 0200000000000040 ffff88810d3c2000 dead000000000122 0000000000000000
raw: 0000000000000000 00000000801f001f 00000001ffffefff 0000000000000000
head: 0200000000000040 ffff88810d3c2000 dead000000000122 0000000000000000
head: 0000000000000000 00000000801f001f 00000001ffffefff 0000000000000000
head: 0200000000000001 ffffea000434f201 ffffffffffffffff 0000000000000000
head: 0000000000000002 0000000000000000 00000000ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff88810d3c7f00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff88810d3c7f80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>ffff88810d3c8000: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                   ^
 ffff88810d3c8080: fb fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc
 ffff88810d3c8100: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
==================================================================
    ok 38 kmem_cache_rcu_uaf

Signed-off-by: Jann Horn <jannh@google.com>
---
Jann Horn (2):
      kasan: catch invalid free before SLUB reinitializes the object
      slub: Introduce CONFIG_SLUB_RCU_DEBUG

 include/linux/kasan.h | 20 +++++++++++++
 mm/Kconfig.debug      | 25 ++++++++++++++++
 mm/kasan/common.c     | 63 +++++++++++++++++++++++++++++++--------
 mm/kasan/kasan_test.c | 44 +++++++++++++++++++++++++++
 mm/slab.h             |  3 ++
 mm/slab_common.c      | 12 ++++++++
 mm/slub.c             | 82 ++++++++++++++++++++++++++++++++++++++++++++++-----
 7 files changed, 229 insertions(+), 20 deletions(-)
---
base-commit: 0c3836482481200ead7b416ca80c68a29cfdaabd
change-id: 20240723-kasan-tsbrcu-b715a901f776
-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240724-kasan-tsbrcu-v2-0-45f898064468%40google.com.
