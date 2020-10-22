Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXMNY36AKGQELEPOZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 947B0295FA5
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:26 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id v25sf702012ljh.4
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372766; cv=pass;
        d=google.com; s=arc-20160816;
        b=G8RoXAXVk21s/7w+YekoQDj//V9czchOi/qNrexSEo//uejGbES/wR4pDv8zxhuqc/
         QIfHsJ4f8ZzfIEsczUaUP8kaXjW1WeIOm52if5Wj104UDdn7FfL3qhaQOBt6yDcbvfy0
         skHL/cOZX6ljqZcBrmjNRRnexwsDIiyCnvfBECxQ2V5l7SqIjw74/Gz30Mg6LBxvBYgZ
         akxXdVoZksX8jQ6w1vmka1HFB4qS38DFAdEpcbUI69zFR1UtVpyW9t/m8eLXIl82qjS7
         hqnTaXZXuzuPQHKhi3eT2qQIJ6vMIZxQTeOMFjANH36aetfcfoAFUAb/HubhDPSAqrrb
         Xbcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=6wYVzcecidxjvZj7aufU3L2PZjP3yL9aLYlGCA5c9w0=;
        b=J0AhLZ0XajyeBcSJQfRvHRlcgHlvRloZ49vvC0HTZApfwNQmNSMSJccv3GqhKWNzwU
         6NRN1BoafV4IxuNq77kHVpxtTeu5hce6m36CC5bCiKOWkdOveSu1p7kff7RepBj/Qkua
         0Pp2zD4Rz9keOowOVdLgUthXlTX8cbYX+i02eVbIRkdKr8vxeVfmxgmZntw46WtoiE7m
         yDsMV74mbxWnqknhk7YYzQ9s8cxdWSqJOP/2mKPCcZzzZ2J3ONMVo4rw5Yz3caPA81tX
         ja524bqV7aCVedeJsf7g7eY59R+haKy4PZ70Y24SI0Dv2kV26I1HRDztIoI9rPvHt20c
         BjUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=no5WMYSS;
       spf=pass (google.com: domain of 33iarxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33IaRXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6wYVzcecidxjvZj7aufU3L2PZjP3yL9aLYlGCA5c9w0=;
        b=FyZw91vnmtt4lEFcfLJqhhTx3XLNqmpVyA3Il6yviq0iJV/KxoI30Z/CLHCWmE+OWe
         N2e/pj9Z7FJ9gT7Hw3Q9oA3F6TqNtViXLaFmGyEiNs5HEQBaJzkV+vD0YTx9UJgOtKri
         ADRyGHregsn7RfShfZsGVHJrRvAAJ12+7P5xA7zaYJi0l7ZotsH1DpZrwrP5si+iCXY0
         dflHzrmbmhRruGqjQcteJdJ87fEGLCqXUSW8LubLLmpMh9wyfhGVvUldK3qch4OLxHYE
         tWcHxdwEhrTNJtIMaguo4KuHcQBeRtcGnXtuYXzQsLkPV79B+tHh6O8Uw31L6brIqxuf
         Ag7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6wYVzcecidxjvZj7aufU3L2PZjP3yL9aLYlGCA5c9w0=;
        b=fvQG5xGEkYcUhHaX9PzRKm+tfxiDYamL7tdHTSb+F/rgfXDwHKnUvPKf+XmHj2k+Ny
         RcBfUKXHtvEJkr2TErYnh+vNN3byIxqvxnVbthI8wOOqh8BU7AcCQGA7s8OPMScU755Y
         w8EK0dmrQ9HATOjtstD+IlAlMuhSMwo/RUbTznhs4f7T91x8zz0whNZppvdwqTtpdXIs
         hIdyFYqpN3yiuLlhNSX9t88TlgY/nAnvl/azPypq0MddCwodXwcE7cIPuCrxpSi4gYF0
         VTS1ImyAz3IyhcLj1N9VwmPDnfcup5vrzzwPJND4t20yVcRj05x6THCClBl/ZZ734qoM
         8IRA==
X-Gm-Message-State: AOAM532giJCzsTgPNHee7rsXsDDCr6sSzP/RdJoL49eILymN695whUtQ
	OtvsJF0BgHcRrHHYgwDDjOs=
X-Google-Smtp-Source: ABdhPJye8Mxa1jBSjfVvk2Ug0vaN87U1sOIqCXzQaoum1j2xYiS8e2C3hkc3DzRP3C90l9v7yo0iSw==
X-Received: by 2002:ac2:43b0:: with SMTP id t16mr925690lfl.95.1603372766095;
        Thu, 22 Oct 2020 06:19:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc1:: with SMTP id w1ls337618ljj.4.gmail; Thu, 22 Oct
 2020 06:19:25 -0700 (PDT)
X-Received: by 2002:a2e:a549:: with SMTP id e9mr916856ljn.315.1603372765019;
        Thu, 22 Oct 2020 06:19:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372765; cv=none;
        d=google.com; s=arc-20160816;
        b=sS1bWKpHLsw5nbsF1eyUjYaM7Ak3KAmH/XjD8V/8dFUFtSw6Hj/JFcDtAxIcgoRSsQ
         47+QHw1ukxsc9e+FbrvFobVSbA/x9PD9le8q9/q5KRX1bLy+N9yM+GTaLU1Mf74GDauw
         kKc4At+woHdwB+Ep/Hr6P1h1+KkJcuePjSe7dwbLe7eyOxGljoVkBems+N9U7PmDWtRm
         y/dla3DEhFuFyZa64BLoATBihsuBxeg27acKnPAjrSRjleWfqvGEM/UOvCv+Odbw1Opj
         XM1kZCPHR8EuijD32AkdPfxKTEHHwDG1p/Fa3V6ciGDeMgNz6FEE4v9vqJLlXjqWxJug
         xzVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=gP40pqOrjsRuGDtDL77O5g/LDtgANLIwrEsf6Di4U2Q=;
        b=rHke9vyUqeNbS7sLlQPbBw8qMGkdSsSZswnbigS/Zhyh3C/3Uryvt+Ay9AqZHJdPFD
         rwm8zr90TP2hbWhs1IOpW7AQP9IkI0v6zw7v11m1qalyCBlUcEAccNKgpU/MpS1ULzIt
         gO411E+ZzXUuBIlltKA7knGE6GO/ezt99kVGSIaH3/CWPIxdBW4kHKKgyThkYD2Oytw6
         5tWJFISGdKB20mN96X1oLZERRbApGAZgpjoKAGxldGU/6xY71eH1Ai/cP1Z33RtdbtL3
         ITFxvWxqR4GsqbYiOPneUZ09Ktr+yG4s3NbQ6Pg3lAp1hWPDQkIq2KYZG2P8amN7RbQZ
         tJ3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=no5WMYSS;
       spf=pass (google.com: domain of 33iarxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33IaRXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id o4si73170lfn.12.2020.10.22.06.19.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33iarxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id u6so659925eju.4
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:24 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:aa7:d7d9:: with SMTP id
 e25mr2166504eds.253.1603372764236; Thu, 22 Oct 2020 06:19:24 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:52 +0200
Message-Id: <cover.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 00/21] kasan: hardware tag-based mode for production
 use on arm64
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=no5WMYSS;       spf=pass
 (google.com: domain of 33iarxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=33IaRXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patchset is not complete (hence sending as RFC), but I would like to
start the discussion now and hear people's opinions regarding the
questions mentioned below.

=== Overview

This patchset adopts the existing hardware tag-based KASAN mode [1] for
use in production as a memory corruption mitigation. Hardware tag-based
KASAN relies on arm64 Memory Tagging Extension (MTE) [2] to perform memory
and pointer tagging. Please see [3] and [4] for detailed analysis of how
MTE helps to fight memory safety problems.

The current plan is reuse CONFIG_KASAN_HW_TAGS for production, but add a
boot time switch, that allows to choose between a debugging mode, that
includes all KASAN features as they are, and a production mode, that only
includes the essentials like tag checking.

It is essential that switching between these modes doesn't require
rebuilding the kernel with different configs, as this is required by the
Android GKI initiative [5].

The patch titled "kasan: add and integrate kasan boot parameters" of this
series adds a few new boot parameters:

kasan.mode allows choosing one of main three modes:

- kasan.mode=off - no checks at all
- kasan.mode=prod - only essential production features
- kasan.mode=full - all features

Those mode configs provide default values for three more internal configs
listed below. However it's also possible to override the default values
by providing:

- kasan.stack=off/on - enable stacks collection
                       (default: on for mode=full, otherwise off)
- kasan.trap=async/sync - use async or sync MTE mode
                          (default: sync for mode=full, otherwise async)
- kasan.fault=report/panic - only report MTE fault or also panic
                             (default: report)

=== Benchmarks

For now I've only performed a few simple benchmarks such as measuring
kernel boot time and slab memory usage after boot. The benchmarks were
performed in QEMU and the results below exclude the slowdown caused by
QEMU memory tagging emulation (as it's different from the slowdown that
will be introduced by hardware and therefore irrelevant).

KASAN_HW_TAGS=y + kasan.mode=off introduces no performance or memory
impact compared to KASAN_HW_TAGS=n.

kasan.mode=prod (without executing the tagging instructions) introduces
7% of both performace and memory impact compared to kasan.mode=off.
Note, that 4% of performance and all 7% of memory impact are caused by the
fact that enabling KASAN essentially results in CONFIG_SLAB_MERGE_DEFAULT
being disabled.

Recommended Android config has CONFIG_SLAB_MERGE_DEFAULT disabled (I assume
for security reasons), but Pixel 4 has it enabled. It's arguable, whether
"disabling" CONFIG_SLAB_MERGE_DEFAULT introduces any security benefit on
top of MTE. Without MTE it makes exploiting some heap corruption harder.
With MTE it will only make it harder provided that the attacker is able to
predict allocation tags.

kasan.mode=full has 40% performance and 30% memory impact over
kasan.mode=prod. Both come from alloc/free stack collection.

=== Questions

Any concerns about the boot parameters?

Should we try to deal with CONFIG_SLAB_MERGE_DEFAULT-like behavor mentioned
above?

=== Notes

This patchset is available here:

https://github.com/xairy/linux/tree/up-prod-mte-rfc2

and on Gerrit here:

https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3707

This patchset is based on v5 of "kasan: add hardware tag-based mode for
arm64" patchset [1] (along with some fixes).

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://lore.kernel.org/linux-arm-kernel/cover.1602535397.git.andreyknvl@google.com/
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] https://arxiv.org/pdf/1802.09517.pdf
[4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
[5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
[6] https://github.com/qemu/qemu

=== History

Changes RFCv1->RFCv2:
- Rework boot parameters.
- Drop __init from empty kasan_init_tags() definition.
- Add cpu_supports_mte() helper that can be used during early boot and use
  it in kasan_init_tags()
- Lots of new KASAN optimization commits.

Andrey Konovalov (21):
  kasan: simplify quarantine_put call site
  kasan: rename get_alloc/free_info
  kasan: introduce set_alloc_info
  kasan: unpoison stack only with CONFIG_KASAN_STACK
  kasan: allow VMAP_STACK for HW_TAGS mode
  kasan: mark kasan_init_tags as __init
  kasan, arm64: move initialization message
  kasan: remove __kasan_unpoison_stack
  kasan: inline kasan_reset_tag for tag-based modes
  kasan: inline random_tag for HW_TAGS
  kasan: inline kasan_poison_memory and check_invalid_free
  kasan: inline and rename kasan_unpoison_memory
  arm64: kasan: Add cpu_supports_tags helper
  kasan: add and integrate kasan boot parameters
  kasan: check kasan_enabled in annotations
  kasan: optimize poisoning in kmalloc and krealloc
  kasan: simplify kasan_poison_kfree
  kasan: rename kasan_poison_kfree
  kasan: don't round_up too much
  kasan: simplify assign_tag and set_tag calls
  kasan: clarify comment in __kasan_kfree_large

 arch/Kconfig                       |   2 +-
 arch/arm64/include/asm/memory.h    |   1 +
 arch/arm64/include/asm/mte-kasan.h |   6 +
 arch/arm64/kernel/mte.c            |  20 +++
 arch/arm64/kernel/sleep.S          |   2 +-
 arch/arm64/mm/kasan_init.c         |   3 +
 arch/x86/kernel/acpi/wakeup_64.S   |   2 +-
 include/linux/kasan.h              | 225 ++++++++++++++++++-------
 include/linux/mm.h                 |  27 ++-
 kernel/fork.c                      |   2 +-
 mm/kasan/common.c                  | 256 ++++++++++++++++-------------
 mm/kasan/generic.c                 |  19 ++-
 mm/kasan/hw_tags.c                 | 182 +++++++++++++++++---
 mm/kasan/kasan.h                   | 102 ++++++++----
 mm/kasan/quarantine.c              |   5 +-
 mm/kasan/report.c                  |  26 ++-
 mm/kasan/report_sw_tags.c          |   2 +-
 mm/kasan/shadow.c                  |   1 +
 mm/kasan/sw_tags.c                 |  20 ++-
 mm/mempool.c                       |   2 +-
 mm/slab_common.c                   |   2 +-
 mm/slub.c                          |   3 +-
 22 files changed, 641 insertions(+), 269 deletions(-)

-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1603372719.git.andreyknvl%40google.com.
