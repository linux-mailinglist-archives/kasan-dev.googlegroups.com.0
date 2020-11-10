Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLNEVT6QKGQEETQBFYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0102A2AE31E
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:30 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id e6sf11655vkb.11
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046830; cv=pass;
        d=google.com; s=arc-20160816;
        b=UHhYuHTLBLq7cAoXwag++O19dg6mMDv+P2GPqEPbAE7udmw6N/5XGFDgNzQRnXAmzY
         ZzSR29dIUolWGGYN6UMWKR/MgtWXsyx0e3ImCKsyBLh2GDIqWZfghs1YMd0fcCNe33xQ
         x7b/zEvSVnc4t/igTTy5oc9ZMDkcAEYq7v5sRYJES1VI3Ss31L035BWoVFHyfI/aip0W
         N8jh41B+pAHm6jH0XT4dhMsUOQh3Xt6Kz36LmDLkt1FG8wutjCS/LFhEi7feXI6gZoBu
         CfP/Y6b0F94cCIKHVjnr0wje99OWJH/8rJmQ3RGxZIaLJ9DizOwpzge/fEqQqweCeCJt
         V/+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=JDtP4OeFPsPeJduAC2/PH4mIdkWdvid3j5hQk0ZpLG4=;
        b=CQuzjGBIX1RLxeLCmTNoe5gj8wModW+UqM9xTfdhRuYPDjFm4PhpXxvSqpi6Su0v/b
         ioqGLQ5BrMa7FfDikQGt6+xWgTkGUpnEgys4sSDDCQH3FDZo+lz13Wmi3RJyx415NXnr
         nOECosgmCqPmz5Zg5t7XJmg6R5nzDp9q0FVXs1YnJKBf5lbnPRebiNOBXnfq07PM37hM
         L1ifOON5/505bXGm30BIiVbzciAXD+ru3pWRMZy37+MvC0E/wx7xELnx2AU1eRmM7ENH
         pbABvTQ5jYQpVAarkybfqVHkRzSXcqqpDgj6LO3rFaOISMRCfpAojfO8mJq9QHGCRI5X
         r91w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TE1cjQyl;
       spf=pass (google.com: domain of 3lrkrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3LRKrXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JDtP4OeFPsPeJduAC2/PH4mIdkWdvid3j5hQk0ZpLG4=;
        b=nXPknJlOmOyy6CnSjGEWStY6ndxTTIE9N3HrZYSxMWK13z4C9Rwc7gUeaWsQdxjVv4
         s5tsp1gsJdfR9OQ8s0ps9YYlrxupXFUdLzefYfE76TbEgJIfjzuwl3Eyx3HD6bDvSdB2
         mOUFt/CfTQbQtJBBttUgoMd6MYRn0alygbLWjXQVj90yxF3SfTMnYNlcGrtEgQbG+gMr
         ztZCElnJNofpikJN2pWdTzr+ebO5P9rPBC9rtraIAr74cZD7WZekJQIbNtZ/2g9/WtiR
         tl17tWyihosYnXCJjEZcNAAE/t7FepgTh4ZZ8QXpyxsEuEWigZbHDHgDhzb2cmKYiXzv
         IKOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JDtP4OeFPsPeJduAC2/PH4mIdkWdvid3j5hQk0ZpLG4=;
        b=HunalL9njeyXJLWi/To3eAOv81skG7dbxt9wwihoBh7CUI0yu6k6nApaHUeK8vHWKZ
         G4KMhEiNiUt9DPRolL8cAqZjx8s0r1NgboT7VdRh1HvPdyOTT4PkpMpOw4iyE9Fe6mXE
         d143Z1QHUQovKoMha4sAAL+opy9C52JFFvrfw+v2T0WZ4FYvl2JtVLAZtB9s2t3IQ+V0
         VUVG+4mfuCInQTCPnlaO9VqDN7gu7sXnyk0sn8+Z/Sj/iQlD/W+vCR815uqwV/Cxqu22
         KknHzAymqkB12GFzBsaIMxjagRuSpXdOEogi/+jQ6x+/t66WmEwhWpANAIydjcP387Qr
         AiJg==
X-Gm-Message-State: AOAM533p+lk48K7ZIJzRZ+i0ru30Qc4cgcMnBxP/hXmnDbUltPNCcMuz
	fQwLzQFWK5Jo10M5PTKpLL4=
X-Google-Smtp-Source: ABdhPJztdnlBYLjZVxHr86Cedop4qIFy7i7XWpSkkjGATI9+5h6NpOoD+NMSJbY7rqcZRcqpZOeA5Q==
X-Received: by 2002:ab0:39d9:: with SMTP id g25mr11405458uaw.60.1605046830013;
        Tue, 10 Nov 2020 14:20:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:348c:: with SMTP id c12ls911252uar.9.gmail; Tue, 10 Nov
 2020 14:20:29 -0800 (PST)
X-Received: by 2002:a9f:2c92:: with SMTP id w18mr11899449uaj.58.1605046829506;
        Tue, 10 Nov 2020 14:20:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046829; cv=none;
        d=google.com; s=arc-20160816;
        b=MvBI5DW3OmDca1En9sDrEnVanbAioJCB99WExn/fhPX9EffVXUznRDBgaHNP5yoSgr
         E1S5eNOEhGLp4pwN2Ye3iawXBIWy/Z4L1CRVAvztBTyCuSxrxOAyVxMooJLs8ENURcnX
         GlRHVHUxnMv0GWmR4kvX8m/kj3WtNesWE7/kNhiYZCbtf+iLxQXhiBq410SWJygeimYH
         5TLO5N/OU0mAN+J988um88TNpymQiR+D8FbS7DYLMWDXyCLUJyE7p9NUbUkD7lLnuW/N
         kVT2u+ttj1jlf3gYcMXkWGr5WohFI21TpgBXsukcwfILqqCQu7GPYUFHDZdrLoamMd0V
         t30g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=b8CotiQpp+bxdSd+En1KItJC9YbOfc1UzHfr7o3MXho=;
        b=vsrcAC8QbbbE08MHcFarl1Phi/Uq4cMPH6VmRG6QDpYw10cnNPyPvSLy7t/eeu1Sq0
         vL9hpi4buofTAtmXEyNA12KgXOnkfUeV81FW9qrlqNNzBEvJXW5kr7lYjL1TrnyQQe20
         kzw7w/b/L787sAq+bCXzUZKnbUn4XdzAb4eSbXSjdoasIMnDkg5JwqxNDIHzkqr1+Mcp
         2Mwf/5PIIN/k0Ang1CAnPomqArOas2jo27Djxqb3SFKNXniGHgxg4KVJBHx/OxrvQAOq
         SKrYBQ/2IMWqi/kh9pZgJzi8yTvN+rpKJDcFdUnjpgsGemwlaH6QPmQcCIBXIf2ZqmJ6
         iaDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TE1cjQyl;
       spf=pass (google.com: domain of 3lrkrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3LRKrXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id m17si16392vsk.0.2020.11.10.14.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lrkrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id m76so222692qke.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:548b:: with SMTP id
 q11mr21256172qvy.44.1605046829085; Tue, 10 Nov 2020 14:20:29 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:04 +0100
Message-Id: <cover.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 00/20] kasan: boot parameters for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TE1cjQyl;       spf=pass
 (google.com: domain of 3lrkrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3LRKrXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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

=== Overview

Hardware tag-based KASAN mode [1] is intended to eventually be used in
production as a security mitigation. Therefore there's a need for finer
control over KASAN features and for an existence of a kill switch.

This patchset adds a few boot parameters for hardware tag-based KASAN that
allow to disable or otherwise control particular KASAN features, as well
as provides some initial optimizations for running KASAN in production.

There's another planned patchset what will further optimize hardware
tag-based KASAN, provide proper benchmarking and tests, and will fully
enable tag-based KASAN for production use.

Hardware tag-based KASAN relies on arm64 Memory Tagging Extension (MTE)
[2] to perform memory and pointer tagging. Please see [3] and [4] for
detailed analysis of how MTE helps to fight memory safety problems.

The features that can be controlled are:

1. Whether KASAN is enabled at all.
2. Whether KASAN collects and saves alloc/free stacks.
3. Whether KASAN panics on a detected bug or not.

The patch titled "kasan: add and integrate kasan boot parameters" of this
series adds a few new boot parameters.

kasan.mode allows to choose one of three main modes:

- kasan.mode=off - KASAN is disabled, no tag checks are performed
- kasan.mode=prod - only essential production features are enabled
- kasan.mode=full - all KASAN features are enabled

The chosen mode provides default control values for the features mentioned
above. However it's also possible to override the default values by
providing:

- kasan.stacktrace=off/on - enable stacks collection
                            (default: on for mode=full, otherwise off)
- kasan.fault=report/panic - only report tag fault or also panic
                             (default: report)

If kasan.mode parameter is not provided, it defaults to full when
CONFIG_DEBUG_KERNEL is enabled, and to prod otherwise.

It is essential that switching between these modes doesn't require
rebuilding the kernel with different configs, as this is required by
the Android GKI (Generic Kernel Image) initiative.

=== Benchmarks

For now I've only performed a few simple benchmarks such as measuring
kernel boot time and slab memory usage after boot. There's an upcoming
patchset which will optimize KASAN further and include more detailed
benchmarking results.

The benchmarks were performed in QEMU and the results below exclude the
slowdown caused by QEMU memory tagging emulation (as it's different from
the slowdown that will be introduced by hardware and is therefore
irrelevant).

KASAN_HW_TAGS=y + kasan.mode=off introduces no performance or memory
impact compared to KASAN_HW_TAGS=n.

kasan.mode=prod (manually excluding tagging) introduces 3% of performance
and no memory impact (except memory used by hardware to store tags)
compared to kasan.mode=off.

kasan.mode=full has about 40% performance and 30% memory impact over
kasan.mode=prod. Both come from alloc/free stack collection.

=== Notes

This patchset is available here:

https://github.com/xairy/linux/tree/up-boot-mte-v2

and on Gerrit here:

https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3707

This patchset is based on v9 of "kasan: add hardware tag-based mode for
arm64" patchset [1].

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://lkml.org/lkml/2020/11/10/1187
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] https://arxiv.org/pdf/1802.09517.pdf
[4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
[5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
[6] https://github.com/qemu/qemu

=== History

Changes v1 -> v2:
- Rebased onto v9 of the HW_TAGS patchset.
- Don't initialize static branches in kasan_init_hw_tags_cpu(), as
  cpu_enable_mte() can't sleep; do in in kasan_init_hw_tags() instead.
- Rename kasan.stacks to kasan.stacktrace.

Changes RFC v2 -> v1:
- Rebrand the patchset from fully enabling production use to partially
  addressing that; another optimization and testing patchset will be
  required.
- Rebase onto v8 of KASAN_HW_TAGS series.
- Fix "ASYNC" -> "async" typo.
- Rework depends condition for VMAP_STACK and update config text.
- Remove unneeded reset_tag() macro, use kasan_reset_tag() instead.
- Rename kasan.stack to kasan.stacks to avoid confusion with stack
  instrumentation.
- Introduce kasan_stack_collection_enabled() and kasan_is_enabled()
  helpers.
- Simplify kasan_stack_collection_enabled() usage.
- Rework SLAB_KASAN flag and metadata allocation (see the corresponding
  patch for details).
- Allow cache merging with KASAN_HW_TAGS when kasan.stacks is off.
- Use sync mode dy default for both prod and full KASAN modes.
- Drop kasan.trap=sync/async boot parameter, as async mode isn't supported
  yet.
- Choose prod or full mode depending on CONFIG_DEBUG_KERNEL when no
  kasan.mode boot parameter is provided.
- Drop krealloc optimization changes, those will be included in a separate
  patchset.
- Update KASAN documentation to mention boot parameters.

Changes RFC v1 -> RFC v2:
- Rework boot parameters.
- Drop __init from empty kasan_init_tags() definition.
- Add cpu_supports_mte() helper that can be used during early boot and use
  it in kasan_init_tags()
- Lots of new KASAN optimization commits.

Andrey Konovalov (20):
  kasan: simplify quarantine_put call site
  kasan: rename get_alloc/free_info
  kasan: introduce set_alloc_info
  kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
  kasan: allow VMAP_STACK for HW_TAGS mode
  kasan: remove __kasan_unpoison_stack
  kasan: inline kasan_reset_tag for tag-based modes
  kasan: inline random_tag for HW_TAGS
  kasan: inline kasan_poison_memory and check_invalid_free
  kasan: inline and rename kasan_unpoison_memory
  kasan: add and integrate kasan boot parameters
  kasan, mm: check kasan_enabled in annotations
  kasan: simplify kasan_poison_kfree
  kasan, mm: rename kasan_poison_kfree
  kasan: don't round_up too much
  kasan: simplify assign_tag and set_tag calls
  kasan: clarify comment in __kasan_kfree_large
  kasan: clean up metadata allocation and usage
  kasan, mm: allow cache merging with no metadata
  kasan: update documentation

 Documentation/dev-tools/kasan.rst | 180 ++++++++++++--------
 arch/Kconfig                      |   8 +-
 arch/arm64/kernel/sleep.S         |   2 +-
 arch/x86/kernel/acpi/wakeup_64.S  |   2 +-
 include/linux/kasan.h             | 253 +++++++++++++++++++++------
 include/linux/mm.h                |  22 ++-
 kernel/fork.c                     |   2 +-
 mm/kasan/common.c                 | 274 ++++++++++++++++++------------
 mm/kasan/generic.c                |  27 +--
 mm/kasan/hw_tags.c                | 183 ++++++++++++++++----
 mm/kasan/kasan.h                  | 113 ++++++++----
 mm/kasan/quarantine.c             |  13 +-
 mm/kasan/report.c                 |  61 ++++---
 mm/kasan/report_hw_tags.c         |   2 +-
 mm/kasan/report_sw_tags.c         |  13 +-
 mm/kasan/shadow.c                 |   5 +-
 mm/kasan/sw_tags.c                |  17 +-
 mm/mempool.c                      |   2 +-
 mm/slab_common.c                  |  13 +-
 19 files changed, 826 insertions(+), 366 deletions(-)

-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1605046662.git.andreyknvl%40google.com.
