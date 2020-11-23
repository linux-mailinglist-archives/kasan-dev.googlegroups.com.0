Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP5Q6D6QKGQEMMUEHXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B7632C1569
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:14:56 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id g11sf5196742pll.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:14:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162495; cv=pass;
        d=google.com; s=arc-20160816;
        b=R29PHuYnQcGccSOyVvalIX/iXNUYr/qO/dXS9+XDBeOImKBAV6BrdJkE2QVpTSpkTL
         0N3L2tZHLW5LtbAL/zduNZVhnNr3ph08aeVG7YuCeDGKliPih5/c5cdwTqO4SbWf/a3W
         DXZB2mw79r+6ige0yObcbixwLCww5YzWuh04a56kN2IP9Dw7whLtbfhgn6VWx2j0r8DR
         kjRCsdczhGLXyZkiTCYyDfjeLa5hEef6iAiuMjEV0SyBrQtg3o9ANUmLymaPo7KiXKIb
         5vl5t8mOwEvsGhsdmcuHVyUvOVPRRR5qPvcx9IjieQP6YDOj4rT0UE73Cq6J+jKwhpA3
         mHRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=dsF8LCxp8mKJqX5GtLnpX0CWpmt+dHYHMw/vOfuxsTg=;
        b=iTbWpAjPMxpHqthSNCh4BplHUebYdOorPFeJisyAQytIyUDoQFmnrZs+sIeJcFJRyZ
         Fxcv/5PEUnZKXtCUK0bPAYJQXOVs2eiiTXAIwqzxYvpH60PFu+f4FrW6I1iJx0J96ITE
         Z2GjQgW7pj15QldcKjtKWszaFue5nFsC831KOMY3WsxH05lC90A7X2gpGLI0JYcUsNEO
         2Fz/+R9zokHrFJ2rvJzVxQl+Npc2kSMAsWtRjeTC45ts7k3RLQbxa7b8PX/QnU1TAMJL
         iOejd61+nMDRX0mTlZ7Mh5kjrEhjKx92sidyw/kFNTC3RMVnMhEEwTFUAsifrS0/AwZa
         H8Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lUVUGtgc;
       spf=pass (google.com: domain of 3pri8xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PRi8XwoKCWIANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dsF8LCxp8mKJqX5GtLnpX0CWpmt+dHYHMw/vOfuxsTg=;
        b=F/KAGISRfBbhriJ51giiNWq7loPItDN71U/wqQLT+V4K/AJnSHIKj2vfH91LWwQUkZ
         RLPdY63bnytJBi/+oLJEKE57AddRIXUdAbrLgL9TjhPWYTOLw6FkezF7TiUP4TKioeC8
         N6iYbxm1xMeCeogPPp+pBuRd55JQREoEehFYaE/45o47DRzlvv1VHbHc72/86UlwVEp3
         xDHD4KgQ7F3QiscDPKrnS1sEaveigD3EuTuwhVNSQxgvSpwx/d2cLB+5bFpGsVZCkQzj
         IG9xLH82TqbzpsH6YWeeK0XNOKpuJZ2QRlOV9wZiom+iBhgVZpuBlnIHeWs6OearVkgB
         +lSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dsF8LCxp8mKJqX5GtLnpX0CWpmt+dHYHMw/vOfuxsTg=;
        b=SNu4MGTPh4W/O+sZWq8QzjETiJ40G6fzgFY3//kfRbpNW9+C20J+icGiH6S+aUNed5
         Kzaq0Rr4HKaFqmuGeLu61dxdkoCY5Ph7HCs1nbo1y4WlKBTARE28pBp1PgQ/p1A9AoPH
         izw72A19ZunRIqA0MBIVsJu9F4TK9sQ+TvL7wlrqx9ixKUdJCYP/fQlxePEzACeUCWLR
         rNISopNHOZEnmNvIKhW6IKSl44/p9fwpIczIMMadNuoQqrx2jjS7NZbrxT5xUunnrZnd
         qNoXik6PgeQE1G20MEQmjYJqNaEdZMVYwCPRkGd9liGFAVv4SuYbulPQfbwSrJw+ScNn
         sWYw==
X-Gm-Message-State: AOAM5326lxUnuHwLMDWq5MtEI+7k/jHRwriEDzHkbwWVqWIr+bKXxgv0
	3V6Ufw7M+6OZDaOX/FE7tGk=
X-Google-Smtp-Source: ABdhPJzRISOqcKfGcX0L8bpn/MvBQ3E76WvNLoiJlyxns0ZtWYX/zll71AzolaFtLGdxcLkGt51cnQ==
X-Received: by 2002:aa7:9198:0:b029:18b:3835:3796 with SMTP id x24-20020aa791980000b029018b38353796mr996338pfa.9.1606162495313;
        Mon, 23 Nov 2020 12:14:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a47:: with SMTP id x7ls6677394plv.1.gmail; Mon, 23
 Nov 2020 12:14:54 -0800 (PST)
X-Received: by 2002:a17:90a:f3c1:: with SMTP id ha1mr740306pjb.20.1606162494769;
        Mon, 23 Nov 2020 12:14:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162494; cv=none;
        d=google.com; s=arc-20160816;
        b=ioVNnOGtpR5fjkcV21NQsQWBstlpPcj/EmqnFCIWQMDO2ek8FsLRFJi8z4eHX6e+gE
         EiIZFhCQjWFSFIVsQ/MuaSYXCC+Cj+amvXp+ZgQNin8gkXdiH8+9rJ0uCM3VFsNYdDwW
         beowj2uHSWGBLa2mYleMuoWkFrjIe53hLTrqUL6bPPR3WCZrmwkyESjQhbUDX//GrOiD
         iTM/G6EzoCYf0mA+cltegaf7R6bFpzKIFcvtros+7fifcIChhjR1jDiFLsAwUsi388od
         cqRMeXYenBNseC5ctvMLfZmKtvpyZ66hZ0S+VrAuuGljucU8mOvZcDF80ITogHgyhJqC
         9w7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=c7c8JGgo4s/MC71Qht68VJkAl4Zrn9c78/9WNR2CDz4=;
        b=H7kjsGefsnLDYvyr5MtE40u9aAOwASYMqgfHe5+w7k43vWuVXON7yihH1Z7tnC1QhM
         DMmTmn9xTxyHBDgm62vtSD4vRjoWmRQGMeLKBQihawm4usne0wS+HUL4F+CAyPoSaKKv
         ipaAWQl3402B4NmJiZs7Y9X96K2GyApF13v91VutcvorjjWn8n+YFv2QVfq92uKAYvAW
         BBVkdyF1kLBGDeKiQMfTZXWpASeXZx9WZwJBm53zUpnFAgwDb5a1hl3uB6QG/GQnfS1O
         v1i2HyfGiMhc0p5r70M7tp7DmmOiJTcxRpGp1ogOvzoqcLnepfaW//sXqSo4le7Zi45A
         Cskg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lUVUGtgc;
       spf=pass (google.com: domain of 3pri8xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PRi8XwoKCWIANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b26si765827pfd.5.2020.11.23.12.14.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:14:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pri8xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id v8so13697709qvq.12
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:14:54 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:83a2:: with SMTP id
 k31mr1254889qva.57.1606162493822; Mon, 23 Nov 2020 12:14:53 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:30 +0100
Message-Id: <cover.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 00/19] kasan: boot parameters for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lUVUGtgc;       spf=pass
 (google.com: domain of 3pri8xwokcwiandreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PRi8XwoKCWIANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
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

https://github.com/xairy/linux/tree/up-boot-mte-v4

This patchset is based on v11 of "kasan: add hardware tag-based mode for
arm64" patchset [1].

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://lore.kernel.org/linux-arm-kernel/cover.1606161801.git.andreyknvl@google.com/T/#t
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] https://arxiv.org/pdf/1802.09517.pdf
[4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
[5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
[6] https://github.com/qemu/qemu

=== Tags

Tested-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

=== History

Changes v3 -> v4:
- Rebase onto v11 of the HW_TAGS series.
- Don't leak objects for generic KASAN when metadata doesn't fit.
- Clarify metadata rework patch title.
- Drop unnecessary returns kasan_unpoison_object_data() and
  kasan_poison_slab().

Changes v2 -> v3:
- Rebase onto v10 of the HW_TAGS series.
- Add missing return type for kasan_enabled().
- Always define random_tag() as a function.
- Mark kasan wrappers as __always_inline.
- Don't "kasan: simplify kasan_poison_kfree" as it's based on a false
  assumption, add a comment instead.
- Address documentation comments.
- Use <linux/static_key.h> instead of <linux/jump_label.h>.
- Rework switches in mm/kasan/hw_tags.c.
- Don't init tag in ____kasan_kmalloc().
- Correctly check SLAB_TYPESAFE_BY_RCU flag in mm/kasan/common.c.
- Readability fixes for "kasan: clean up metadata allocation and usage".
- Change kasan_never_merge() to return SLAB_KASAN instead of excluding it
  from flags.
- (Vincenzo) Address concerns from checkpatch.pl (courtesy of Marco Elver).

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

Andrey Konovalov (19):
  kasan: simplify quarantine_put call site
  kasan: rename get_alloc/free_info
  kasan: introduce set_alloc_info
  kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
  kasan: allow VMAP_STACK for HW_TAGS mode
  kasan: remove __kasan_unpoison_stack
  kasan: inline kasan_reset_tag for tag-based modes
  kasan: inline random_tag for HW_TAGS
  kasan: open-code kasan_unpoison_slab
  kasan: inline (un)poison_range and check_invalid_free
  kasan: add and integrate kasan boot parameters
  kasan, mm: check kasan_enabled in annotations
  kasan, mm: rename kasan_poison_kfree
  kasan: don't round_up too much
  kasan: simplify assign_tag and set_tag calls
  kasan: clarify comment in __kasan_kfree_large
  kasan: sanitize objects when metadata doesn't fit
  kasan, mm: allow cache merging with no metadata
  kasan: update documentation

 Documentation/dev-tools/kasan.rst | 186 ++++++++++++--------
 arch/Kconfig                      |   8 +-
 arch/arm64/kernel/sleep.S         |   2 +-
 arch/x86/kernel/acpi/wakeup_64.S  |   2 +-
 include/linux/kasan.h             | 245 ++++++++++++++++++++------
 include/linux/mm.h                |  22 ++-
 mm/kasan/common.c                 | 283 ++++++++++++++++++------------
 mm/kasan/generic.c                |  27 +--
 mm/kasan/hw_tags.c                | 185 +++++++++++++++----
 mm/kasan/kasan.h                  | 120 +++++++++----
 mm/kasan/quarantine.c             |  19 +-
 mm/kasan/report.c                 |  61 ++++---
 mm/kasan/report_hw_tags.c         |   2 +-
 mm/kasan/report_sw_tags.c         |  15 +-
 mm/kasan/shadow.c                 |   5 +-
 mm/kasan/sw_tags.c                |  17 +-
 mm/mempool.c                      |   4 +-
 mm/slab_common.c                  |   3 +-
 18 files changed, 829 insertions(+), 377 deletions(-)

-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1606162397.git.andreyknvl%40google.com.
