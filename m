Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHECRX6QKGQEB2FKYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F36A2A7368
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:37 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id j2sf478603ybb.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534556; cv=pass;
        d=google.com; s=arc-20160816;
        b=OwPBoUzGZ6y42kXSCkdlZO0g/nY/VhVUxMZlz8UGHIXu9GfKVHaXvIDu5a18qvEGOG
         S7zmwuvMAG+QMuCJCPc0fnL/LlPPi7hvRPIFJlxE+PpxZDCgu0Y3+tbiEa7jggpSvvJE
         Gmf9GM09+DralUBzXu5akUetTfVY6zrzS0tJCwGE7AOyLY960kGa8f8Q51zw5Fe0GBaE
         qQgKyLXtrDCz9RZFzwtPIR9vPMVCzGMCs/0Et4U2p9NfkvZPn2yX67ptNITmSMQMm5/z
         OZ9X4TpA/cbabNL0kJ4YP8XRg498rjkHn775cuSJorIBpS1uhqrm3Wwc8smyIALcXFBF
         YjNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=sSzJKhb8z9242P/VZBDII5KolQ504rssq6guPxutTiQ=;
        b=05b/pZCYS6OJMuCDws0JAXnp4uXxa0Cn1q7Fb4Qqm7f+PpaGAJrwR18CTn5gkrxLgh
         pj8/+IgBSplKLts6XBT4O4GbsZulDBcj/VsO5bbkVL/IVQCU9J2FWkCG9c4CB+Fqthbf
         E0aYnSNbnlCDjx2ulG7PEk28UsJwqvZ3pOdzYNP2kDG8YQIinQaPJnfY6C6x5A+bOq15
         gnlkPeIKWkHeAg6e+UyMAv/xa3KuBkIxT50x/5F+HlgGn4AxrErrbYGQfxWCex96Kaji
         KGzPWUGyBlRWPw2JdxI2Of5zb8rJJiYbbf/q1mtgM/qMroIXG7wH3e+YHfhE0Y/Kaa60
         pB5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tlosH7TY;
       spf=pass (google.com: domain of 3g0gjxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3G0GjXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sSzJKhb8z9242P/VZBDII5KolQ504rssq6guPxutTiQ=;
        b=HYIjjIi3e8KHSSx7lA2A2hi/zRVQrGvbU3OKDyyORK3Azeop+6UWsQL8ueG3ReXmGU
         DCtqtzaRBni11h8x1uBENBvEfIravSJauuqnBmuvi3mPKkMPkSbTHKw7dtE+gC81MTQB
         Ab7/JRayxsHux6OHxQBQHqCNnMmpmX4z+EU2+ojdspd66dtHI7MFOWoCeo7ce2u0Tv/8
         mkbod6xeJwvEuKFO6NpYSrNdW/L70ON6Tz5xyZ/Gr7ufNgbR+DVIKsx3FvWOe6qalYtc
         PlSLoe5yiDLUsFQPvy3E+HKVt6F0+G5kc2BGjwwqOFKj6R5lNttzhwuftT1/4THU8peC
         z6Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sSzJKhb8z9242P/VZBDII5KolQ504rssq6guPxutTiQ=;
        b=XwhhOE49TksAsC1/vXV1zO6PKI+DV/QvRuGLekq49I1LYppNy+lKgFn3dwasZ/Naik
         bLpcVrKchggIAR+nWxDwdEv1nUF57QBr1i9nPboHG/9C7aFODXxSgxIfWUc0ktuxjk83
         +kWFo2xiyjZyG4BsCqlzDyS0DwMB6opxKwU36uH6NrPkUfFKv6Y0HhAszlB3SD/nTkFd
         8VrnzIi5itpY5h8Q0FjuuryRG6uDpoABJ8jLLP6FvOIAs1hHYzBleSGYGLHONMgVtJUj
         cj/QSTorBs2illcK1ihJi4f/0PKDaGgdfMpm0OQukhRB4DFPCJty2y45kGl6dB/5LJDE
         mICw==
X-Gm-Message-State: AOAM530UzWj3TDZZSB/ufm2qR/ZKsssFkYByb1HLqd+fgVzB9TzgVHdE
	P3aYXgLfJrJ9kM+pmdkF8T4=
X-Google-Smtp-Source: ABdhPJzC0hVJNmMFR/t3gHj35bQ75BJIEo9N1mckVr20lF5ueEg8pP3ZKQef8k8KJ/pu2yMW9R8c0Q==
X-Received: by 2002:a25:bbd2:: with SMTP id c18mr26851ybk.442.1604534556442;
        Wed, 04 Nov 2020 16:02:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4e08:: with SMTP id c8ls8245ybb.3.gmail; Wed, 04 Nov
 2020 16:02:36 -0800 (PST)
X-Received: by 2002:a25:c7c7:: with SMTP id w190mr10967ybe.83.1604534555851;
        Wed, 04 Nov 2020 16:02:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534555; cv=none;
        d=google.com; s=arc-20160816;
        b=d/hBq6xy3fgaaRVHZ3JOL/1nGDzsAKKKNvI813jWyLMAZFC0dBNQ6uPClnQdMbOR2b
         Y5pmaaZxZ7X11Rd8urRhhPkhxgiB8kz2Lr+U+gSCO91jVCH7jGuXgfgUkWQDi95Vm2pT
         erOhBcKs1fWlQ23M1BmK221vMtOJQVMv/37Y9NjmnjgIJ7HZYAxp867/Zm9niKd7xPAH
         CU3haL1+zfum4QMY9Rdka5RlVnnOearw7SyIidptEFqjLIu1r68rvochiiteMER+iv0u
         68HsN1Sx8UZm8DMxiPwoc61SLCnUgfFjFSy+7i27BuL4DZYKASo/ybQF5+HLlq0Nfx+8
         HAEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=WSUBpnn+b8BH+LyGrDbHds9kTTIXmq8ZO4c/IH1ztE8=;
        b=jyiV6o/SWxFjTueqCpKaxMkxcuFfq4mgJRAgFkLTKqtWTryOfvDe1hL0vWePoSJFq6
         6BM209cBql4QO4qJVwGLBaEVhc9kmpY6LpISRzp/+3CdoULK2SC2bLw7AYXs0eX/c1NM
         IjDjlprLIxjmOQF1WVMZ0ISwFyc3tp8BYidCrVG9Txp1hATdjTRPkAnT6El/4xmKdMVM
         YjwEhwZRQTOdP4TT1JXKKysjdbhZyI25kOrq8umwxSoF3yyl4Ubg7hR6/W0LfKGMo4tL
         eB3AOU+A6mlog5Rc3ruBXCyP0xdptLNqDttDVM8lIBAuN9bTIFC5iRV+6RMtkEllsnSq
         5VNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tlosH7TY;
       spf=pass (google.com: domain of 3g0gjxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3G0GjXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id t12si1220ybp.2.2020.11.04.16.02.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3g0gjxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id e23so23924qkm.20
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c187:: with SMTP id
 n7mr286302qvh.19.1604534555430; Wed, 04 Nov 2020 16:02:35 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:10 +0100
Message-Id: <cover.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 00/20] kasan: boot parameters for hardware tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tlosH7TY;       spf=pass
 (google.com: domain of 3g0gjxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3G0GjXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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
allow to disable or otherwise control particular KASAN features.

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

- kasan.stack=off/on - enable stacks collection
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

https://github.com/xairy/linux/tree/up-boot-mte-v1

and on Gerrit here:

https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3707

This patchset is based on v8 of "kasan: add hardware tag-based mode for
arm64" patchset [1].

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://lkml.org/lkml/2020/11/4/1208
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] https://arxiv.org/pdf/1802.09517.pdf
[4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
[5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
[6] https://github.com/qemu/qemu

=== History

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
 mm/kasan/hw_tags.c                | 171 ++++++++++++++++---
 mm/kasan/kasan.h                  | 113 ++++++++----
 mm/kasan/quarantine.c             |  13 +-
 mm/kasan/report.c                 |  61 ++++---
 mm/kasan/report_hw_tags.c         |   2 +-
 mm/kasan/report_sw_tags.c         |  13 +-
 mm/kasan/shadow.c                 |   5 +-
 mm/kasan/sw_tags.c                |  17 +-
 mm/mempool.c                      |   2 +-
 mm/slab_common.c                  |  13 +-
 19 files changed, 816 insertions(+), 364 deletions(-)

-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1604534322.git.andreyknvl%40google.com.
