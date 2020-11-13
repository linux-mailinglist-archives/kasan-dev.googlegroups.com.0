Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIENXT6QKGQEFX66W6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 865AE2B2837
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:17 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id l3sf6950375ply.6
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306016; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ud/9gMpY4O3O8WT2MvRT7FsRkw4B+IgZrmTky5Os1iJrlRuxcu0CQkfl37iPldv7oi
         wPp62sl32oOcdgYJ44vDmE+rJXGTe738/eBfrNnSp3tsZ3VciUafGscvZNkQAD+UzMjz
         GtI+FSl2IVACK6TmFlTgRmCM7yw30YuU/0XAwYO4fuWPeaBPKhpfI7NK7UPe4W4Je6CC
         Ow/PgXpCQC1s5L1BbfQsneo04fxVhxaEImwTsn7hnDxhYYp+FoiZJYZ35HYyKxRyrJGw
         bDGaciuPH9GhxvOEDkF+aXtChvqYcZ3cYYmVyFDXV5iyUclRsOM0i4kbv2wxiyLS7bkz
         x9HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=4dNDa8M3Sv466QAZ4PVwtmraQ3CP3pOFD4ZF234+Nz8=;
        b=pMntCLnbnqrQ3+bjagYmntjIVc6Qd2e5ZrjV3pd+sNfxerpAG/zRy9vq4gpSAsadLL
         73zdrBt0kSH1rJPUN9uOeM73LcmfsxyrDpT7gICOLgJeB6Gucepp1DTfA+Ab3ee/+EiC
         3EH/vkoheq0vc1WuvePZa3+w4maa0ECGPcHf9+yaGjFQs0VVirgtBS5HhSTC4cCVag8Y
         wZMBRjP7q3kZGBZBQcyArYORjfWep84DPyGPQHyS+z+e32+2emjXtnwApjkukl49ktOz
         RnasI1YyV8TkkBd+A3LHjGvniyQhbmK2j4cqu9UVVWJFREf8Ee3Xnacdub/HXwvOI1/k
         UiGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oYiPLvJu;
       spf=pass (google.com: domain of 3ngavxwokcwsjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ngavXwoKCWsJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4dNDa8M3Sv466QAZ4PVwtmraQ3CP3pOFD4ZF234+Nz8=;
        b=ZXSOY6zOLKcTQOz9MesxkOJN9sV5SkLNpZWVXZFebJQqQZGX2GTMI8dj5z8sa47Wq2
         RO6K6B50FwHBHbnoDa2Om5qXAKlI5iA0JNJHL5JGLT02iMsx45JpfW/6k06pLrZ+wgRX
         Eqa0TDX9fnYfOKoLbIpIKuVzOSmoSqQYM65tB+LeoTaCWUMKdwgrUAUfVTNgV+x87IT6
         9jZQQyMvhkMqpjXDGvxkepNELF5dFQEB+GG/6m1KwVg/CTL1rbH01OTRjPqEkANHabUj
         c3W7aT9U+0DHWZpGB74UsknxDjY4V7QUNsK23R7Q0kih12ib2gYbUPeM+An0R/+lVd7D
         7txQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4dNDa8M3Sv466QAZ4PVwtmraQ3CP3pOFD4ZF234+Nz8=;
        b=rx9vw54j1NYvRA6drmn7zbfWmQMbuLft4WwO6wjUPRLp66g0tyOMaMgsPc8++aO9XV
         WHpCGmnaI2wQBDfBzXepzz8Q442N0p54W/1YqKxbQyR6UbkiB3ECdIzG+P9t/NLR0Wkk
         MtWiH9Rx2ZLcktXXdzu7uPs51nwXtq7rc8rh4mbw2sGthqvJj+VEbAKmEGxS4ykn1NEj
         XEocUt6f7dPivcJKjG4+6teQAl+HjX5OryTNrf3KoNYCDVJgFbUPa1hFpyqG26IpZ82B
         HcnK/FAGcBbq/39F1RBrI7g1uQFNG3LWSDG74d1n7U4pEgQreIXdUJ2qK5bQTYL2nmyU
         IWcw==
X-Gm-Message-State: AOAM531S9Kwo87TTzbhtp6QMFF6XdwnQy0jZsHgKoPp+90GssRtGnZKV
	9RecOOv2jI155XursIY+D5Q=
X-Google-Smtp-Source: ABdhPJyM/H232ekZs+ys2SbW1j93oWrGM+OXouV7ye/uL42Yea0s45UPB0CHwJTVqXPRYpyveAQ/2Q==
X-Received: by 2002:a17:902:a70c:b029:d7:eba5:7874 with SMTP id w12-20020a170902a70cb02900d7eba57874mr3949269plq.9.1605306016265;
        Fri, 13 Nov 2020 14:20:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:485d:: with SMTP id x29ls2565323pgk.3.gmail; Fri, 13 Nov
 2020 14:20:15 -0800 (PST)
X-Received: by 2002:a65:5907:: with SMTP id f7mr3568400pgu.445.1605306015717;
        Fri, 13 Nov 2020 14:20:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306015; cv=none;
        d=google.com; s=arc-20160816;
        b=j44ux0egC7evpPiw/KgtRpNIxuXFkphPyw0/FDJwlGxKQlvoJxGHpS44SEoIX9xnCz
         4UsEE6Xdodg3HLA7YZQXmX1DI73a5UzPHkp3sQr8xLHM77PYUVbygttKnTv6jBY2mGBF
         WcTMB9PFf6hnXdDiaBukFKHtkJSUTBs0E21O3oWPyQ8A324DyqtCyNbzG8+oMpciorLG
         zMtULNi+1AdXcoQwmOynw4gHz5GcvKovgUrN/mOwYLVs5SqS6IXZjGG9cx9MPisxwvNh
         o/X757cByDnhwRr3DR8O9Ab4MDEkDFIQdZ3Ir2s0NEQN0D4KArT+KT3s4q/MQk8T534j
         BQug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=zDRs3jeCXygY+JyOeXMq20UgM8uSb4KrUxuaITbMOZY=;
        b=pMfRxIZIgKDUFsZtXw6G0JxfgUrWMrbgRi5RJcQdlauacEApWwfnwP2S4t4ICZQmr/
         nxqDacpYzhM4RZ2bndeD0eQCrBnIjPMscRIWp6pVzwBACRm1DP/Y4vWwv0arpit3b3Xe
         yoeELGDqTCIi+Fz57xKh7FVJrthsFj3ia8niqBm9Nq0ohenlnF2v74BguaUF4Ijwy0+L
         SIFpzIY8uPiKO+/mIU22a58Faw0XS7xmyhZakMl9jBKNGMwwc7eZ2wAa4hGKVLMFZ9RN
         ogfykclttFB3cNtKgXOXXdOxweJcwG4n8GL402lFFg5jf2Ui/Mc3E2gpbdna/LwMtQvI
         uf6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oYiPLvJu;
       spf=pass (google.com: domain of 3ngavxwokcwsjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ngavXwoKCWsJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e19si606432pgv.4.2020.11.13.14.20.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ngavxwokcwsjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id x20so6633094qts.19
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:15 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:fdcb:: with SMTP id
 g11mr4474180qvs.58.1605306014857; Fri, 13 Nov 2020 14:20:14 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:50 +0100
Message-Id: <cover.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 00/19] kasan: boot parameters for hardware tag-based mode
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
 header.i=@google.com header.s=20161025 header.b=oYiPLvJu;       spf=pass
 (google.com: domain of 3ngavxwokcwsjwmanhtweupxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ngavXwoKCWsJWMaNhTWeUPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--andreyknvl.bounces.google.com;
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

https://github.com/xairy/linux/tree/up-boot-mte-v3

This patchset is based on v10 of "kasan: add hardware tag-based mode for
arm64" patchset [1].

For testing in QEMU hardware tag-based KASAN requires:

1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
   to run).
2. GCC version 10.

[1] https://lkml.org/lkml/2020/11/13/1154
[2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
[3] https://arxiv.org/pdf/1802.09517.pdf
[4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
[5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
[6] https://github.com/qemu/qemu

=== History

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
  kasan: clean up metadata allocation and usage
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
 mm/kasan/quarantine.c             |  13 +-
 mm/kasan/report.c                 |  61 ++++---
 mm/kasan/report_hw_tags.c         |   2 +-
 mm/kasan/report_sw_tags.c         |  15 +-
 mm/kasan/shadow.c                 |   5 +-
 mm/kasan/sw_tags.c                |  17 +-
 mm/mempool.c                      |   4 +-
 mm/slab_common.c                  |   3 +-
 18 files changed, 824 insertions(+), 376 deletions(-)

-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1605305978.git.andreyknvl%40google.com.
