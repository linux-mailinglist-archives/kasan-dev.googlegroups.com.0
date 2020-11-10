Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL5GVT6QKGQEUBCIPMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AF7C32AE353
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:24:48 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id u13sf16746ooj.14
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:24:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605047087; cv=pass;
        d=google.com; s=arc-20160816;
        b=ums5X6XrD2VV6gcQggtfk4SZ4Od3E69EYmA+i5N3JlMjRMHIuFY2Vqkp5Rqj8grdeD
         OK0MosWk1OhbmqHTf+EYWTQbbjnhDZjr0pzOxQhZBxCDvlwonJaoQtEGoMdOl06ZvuVo
         a4zLviyGhWkXWH5a6UhUBXw9sd9zYG7eSFPkEhjsn/+buj3Y19yLeYlQH5Ld9N2+YvCx
         5OHLFwwgRzL5X2skiYz0BcFPiYTMg5RtVEOiab8GTnZBnzORKR8C3bnLb39cI5CqTWa+
         ARGHwHw6lwookifjS+K+oAVLIemFJ4ocjunFE7Sdo7uv2TT7agnjPc9Sh63VJCp3rapu
         2XBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ibSnsKYaknkPCNSXRU0GIRdfMAfGFOq4JYivclSed/o=;
        b=WYJrqNUuxNkuF1u90k5kaRgr8G1tlXPEHsWfCIQtFsR5jSYtxqsLuv20Lp7C7t56lE
         i+2AbhBQ8jUk7TTkfoG3r9M63hbClffjEmXlBxbwnsfIeOazwkDLuP4ogZxKX6k82SW/
         eKrXQL1OV8r1CcAPLgZ61wmRxBim6j7lhZmVNgWm6Gu7FSte3uy3H+Mp/C3AR48Yn0KZ
         bEC3l0dyMLmQor0zbHZ6iiWUbehAMZbEo/z3HxfQmAWT+Mg9hvXBKJe5eC1AoC6myP8e
         QloW8WT/K/rs2iURyJHyS7E/QW/Sz67r9B3wTw7sXK22VhGp2F61SiJo+uJ9QVTs9f7s
         xJ3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qd3Cs5Q4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ibSnsKYaknkPCNSXRU0GIRdfMAfGFOq4JYivclSed/o=;
        b=sVF/c9iSCOhCYMZEa4q2kOIqxAx10i5oLVHQ2tbBbaYitlu50mSQ//Ydzh+mYvVl8D
         XaKPXdi/78WFFJVRRCzAYdpZi5mqsrCtJqu0l3dajQQEJzcqZfmS8u3qh6nxJMixPPQC
         iRlyhbGJ/OviVrZPpZB+JtN5TrSLfExSndTe6HsxdtO+GuGHVO3wy9SetDiG/cLW3WZA
         vKWGDq05oOQNa3LqT70JNiY3igRZlxHZC2DeyZIZm82LNt8klSOn5B7GIUeIym4I8FV+
         3OWpDxCitpCqMg8MNJkuxVNt8aehv3j9hgaO3zvUV8Mr7mFSYpfbwW5WST0DnB/kncmu
         56MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ibSnsKYaknkPCNSXRU0GIRdfMAfGFOq4JYivclSed/o=;
        b=fzTOwashs2FgCSqUEb6AzCRZK11s9k6NlIz5oCwBSpA0LR8R7ne81LRUuc5QNsSpWt
         2l7J33JllW/1t/zoKZx+r1Upi38y1wWM6Z9BKXKyfwHh09Gheno0T6wB4efZ5vE8R402
         SJJc4lft7x4HA/3gYGFWZFVMcV9qed1cUCq/K5DjM+PhjDNk/fGEwsoRvmkNPXvdd2an
         Ktsgr0cwS8X6TQnwQnhmZ4H48lIzZ9U1/ftiUVdayXl8MMF/inuM4MqIgeGUH3O+iRdw
         ksevY+/G5uHlcjmpZ6BTfvuJrZXMPgFqSHixnPzamM0YnF8vjmZjnbwrDzVUu/QFtD9G
         zGqQ==
X-Gm-Message-State: AOAM533nbNxKEcHKftV/VTz6D+i4epiSnBBfClbHH3s3UYEocC5KwYiF
	YLM5BPgtIhytxuI88XUiJM8=
X-Google-Smtp-Source: ABdhPJwvJmc6yE6Tk8/PGICqf6Qvg9OvWb6BEuxROhNUBfAwCIicKBRFEPgcZSZcGBKeFHSkZ0Ridg==
X-Received: by 2002:a4a:1482:: with SMTP id 124mr15252397ood.78.1605047087650;
        Tue, 10 Nov 2020 14:24:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls3432932oie.2.gmail; Tue, 10 Nov
 2020 14:24:47 -0800 (PST)
X-Received: by 2002:aca:548b:: with SMTP id i133mr186563oib.113.1605047087262;
        Tue, 10 Nov 2020 14:24:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605047087; cv=none;
        d=google.com; s=arc-20160816;
        b=XI94I0Fz4ZTdLhuXW0ZfNRbcVxP4AI9rGKkAUpjproiQn3AnlTMuBu+nMet/Dw3Wnl
         GgAjh+mAn8bLQ7SHBsp8RREnLyUtCm9zDuxH6eroTn2tdczuiCvc9Ol+5magkXugyAsf
         qxDFnm5Dq4+FnbwKvaeEz0XQu11mECtdKbHYmte3yASpHvKPaoCZs8eROEF/wOU5JAQJ
         e7UR1QbmdQ31Df1I8Intz0Az/w5PXI0F301eys39ispdw5yTyaUKvaU46Z1oNYRlozGy
         ZeejkENa9WuOtins4Q+oCNxOjJ4ToyC1k0sl6x1PgDk+mWpXhJb7qXkGCTsukcxs8VM6
         s/Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ucd1v1fmt9Aox8XVlg3EWNREpeq3rzghILv47+FEoWM=;
        b=AKgIDdBVxlcpAQA+vdlaWpm9gom6HkuyOxTwlnybz9MdSySUu+t3ccX0/gw4Vbz/rB
         Wq9sGbWCFX81iyGQZBUUgGHz1oMfgK3XRNBmCRciFRwZu2tleBaRwVP8ilc3ds16lHfl
         SadiWzfXP9KS3bh+tYfJi9F3u4oWc8eDKNmsY1j4JGABrI38/zpH6KjB44zpphjx+KEU
         oD2TC8mkM/xX4gb8AKMAn1Aw7OipjOmGEQ5AGCaNEVQv4X8BG6ar95eL8bc+K30HYZOk
         D1giYREKp+s/eawUQjGByzHSUmFr0cclFNUoThAbDnXBV9+zIXygTvRzeZagrCJNGKTV
         uYmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qd3Cs5Q4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id r6si24923oth.4.2020.11.10.14.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:24:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id f27so8098591pgl.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:24:47 -0800 (PST)
X-Received: by 2002:a17:90a:eb02:: with SMTP id j2mr349233pjz.136.1605047086391;
 Tue, 10 Nov 2020 14:24:46 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Nov 2020 23:24:35 +0100
Message-ID: <CAAeHK+yz7219CWL_afRiJD10FHR5pC9roMz7_dxOq9feAhmKMw@mail.gmail.com>
Subject: Re: [PATCH v2 00/20] kasan: boot parameters for hardware tag-based mode
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qd3Cs5Q4;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Nov 10, 2020 at 11:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> === Overview
>
> Hardware tag-based KASAN mode [1] is intended to eventually be used in
> production as a security mitigation. Therefore there's a need for finer
> control over KASAN features and for an existence of a kill switch.
>
> This patchset adds a few boot parameters for hardware tag-based KASAN that
> allow to disable or otherwise control particular KASAN features, as well
> as provides some initial optimizations for running KASAN in production.
>
> There's another planned patchset what will further optimize hardware
> tag-based KASAN, provide proper benchmarking and tests, and will fully
> enable tag-based KASAN for production use.
>
> Hardware tag-based KASAN relies on arm64 Memory Tagging Extension (MTE)
> [2] to perform memory and pointer tagging. Please see [3] and [4] for
> detailed analysis of how MTE helps to fight memory safety problems.
>
> The features that can be controlled are:
>
> 1. Whether KASAN is enabled at all.
> 2. Whether KASAN collects and saves alloc/free stacks.
> 3. Whether KASAN panics on a detected bug or not.
>
> The patch titled "kasan: add and integrate kasan boot parameters" of this
> series adds a few new boot parameters.
>
> kasan.mode allows to choose one of three main modes:
>
> - kasan.mode=off - KASAN is disabled, no tag checks are performed
> - kasan.mode=prod - only essential production features are enabled
> - kasan.mode=full - all KASAN features are enabled
>
> The chosen mode provides default control values for the features mentioned
> above. However it's also possible to override the default values by
> providing:
>
> - kasan.stacktrace=off/on - enable stacks collection
>                             (default: on for mode=full, otherwise off)
> - kasan.fault=report/panic - only report tag fault or also panic
>                              (default: report)
>
> If kasan.mode parameter is not provided, it defaults to full when
> CONFIG_DEBUG_KERNEL is enabled, and to prod otherwise.

Can I get everyone's Ack on these boot parameters?

>
> It is essential that switching between these modes doesn't require
> rebuilding the kernel with different configs, as this is required by
> the Android GKI (Generic Kernel Image) initiative.
>
> === Benchmarks
>
> For now I've only performed a few simple benchmarks such as measuring
> kernel boot time and slab memory usage after boot. There's an upcoming
> patchset which will optimize KASAN further and include more detailed
> benchmarking results.
>
> The benchmarks were performed in QEMU and the results below exclude the
> slowdown caused by QEMU memory tagging emulation (as it's different from
> the slowdown that will be introduced by hardware and is therefore
> irrelevant).
>
> KASAN_HW_TAGS=y + kasan.mode=off introduces no performance or memory
> impact compared to KASAN_HW_TAGS=n.
>
> kasan.mode=prod (manually excluding tagging) introduces 3% of performance
> and no memory impact (except memory used by hardware to store tags)
> compared to kasan.mode=off.
>
> kasan.mode=full has about 40% performance and 30% memory impact over
> kasan.mode=prod. Both come from alloc/free stack collection.
>
> === Notes
>
> This patchset is available here:
>
> https://github.com/xairy/linux/tree/up-boot-mte-v2
>
> and on Gerrit here:
>
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3707
>
> This patchset is based on v9 of "kasan: add hardware tag-based mode for
> arm64" patchset [1].
>
> For testing in QEMU hardware tag-based KASAN requires:
>
> 1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
>    to run).
> 2. GCC version 10.
>
> [1] https://lkml.org/lkml/2020/11/10/1187
> [2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
> [3] https://arxiv.org/pdf/1802.09517.pdf
> [4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
> [5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
> [6] https://github.com/qemu/qemu
>
> === History
>
> Changes v1 -> v2:
> - Rebased onto v9 of the HW_TAGS patchset.
> - Don't initialize static branches in kasan_init_hw_tags_cpu(), as
>   cpu_enable_mte() can't sleep; do in in kasan_init_hw_tags() instead.
> - Rename kasan.stacks to kasan.stacktrace.
>
> Changes RFC v2 -> v1:
> - Rebrand the patchset from fully enabling production use to partially
>   addressing that; another optimization and testing patchset will be
>   required.
> - Rebase onto v8 of KASAN_HW_TAGS series.
> - Fix "ASYNC" -> "async" typo.
> - Rework depends condition for VMAP_STACK and update config text.
> - Remove unneeded reset_tag() macro, use kasan_reset_tag() instead.
> - Rename kasan.stack to kasan.stacks to avoid confusion with stack
>   instrumentation.
> - Introduce kasan_stack_collection_enabled() and kasan_is_enabled()
>   helpers.
> - Simplify kasan_stack_collection_enabled() usage.
> - Rework SLAB_KASAN flag and metadata allocation (see the corresponding
>   patch for details).
> - Allow cache merging with KASAN_HW_TAGS when kasan.stacks is off.
> - Use sync mode dy default for both prod and full KASAN modes.
> - Drop kasan.trap=sync/async boot parameter, as async mode isn't supported
>   yet.
> - Choose prod or full mode depending on CONFIG_DEBUG_KERNEL when no
>   kasan.mode boot parameter is provided.
> - Drop krealloc optimization changes, those will be included in a separate
>   patchset.
> - Update KASAN documentation to mention boot parameters.
>
> Changes RFC v1 -> RFC v2:
> - Rework boot parameters.
> - Drop __init from empty kasan_init_tags() definition.
> - Add cpu_supports_mte() helper that can be used during early boot and use
>   it in kasan_init_tags()
> - Lots of new KASAN optimization commits.
>
> Andrey Konovalov (20):
>   kasan: simplify quarantine_put call site
>   kasan: rename get_alloc/free_info
>   kasan: introduce set_alloc_info
>   kasan, arm64: unpoison stack only with CONFIG_KASAN_STACK
>   kasan: allow VMAP_STACK for HW_TAGS mode
>   kasan: remove __kasan_unpoison_stack
>   kasan: inline kasan_reset_tag for tag-based modes
>   kasan: inline random_tag for HW_TAGS
>   kasan: inline kasan_poison_memory and check_invalid_free
>   kasan: inline and rename kasan_unpoison_memory
>   kasan: add and integrate kasan boot parameters
>   kasan, mm: check kasan_enabled in annotations
>   kasan: simplify kasan_poison_kfree
>   kasan, mm: rename kasan_poison_kfree
>   kasan: don't round_up too much
>   kasan: simplify assign_tag and set_tag calls
>   kasan: clarify comment in __kasan_kfree_large
>   kasan: clean up metadata allocation and usage
>   kasan, mm: allow cache merging with no metadata
>   kasan: update documentation
>
>  Documentation/dev-tools/kasan.rst | 180 ++++++++++++--------
>  arch/Kconfig                      |   8 +-
>  arch/arm64/kernel/sleep.S         |   2 +-
>  arch/x86/kernel/acpi/wakeup_64.S  |   2 +-
>  include/linux/kasan.h             | 253 +++++++++++++++++++++------
>  include/linux/mm.h                |  22 ++-
>  kernel/fork.c                     |   2 +-
>  mm/kasan/common.c                 | 274 ++++++++++++++++++------------
>  mm/kasan/generic.c                |  27 +--
>  mm/kasan/hw_tags.c                | 183 ++++++++++++++++----
>  mm/kasan/kasan.h                  | 113 ++++++++----
>  mm/kasan/quarantine.c             |  13 +-
>  mm/kasan/report.c                 |  61 ++++---
>  mm/kasan/report_hw_tags.c         |   2 +-
>  mm/kasan/report_sw_tags.c         |  13 +-
>  mm/kasan/shadow.c                 |   5 +-
>  mm/kasan/sw_tags.c                |  17 +-
>  mm/mempool.c                      |   2 +-
>  mm/slab_common.c                  |  13 +-
>  19 files changed, 826 insertions(+), 366 deletions(-)
>
> --
> 2.29.2.222.g5d2a92d10f8-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byz7219CWL_afRiJD10FHR5pC9roMz7_dxOq9feAhmKMw%40mail.gmail.com.
