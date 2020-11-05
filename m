Return-Path: <kasan-dev+bncBCJZXCHARQJRBXGKSH6QKGQEHMCJSHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F5492A884F
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 21:49:34 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id s130sf1939248pgc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 12:49:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604609373; cv=pass;
        d=google.com; s=arc-20160816;
        b=rEV4Ue2kZF80GyCi+3VAYTYIvmF0CU4EPA+xINJKkMq/PA38Fs4AWJEyT4dSo+0OyY
         pBi10B5F32Qmxk5QtYhdxVlmi4pYVubYb00l25mZAOnWT+dLQvNdGFnF98miFs+FZbqm
         vGknqQnBwlogV5js07ooLcuatjQUTLNKV/4ulfnabhFtB5e7+xyP2984h1Y5pIMNB/8P
         iJroaPm2O8KSb0FO4cVL6ccpfOl16bmiIuv7q541YHjbThhqTuVVIvl2k6lSUqyiIvR1
         ao/xiaueLn1Txa9tiX4KIOd1xNQ4N6MBnOS20DMsm2M+xG+1n6/7goFkiHiZlqqVhpuE
         l7nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ssisd3uUaoADb0QCB3tndHradIWzy7ri0vZ2PrYg0yU=;
        b=dNqNcSaGRyubMCDNKz25F6x8YpKYT2Xb//gwX1dB7rR5qDtkB68QnyCoii0gFkhg7s
         5EGdiTfK754Z9QRCFZdvvAr5QcIn0dbOVH2HsHGwhDZbbQXOufKmULO+q5lSNicrRF/W
         f/c/HPMT2Ghqk7Bgcz7bXj6t/uxvWKtZAxbbwncqLk2vyzGkkbXRYvCPCc5avgaf9Vws
         a2swZK/DeorJeDSeYiyivwgF6SL+oJfMBuoWjMhVptXEPNM/AaJesMdl9UdYU+Sj+d/M
         5urS0TdZTIxTwA9B70gz0NSP4G7dp2adubIkuJ63Zqlm9IfysIBLv48sjqIcLMasEue8
         ge5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ESrF9IcK;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ssisd3uUaoADb0QCB3tndHradIWzy7ri0vZ2PrYg0yU=;
        b=JcodNCQD7tQY0q7tMOsMXPuIzX/Yt0RIHeNCo4daAlI8RnZsRM9N5flKAJiH9SkvKC
         LtKfKtvXm/7shooBa3Dte4LmEszUFixAXNMb0yrTIV2Q7oaggy/DICZmvKY3NkvhIpNm
         ONoyS+99D1uvaW2+3seHGnoJ85FUXBKOj5/spWN1xI/AcxmeYpS+SInqMrSXHm1u0dW6
         c5L1tVqycygcaIizRJ8HXzl4vAlTs47UXAqqvL3+ohWUl3kdlRnVdDYg6DR4cVdpNx9p
         tVRuhdrOXpwkuie6yQv17MvCrdTXdFJVV6KIgYQ1wjbqE9cJi4qaEa770zZ2D/bpCLmQ
         qCEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ssisd3uUaoADb0QCB3tndHradIWzy7ri0vZ2PrYg0yU=;
        b=awq5gfh/agA48Lcqi9+fSJysVOKsKK54LDnX8HpR/x6/7HXF9PHXAoVw6bkbzw3PdR
         HzVzU+TN8VSy6jc1M/mpYxWI2BQ93AdRZo3d6x4jPs3VV05vYgucIbh7oxKcH41B7sNZ
         DyKCSe7jK2LBPsxIrTdeD2+AwVvsJPLHEAvd8Qi3bjchHmWWW5msYzH7vCEkJveq9jJQ
         fFLRKjncNafPgE/qviWMSkipZOsRCe6PBEJycn9l0B+ZVDLYzpLe/Cm/Rxbci2hzbqpm
         tXKRAI3PUOsUqR3jtW2Gj5yCI7kiEgcu841kK4uJhSJTLTWXU8YsedeCHyruAbzi1dbP
         LrOw==
X-Gm-Message-State: AOAM530jLFGFYjF86Q8Xa4o1vLqsCj9Mxbwk2mBFEiTQBdm4AB6K+eXA
	b55FwHOf2UkqY6r+fnCRqsQ=
X-Google-Smtp-Source: ABdhPJw13dB2mXdGAtc8rPFRpI59McOc0UD/8wP+BqCjF4CNPtF9+rcLLiTLXpJaoGaLlhZhiIUvPA==
X-Received: by 2002:a17:90a:5d82:: with SMTP id t2mr4253054pji.42.1604609372916;
        Thu, 05 Nov 2020 12:49:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7786:: with SMTP id o6ls1219335pll.0.gmail; Thu, 05
 Nov 2020 12:49:32 -0800 (PST)
X-Received: by 2002:a17:90a:cb05:: with SMTP id z5mr4283518pjt.216.1604609372340;
        Thu, 05 Nov 2020 12:49:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604609372; cv=none;
        d=google.com; s=arc-20160816;
        b=xGzlyWRueOVZPbIiKz4Kk3J07bzExXm8S6uJqpXOrPQ4VGtBCnB9yFtlAh5b7BIX50
         5noZa2oCWeoakXjPlh2BI9CcsUj0xeezsig/zwppBzXOB+37cRnJeyjcv//BinXyih5T
         WUxlNXPqBkI+vkr7uGBSMPUgwT6YeWkQC63Ig9ovtKMj/vuhjvw+uhiusWG4glSpWMvA
         kha/uYFXwn2VUDuE8ek4wke5hmk0IEkHG2aBBIk64MV544BExT7hZngIws1zUsYN8G6p
         8dnG0Y1tbJkSdcjuleNfUWS/wh+lecxMJyxsi9osvqKLccHh3JHxbdHmlSxCLAifuZG7
         ehvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a2MIruyaauzWgJCQrDte1MB4IpvSBdXb3vNyeqYlOUw=;
        b=GUEtzQEvgAhhWDeNuONAa9+fjPs81MLs1Ra4MRLZLKR0utlPLlfFhhoVSqrVcRY9VD
         tkHcWXo+R1C81wtM+4o5CSsWJV1u6UjVXO3yG3bOs7JGKzvItDrBQ2H7Lck8p0o9JBXg
         ayuyX6E8wpkQtZDVJWIJ+aCci+2iIaCgbAoufXInkZULhiSouGfzSjm+kOsmGI3Jjt/I
         gA5+3UZS8ZlUBva1DGb5CIhelnVWsRWhaP00UwA9Zkkqyfju6q0aLLwWpjdY+7ICVEG+
         m/lNijlS38abDivf4QapnOkp+xMNO2Drx6DhCcfvlkbo8Rm8SRRE/X7WEyI0G1PDZjDQ
         EhlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ESrF9IcK;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb44.google.com (mail-yb1-xb44.google.com. [2607:f8b0:4864:20::b44])
        by gmr-mx.google.com with ESMTPS id iq1si184568pjb.2.2020.11.05.12.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 12:49:32 -0800 (PST)
Received-SPF: pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b44 as permitted sender) client-ip=2607:f8b0:4864:20::b44;
Received: by mail-yb1-xb44.google.com with SMTP id c18so2514553ybj.10
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 12:49:32 -0800 (PST)
X-Received: by 2002:a25:b2a1:: with SMTP id k33mr6394582ybj.337.1604609371269;
 Thu, 05 Nov 2020 12:49:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
From: "'Evgenii Stepanov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 12:49:19 -0800
Message-ID: <CAFKCwrgCfx_DBf_b0bJum5Y6w1hp_xzQ_xqgMe1OH2Kqw6qrxQ@mail.gmail.com>
Subject: Re: [PATCH 00/20] kasan: boot parameters for hardware tag-based mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eugenis@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ESrF9IcK;       spf=pass
 (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b44
 as permitted sender) smtp.mailfrom=eugenis@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Evgenii Stepanov <eugenis@google.com>
Reply-To: Evgenii Stepanov <eugenis@google.com>
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

On Wed, Nov 4, 2020 at 4:02 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> === Overview
>
> Hardware tag-based KASAN mode [1] is intended to eventually be used in
> production as a security mitigation. Therefore there's a need for finer
> control over KASAN features and for an existence of a kill switch.
>
> This patchset adds a few boot parameters for hardware tag-based KASAN that
> allow to disable or otherwise control particular KASAN features.
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
> - kasan.stack=off/on - enable stacks collection
>                    (default: on for mode=full, otherwise off)

I think this was discussed before, but should this be kasan.stacktrace
or something like that?
In other places "kasan stack" refers to stack instrumentation, not
stack trace collection.
Ex.: CONFIG_KASAN_STACK

> - kasan.fault=report/panic - only report tag fault or also panic
>                          (default: report)
>
> If kasan.mode parameter is not provided, it defaults to full when
> CONFIG_DEBUG_KERNEL is enabled, and to prod otherwise.
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
> https://github.com/xairy/linux/tree/up-boot-mte-v1
>
> and on Gerrit here:
>
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3707
>
> This patchset is based on v8 of "kasan: add hardware tag-based mode for
> arm64" patchset [1].
>
> For testing in QEMU hardware tag-based KASAN requires:
>
> 1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
>    to run).
> 2. GCC version 10.
>
> [1] https://lkml.org/lkml/2020/11/4/1208
> [2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
> [3] https://arxiv.org/pdf/1802.09517.pdf
> [4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
> [5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
> [6] https://github.com/qemu/qemu
>
> === History
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
>  mm/kasan/hw_tags.c                | 171 ++++++++++++++++---
>  mm/kasan/kasan.h                  | 113 ++++++++----
>  mm/kasan/quarantine.c             |  13 +-
>  mm/kasan/report.c                 |  61 ++++---
>  mm/kasan/report_hw_tags.c         |   2 +-
>  mm/kasan/report_sw_tags.c         |  13 +-
>  mm/kasan/shadow.c                 |   5 +-
>  mm/kasan/sw_tags.c                |  17 +-
>  mm/mempool.c                      |   2 +-
>  mm/slab_common.c                  |  13 +-
>  19 files changed, 816 insertions(+), 364 deletions(-)
>
> --
> 2.29.1.341.ge80a0c044ae-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFKCwrgCfx_DBf_b0bJum5Y6w1hp_xzQ_xqgMe1OH2Kqw6qrxQ%40mail.gmail.com.
