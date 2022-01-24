Return-Path: <kasan-dev+bncBAABBTWTXOHQMGQES3CSXIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 0472649878C
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:02:55 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id v2-20020a1709062f0200b006a5f725efc1sf2425072eji.23
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:02:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047374; cv=pass;
        d=google.com; s=arc-20160816;
        b=uBp5PPbgZOP4rqet8szoFBE1OOX6vAeqGpx14Y7dCRjzooyBzATjJ8HvvR4Lzb9DsS
         e3cBi8d+ZZny9LBqSsojNmuNgPNL7tCFQUm76XgrQYsOvgXg2LHGuwJUCnLlQGkQ4ZUV
         qT3NgPFm1S0pjM/ExiMat4vnrYyps2gog5lAD5hOKt7qalRIsFe2pDnPRnJ/PFKQIO/a
         Jt/pezYQppALugz2zXk0hr5mxNnJebIHKaPZJr8gb5kkJXYsXUJbiXpobuC8k6y5sfmj
         jJRW9As/Grm/eb5+Tdqb1W7y4YkdDtQATwMHb/fIuWg8DrTLcLKexOVf7lK13cMCxHFm
         wh+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=aEf1i1ZQ0o9fvDK/C41P72yH4Ji/dKRoeuVuAw/AShM=;
        b=KFkerico60MTvEl50UQOk+5pqwQ49amXDgdLvP0LBwky+t3J44K6pSxICzlEEf6mSs
         uBG7JrD4pqLKZkoZbWPqQuqs++ZGYOmweTYyJd6Ceo27iUc+2txgXi7anhhfgDpWpmB0
         XRjVr97Bj9LHkjaEyB04Eo3SjghnCy4HAH4NpHOOKeIIuoxbFzCeCwFTRIz2Apw1kvqT
         YkfvczdjwI9xa3lp9Yh7BprRxOgxryf2K3jh41uBoTMh620vZNnrpQYJDS5Kysvt5eHW
         x/IlVQsd3nUHXrdMFkoAYycS9D/o5vZ2U5xjtCj2adSdlfoYI0C8RXuys09pYXzKB7RM
         M/YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xVwDGQ88;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aEf1i1ZQ0o9fvDK/C41P72yH4Ji/dKRoeuVuAw/AShM=;
        b=ICjyauDL3khZNucRIt3NkFOigwK9gAeMGI8hLswxyxoSJYDeQxPn28zX8uVvg3131o
         LJR6HdPe6Tfh/Aww2jAvJ4Yn8X99CDx9Y8GwRPgpaiWchsolcBI16vQKWo2wu6iWSwqv
         KWK6Po1R4X+hQwXl29BTtBTnPQKH49bleGtMs94jq7aJWEQKysMgh29Dqgf6u43AdUQa
         SW6/3n7DeZ2WXa4SDq79X4DzvhabQa7HmCgL0YCd+SCuRE494p+n8TEFhdoQJf4XEjvJ
         fvt5+yD/3V62kpMTBVtER7hpHz82IJkuFS2YqCDqH8tDiWB6STEEpmdy87zhsrzk6p9I
         LzgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aEf1i1ZQ0o9fvDK/C41P72yH4Ji/dKRoeuVuAw/AShM=;
        b=g6uT+VBai8BYLVqNaWiUC1uC2F0yJn+gLfMc4m0Ay9+eaN5dbHfDl0HQE/WUpl5jRt
         sivu79zjJBBer5VuWjL5c7HYxn5RQ0t38T8Ej4VhMuGHfVEQRTKhPLW5uW9064BE2PbC
         3XhQkRVVF2C3p0txBhCM2AJJGgAcbsrKY2D1Yf9LYZC/Vkug4WxyS1rM2Zj8JiMrLWLB
         dR4ADjnGU2dOcXvNwMsGMe9/HLPX00heMZTkP++a5azTKiLfR0WXoNFZFJocC9+XRC7N
         2Dz5BEccKbaccndJb4QcBmrIpVRNlIH7HtjUlGVFOxR9pnDxzwBo3qjfcORE7jOjf3Xx
         q3aA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bqDLoatR6w/a200qS2PafAY9N/LXt42lhD5pp6cvmU5IS3F0T
	yaVmUsthT9DnsOI7/8NvLww=
X-Google-Smtp-Source: ABdhPJxTiUeegk5ixk1xP0qLMmzULXBhEwSIkRgSpYPc/aZ71/NGG/1GR5mPVTsbn2TRsh6VDygJ9Q==
X-Received: by 2002:a17:907:2daa:: with SMTP id gt42mr12865992ejc.704.1643047374622;
        Mon, 24 Jan 2022 10:02:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5190:: with SMTP id q16ls5745920edd.3.gmail; Mon,
 24 Jan 2022 10:02:53 -0800 (PST)
X-Received: by 2002:a05:6402:51cf:: with SMTP id r15mr16835222edd.213.1643047373859;
        Mon, 24 Jan 2022 10:02:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047373; cv=none;
        d=google.com; s=arc-20160816;
        b=zYj6ox0+BGz2SoW60+ir0Ymv8T+1cC/cD7hWTCpTYNIYqBSiI2fgItRVWFOOvd03UP
         h9XN8L+juIO3hiFSXOZntb1gn06V6kmPVg9RqbCb+WhJbYQhqkfCa9anaJjQlrh8MeSN
         48WRD7WBqs4UTifiGnpxnMLPN0bV8DMkZQtjvJVE47C8XYYjJ+3o6R54r4WeHuyaxYK8
         8B2IzDwrmG12J7sE4EqmbxH9fvRI+o+S5nDcQZMBXlxR+viD6+64Q7mck5vAcfsC5YZ1
         nBfFfOdxeKegFYxaWDZQaAdRCfqFP/CbxdAJmoeCPnxKH98+wbbfAt5W+l8os1UFkSYq
         I4tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=GbVJ1msdnw8aUuqkUgFBeXnijUIniHfkygukcEQkJ5A=;
        b=enfch6Jk/FikuyYwCQPh402/86AOs/UD6WeTqB1LNXtYBuXrbcQKvKbqANDe4UJQH3
         KbvyTtfGpeahZFBH/CVVQAglBoCsj8PyQVZNjQ+HeWVKHfsz5AfiOmFgieTZKiuUcOYb
         Kc0DT6UIkBimePI9UXy9Y9yi8iQqDS3T3QBL4EcKoXG9lrlBj63xCbxTHX0iaU2wLcQs
         8+kNsDz6YKGR3K/OUEwLbgbeArobx51vawQBgEFzkS7Hhr47GI26J49SxK52G2UepL+z
         fxQyAUb7AnNIddStR7JMGUjKadrDuSCw7lOQPqKsdNZRRqqgoBqdj/q8Bl4KLYlP1MEp
         S6FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xVwDGQ88;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id l16si674489edb.1.2022.01.24.10.02.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:02:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 00/39] kasan, vmalloc, arm64: add vmalloc tagging support for SW/HW_TAGS
Date: Mon, 24 Jan 2022 19:02:08 +0100
Message-Id: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xVwDGQ88;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Hi,

This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
KASAN modes.

The tree with patches is available here:

https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v6

About half of patches are cleanups I went for along the way. None of
them seem to be important enough to go through stable, so I decided
not to split them out into separate patches/series.

The patchset is partially based on an early version of the HW_TAGS
patchset by Vincenzo that had vmalloc support. Thus, I added a
Co-developed-by tag into a few patches.

SW_TAGS vmalloc tagging support is straightforward. It reuses all of
the generic KASAN machinery, but uses shadow memory to store tags
instead of magic values. Naturally, vmalloc tagging requires adding
a few kasan_reset_tag() annotations to the vmalloc code.

HW_TAGS vmalloc tagging support stands out. HW_TAGS KASAN is based on
Arm MTE, which can only assigns tags to physical memory. As a result,
HW_TAGS KASAN only tags vmalloc() allocations, which are backed by
page_alloc memory. It ignores vmap() and others.

Thanks!

Changes in v5->v6:
- Rebased onto mainline/5.17-rc1.
- Drop unnecessary explicit checks for software KASAN modes from
  should_skip_init().

Changes in v4->v5:
- Rebase onto fresh mm.
- Mention optimization intention in the comment for __GFP_ZEROTAGS.
- Replace "kasan: simplify kasan_init_hw_tags" with "kasan: clean up
  feature flags for HW_TAGS mode".
- Use true as kasan_flag_vmalloc static key default.
- Cosmetic changes to __def_gfpflag_names_kasan and __GFP_BITS_SHIFT.

Changes in v3->v4:
- Rebase onto fresh mm.
- Rename KASAN_VMALLOC_NOEXEC to KASAN_VMALLOC_PROT_NORMAL.
- Compare prot with PAGE_KERNEL instead of using pgprot_nx() to
  indentify normal non-executable mappings.
- Rename arch_vmalloc_pgprot_modify() to arch_vmap_pgprot_tagged().
- Move checks from arch_vmap_pgprot_tagged() to __vmalloc_node_range()
  as the same condition is used for other things in subsequent patches.
- Use proper kasan_hw_tags_enabled() checks instead of
  IS_ENABLED(CONFIG_KASAN_HW_TAGS).
- Set __GFP_SKIP_KASAN_UNPOISON and __GFP_SKIP_ZERO flags instead of
  resetting.
- Only define KASAN GFP flags when when HW_TAGS KASAN is enabled.
- Move setting KASAN GFP flags to __vmalloc_node_range() and do it
  only for normal non-executable mapping when HW_TAGS KASAN is enabled.
- Add new GFP flags to include/trace/events/mmflags.h.
- Don't forget to save tagged addr to vm_struct->addr for VM_ALLOC
  so that find_vm_area(addr)->addr == addr for vmalloc().
- Reset pointer tag in change_memory_common().
- Add test checks for set_memory_*() on vmalloc() allocations.
- Minor patch descriptions and comments fixes.

Changes in v2->v3:
- Rebase onto mm.
- New patch: "kasan, arm64: reset pointer tags of vmapped stacks".
- New patch: "kasan, vmalloc: don't tag executable vmalloc allocations".
- New patch: "kasan, arm64: don't tag executable vmalloc allocations".
- Allowing enabling KASAN_VMALLOC with SW/HW_TAGS is moved to
  "kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS", as this can only
  be done once executable allocations are no longer tagged.
- Minor fixes, see patches for lists of changes.

Changes in v1->v2:
- Move memory init for vmalloc() into vmalloc code for HW_TAGS KASAN.
- Minor fixes and code reshuffling, see patches for lists of changes.

Acked-by: Marco Elver <elver@google.com>

Andrey Konovalov (39):
  kasan, page_alloc: deduplicate should_skip_kasan_poison
  kasan, page_alloc: move tag_clear_highpage out of
    kernel_init_free_pages
  kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
  kasan, page_alloc: simplify kasan_poison_pages call site
  kasan, page_alloc: init memory of skipped pages on free
  kasan: drop skip_kasan_poison variable in free_pages_prepare
  mm: clarify __GFP_ZEROTAGS comment
  kasan: only apply __GFP_ZEROTAGS when memory is zeroed
  kasan, page_alloc: refactor init checks in post_alloc_hook
  kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
  kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
  kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
  kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
  kasan, page_alloc: rework kasan_unpoison_pages call site
  kasan: clean up metadata byte definitions
  kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
  kasan, x86, arm64, s390: rename functions for modules shadow
  kasan, vmalloc: drop outdated VM_KASAN comment
  kasan: reorder vmalloc hooks
  kasan: add wrappers for vmalloc hooks
  kasan, vmalloc: reset tags in vmalloc functions
  kasan, fork: reset pointer tags of vmapped stacks
  kasan, arm64: reset pointer tags of vmapped stacks
  kasan, vmalloc: add vmalloc tagging for SW_TAGS
  kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
  kasan, vmalloc: unpoison VM_ALLOC pages after mapping
  kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
  kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
  kasan, page_alloc: allow skipping memory init for HW_TAGS
  kasan, vmalloc: add vmalloc tagging for HW_TAGS
  kasan, vmalloc: only tag normal vmalloc allocations
  kasan, arm64: don't tag executable vmalloc allocations
  kasan: mark kasan_arg_stacktrace as __initdata
  kasan: clean up feature flags for HW_TAGS mode
  kasan: add kasan.vmalloc command line flag
  kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
  arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
  kasan: documentation updates
  kasan: improve vmalloc tests

 Documentation/dev-tools/kasan.rst   |  17 ++-
 arch/arm64/Kconfig                  |   2 +-
 arch/arm64/include/asm/vmalloc.h    |   6 +
 arch/arm64/include/asm/vmap_stack.h |   5 +-
 arch/arm64/kernel/module.c          |   5 +-
 arch/arm64/mm/pageattr.c            |   2 +-
 arch/arm64/net/bpf_jit_comp.c       |   3 +-
 arch/s390/kernel/module.c           |   2 +-
 arch/x86/kernel/module.c            |   2 +-
 include/linux/gfp.h                 |  35 +++--
 include/linux/kasan.h               |  97 +++++++++-----
 include/linux/vmalloc.h             |  18 +--
 include/trace/events/mmflags.h      |  14 +-
 kernel/fork.c                       |   1 +
 kernel/scs.c                        |   4 +-
 lib/Kconfig.kasan                   |  20 +--
 lib/test_kasan.c                    | 189 ++++++++++++++++++++++++++-
 mm/kasan/common.c                   |   4 +-
 mm/kasan/hw_tags.c                  | 193 ++++++++++++++++++++++------
 mm/kasan/kasan.h                    |  18 ++-
 mm/kasan/shadow.c                   |  63 +++++----
 mm/page_alloc.c                     | 152 +++++++++++++++-------
 mm/vmalloc.c                        |  99 +++++++++++---
 23 files changed, 731 insertions(+), 220 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1643047180.git.andreyknvl%40google.com.
