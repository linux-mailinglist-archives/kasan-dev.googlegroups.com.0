Return-Path: <kasan-dev+bncBAABBMEJXCHAMGQE6GB62SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E6D6481F76
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:49 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id bn28-20020a05651c179c00b002222b4cc6d8sf8443588ljb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891568; cv=pass;
        d=google.com; s=arc-20160816;
        b=vVE+WHMsDEQ/37dcFNUATEy4H6Qgh/oGrGzDABRvECB39MDEi9JIS4cYtSYH3R/hLr
         9ckj6nj8S5G4L0CxamVdm+K81PKsGJdZ+feEtR1jtZqVZZ5x0LZ/AAeohAoYjRF4g0+A
         HdW0iWuycWgQCm60idSw52QEfyWqbqmLlRUwXSrMQzyVeBfMVhAgAIJBusZWJBbSpiXX
         xnEcE+BEmy5h5l2AxbMDh5LRZBz7xlLxfFBhJUtYjV8F852JQt0uPPsEkJe5uq6QhV6i
         GWXu6VjZ8HAVnwwgYTvXJR0opevz8nvwonn3/OatRq7mQt1RF4z6IIPL3nPJbm4A7D2H
         JciA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Mrrgnw99laJb0qYFbc1vwxgLK4UsgE6A1RDyq4usZic=;
        b=ae2TBPv6zcZuHfYxelwX0Xe11/1zPRpy514oBMSVSnz6q5YGsxOkcLvnaWpDY7XAFo
         qBpCP0uhAeuLKKxRDkpuEqBoV528G+mQwYwRHhw78t1WXVTGif64SbFx8qi6vwB7v04j
         nu6HTmGNzq4Cgx/j0ON7dtSkUELv4vKVluuRkqGaWP8y974gvGjaALTBEJR93DLPg7pR
         MLo6XplLqIEfVjDH07hmZdI24D7MoW5odgUcqlewc8eCldckNIR5UlUFYGy5xAUHwJft
         ZcT0tfzU1KYkhOyVNyP/5rik5Bq5yPQZxDBOyVVs2tbcTYbnW/OmGvqWRJ5zsgkHubZY
         OqvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=np1HMaAQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mrrgnw99laJb0qYFbc1vwxgLK4UsgE6A1RDyq4usZic=;
        b=ZhiassY0TrAnt+F03FqMS+RO0cMVWSbwRfVAy/gnNWNaRSfrxqcr6Rn4UTyVlrncbA
         rYAEQyQXt9aGFwHesjEq5B/vPFOt8Kjni1CrS9Sd2YfbWc+M+zYDCb9/1lH8PxvZAc7K
         YUy2CZerbtf8UBM+I6a+S1fIO/4e+Ct1nSOxngZZElKh6tUGXD3HrpTQGgAl94hSM0h2
         vDvfIHHDLgNsWUAsn+ldO0/1gTvlr7IRCDvw6pmZTbr0eDTIkc5l32MjEtbhfgXFcv93
         OgcKAkzZCsHWkGKr4LigISd76bdi/7Q+S+tCmRDDpx6EJwoF0mNl9FA15fMz7VnhNjXz
         iJfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Mrrgnw99laJb0qYFbc1vwxgLK4UsgE6A1RDyq4usZic=;
        b=NpjpzTo9upxTRycEnZSxOe6acxY14XIAzRe9Lj3Ze8vzD6v2G+GucRCychSAkrB+r+
         izkFsSOAJdG21O8CJ7oOHNhYHH9k6oiSzHTGa4Pibvf8A30JK66US90dxNXrjkHIho7h
         wIpqt8hF1Dr+hlCzWWKvLwNs8QJ3ZOdVbI99MMPLlU1Z9KEf3v31zbVXPFzim0W8FDXE
         HV8sNc3ZLykJFiQOlY3kNkO/DwZX+SibG36Pl019lmnefbT3JuT6xfcdLtdWyy3RiOG5
         a180w2s9cVCyvamYfZYY9Sl033PEFF4QZzxv6rc8VwF9IdISYMsTHNXWxJS8VFoCHVoo
         WEVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rxky3N2cp3sNTswuOe+ZjiZlQMCpoTEubsEybVSm+RGAZeFem
	/e2lH+0wPeSpuEhrnWCUEOQ=
X-Google-Smtp-Source: ABdhPJxLUmOulZzy6AZTVWwUtQbFpWWjHDq4r1WRdyTX8bWtzJPbaRMfg3VKYvt0n++fAhYkZfZGGg==
X-Received: by 2002:a05:651c:246:: with SMTP id x6mr27418541ljn.24.1640891568520;
        Thu, 30 Dec 2021 11:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0b:: with SMTP id k11ls1837900ljq.6.gmail; Thu, 30
 Dec 2021 11:12:47 -0800 (PST)
X-Received: by 2002:a2e:b893:: with SMTP id r19mr18076591ljp.464.1640891567604;
        Thu, 30 Dec 2021 11:12:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891567; cv=none;
        d=google.com; s=arc-20160816;
        b=Kwf7oIqZcRR+io4QS4R+ioZxDCbbNzNA8eK+wnr220OquDzFR3bB+WWtDXxWFjh22K
         kTJlOHet9c2ddTQbjrTyVYFHlFje56NBoYDwaTRT2GgbhAy/ny2Faqw6Cxj/PzYnDFkQ
         sJNrYnEBPlm9jUp0g3sYkJpRf5cPIS7x+jOmoyfrHjj75BFDrlkkH4OAadz2Byyu2wDr
         S/ZeygLIimH/Dga0XOnMxgq37XBb3X/Y73LkOwkR3lnwL5PjovHrHKDQ+PrXvWWWtkH7
         cviGxUXO7amczcWNtXDjAnYIrvKqHeTEkapbxanxQay8o+xYmycvBC3WcWCXbaEsGwBd
         MXrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=BxXk+lPKIYPO8LJ4HIf1Lr8qWbs9W4BbC4wotT6dbm0=;
        b=FEwVzmIX+m6XhhguIi0kaXzqyZz5fCZuhNYHk/rNsxj7BGsBxCaRss8ElMY0Lf0X+n
         11oFYVdCheSNAREvSHwND5+79FaRw6cOdgrcrKzJ7P4CgbuToOW18pklABoj6niMaYIZ
         aaN8ZxwfJR/mgx2Xg3/uzJ9OKcNO1n6yrksdoo9yu//gO5gJuF5TjnZS+SJtb/0gsB7r
         HduDdlpkdZmXOkOv0UcTLwsADiCQM+hf0Wwx//7q26gRPA+9TXt40lfMZ5eUta8kDlmi
         FS24EStnGuxs369+yn2+i+3moOcCnbOXEfcsRyAZhoB5fyOYoZUDSw6yl0KfpF5lSoix
         TpJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=np1HMaAQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id c14si1165463lfv.13.2021.12.30.11.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:47 -0800 (PST)
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
Subject: [PATCH mm v5 00/39] kasan, vmalloc, arm64: add vmalloc tagging support for SW/HW_TAGS
Date: Thu, 30 Dec 2021 20:12:02 +0100
Message-Id: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=np1HMaAQ;       spf=pass
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

https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v5-akpm

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
 mm/page_alloc.c                     | 157 +++++++++++++++-------
 mm/vmalloc.c                        |  99 +++++++++++---
 23 files changed, 736 insertions(+), 220 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1640891329.git.andreyknvl%40google.com.
