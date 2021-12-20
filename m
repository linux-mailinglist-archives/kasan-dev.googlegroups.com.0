Return-Path: <kasan-dev+bncBAABBIXZQOHAMGQENEM3DZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E86147B56C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:58:59 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id z13-20020a05600c0a0d00b003457d6619f8sf553345wmp.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:58:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037539; cv=pass;
        d=google.com; s=arc-20160816;
        b=vf6pRDPDj1y5hUNHeTC8lN7Ww9++D+egz90KsSO05k26uhPRkqM05rNLi41O8Pmy8T
         5ffN3AViHtzGkWxdBGVST71iQch94AxdB+YoYK6YeSD+Pur18z5N7WVU+/k6Fj87e5I1
         yYPa2/U7qa5D8W9pqt6/748cW5Go9VDy/btZQEZxXg2xp7M/gTua8gpEITxxvhl9tuy4
         PLGShyzIvjk2XDYYjaKmcZ6DfUfeYGrRh/+bn/nHbCsflwR5KLoNu916jasimpho2qXv
         3m4x+QZ9zzTN5fZi6566z48m2NDmSbAjJ4eNSWCE+LeBWNxfasTdA9rKjuUEIVwWilvQ
         TmhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=v/EuTbHlWHXSsvXy2svUuX7DYn/UY+rBUVKh7IqKFTw=;
        b=aqoDIKUp0q8TuUhpEJulIGxq0KjzLl3h6GJDKYTvaLXT9b06M/7AR3DzOF13JcoFJ/
         kotPzGcchSb5xC2v32WJtfsbaqglN8to39SpswJN3DNYD/uaEwKGlQ2Hs4tEQ0Y5lwhu
         /tngrhCoTVtPNUGslMRwDunosTBIOhuO6GWQie4wEsUJ8Wqv4UFm6oNCoBX1WPiEN9zf
         EEype3wP8e5altYbNXd3BCPjHcA5gPqxi2zjvszBym0WEfyuP3Q2XIYQ4KfetCZKnjC+
         JqlkRjo7STMw9558jAqBRfNxRzclfOoJbkipX0gOV8QiwxfymNaf4uc6e4QA/iI4YhXX
         S21A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DO86EmQz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v/EuTbHlWHXSsvXy2svUuX7DYn/UY+rBUVKh7IqKFTw=;
        b=SBfXivR+aurfjdkxEyi3XqdLjXuKUuqAprlyh9DLpOwS+VG7F1LNoGc5JUQbvC8YuD
         al5t3mB9OQCNCvUQC1Kj8aWka9X2PMyfefFraIhIDjaaNx+6PRmmMFspvQNhsxXLP6L1
         8BQlJ9Zt8eZLDxwwZNvxx+4TfEY3SPDtjuEOI7N/JG6VZ6v6Ied/5wYtJ1+42dUSIDXF
         eUNN+CH2VgOCHW9uN20oFuovA9XyeM4KJ8Fp+cAr55j3cTlWjx6nNQ+prBYxKHsTGTiF
         SrKyefL1zGlDIfVjcL4ItjrTsHEeodpYc2ZH8WH3decx7xjKvj+q0NMFRBwAWwOeilRl
         1yIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=v/EuTbHlWHXSsvXy2svUuX7DYn/UY+rBUVKh7IqKFTw=;
        b=AIkS/ziFst+0khHtjBY3ch8CQ8JUykz44Jfdz+PrrmjhAaMqO4LAAaXq+ItYeJrMVJ
         de2wBp5/dFLuHEZABSrTKWREe5crPV8/QwvZNR1F6ae0HlGeOLmkdF3k/ZcIO8kfwYwa
         wP/eSNt6H1qN5VmpkVsVtbtx9CUzj9v3Bq221eAhErZ3xe+QS4XiPEdLMmpzGzFcLPKo
         9sut1qfHn3iGjdJ0ZhDydtkqvrxIKNrUzHCCSsFuGfTYeTbQjg6KAkPlejDs8btYTdra
         636hpfNy7pXrvgUf/m4ymxgN88RDbEKNmkfgGE+y9Y0tx7imdcZDjYViZ7Vw0+y8LSEE
         x90w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532brArlNmAl3DGJl5pMLsCIYdzj5tRNYTQtUKLsY0ainLCpAuy5
	DPcswMU+uclORnnhpfhXlBg=
X-Google-Smtp-Source: ABdhPJxnyNHNG51XuX4HrUmxsHim+O3vrul8vP9i+1Qm7K9BLKD6PAexT8wrjAG3gO/AaMvfeDe84A==
X-Received: by 2002:a05:600c:a54:: with SMTP id c20mr59802wmq.48.1640037539057;
        Mon, 20 Dec 2021 13:58:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1062338wrb.2.gmail; Mon, 20 Dec
 2021 13:58:58 -0800 (PST)
X-Received: by 2002:adf:f150:: with SMTP id y16mr114197wro.176.1640037538372;
        Mon, 20 Dec 2021 13:58:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037538; cv=none;
        d=google.com; s=arc-20160816;
        b=OOxcv88wP91anV41N8uLl1WczxfpyAVpTotHCfuN1yGywnpzLxypFTByakAT3ZMted
         ZQOFXm+kke+Blps5JKzPpHPxSEVDNbzmEMX8sSqGKhsQ305ukDZD9Hav6Rb7Aftn8jZr
         IN5Gp3kLH6bvIKcAW8orm7hZFDEyO18s5lqGdBTfXlTptporNPIFI6j6Ik9ndX8yTyfW
         hX6BeXlXPIvFFWQZjiwg2xzvQeCewCYgmXSDZV8PkuQDYDZF+/gKdFjzqplYgYcpXTdU
         mNa55n3gxQuvMw7r6nVIQJuqlBBBtFd/ne/Yod2KHAV2XbtUq76B6AU4j66l8S3fKFTs
         IGew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=wFLMQEsPdiKisCnArFXJzf90NsxTel/o3MOusffYrQE=;
        b=f5YbIxdF3WkIPreZlUeKJ/CeAGNOUnbXWvcoNr7I8A7gHgG4uy8DC/3dwnLI9jhNU+
         QsnVvLdwEbsMFOZLnCNcHDVD8nsSDLUVUF6Xye3p/g+Aa5CM2TGTVdVWpfcItjJWOuEX
         8w2xejsODQfHy9E4K2nDyhDIPG/HnH3vOEGlgttVh+NHYtfpiQEGq0Fmar2/3LuF6QhY
         QKxhu6R6w3IEZx3gln8AAAipa+9NrB8yxeSJs6KgAbIlCaBrcfhxB91tZhTUTpBlcRWI
         YQLkMGqTlz/1aW2VABMN927DlES6fUNdrrPYmv+Gs5pFjmXgojRRJtiMihthftzuQJGZ
         Dffw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DO86EmQz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id g9si223653wrd.4.2021.12.20.13.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:58:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v4 00/39] kasan, vmalloc, arm64: add vmalloc tagging support for SW/HW_TAGS
Date: Mon, 20 Dec 2021 22:58:15 +0100
Message-Id: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DO86EmQz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v4-akpm

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

Thanks!

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
  kasan: simplify kasan_init_hw_tags
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
 include/linux/gfp.h                 |  38 ++++--
 include/linux/kasan.h               |  97 ++++++++------
 include/linux/vmalloc.h             |  18 ++-
 include/trace/events/mmflags.h      |  15 ++-
 kernel/fork.c                       |   1 +
 kernel/scs.c                        |   4 +-
 lib/Kconfig.kasan                   |  20 +--
 lib/test_kasan.c                    | 189 +++++++++++++++++++++++++++-
 mm/kasan/common.c                   |   4 +-
 mm/kasan/hw_tags.c                  | 167 +++++++++++++++++++-----
 mm/kasan/kasan.h                    |  16 ++-
 mm/kasan/shadow.c                   |  63 ++++++----
 mm/page_alloc.c                     | 157 ++++++++++++++++-------
 mm/vmalloc.c                        |  99 ++++++++++++---
 23 files changed, 721 insertions(+), 211 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1640036051.git.andreyknvl%40google.com.
