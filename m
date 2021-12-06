Return-Path: <kasan-dev+bncBAABBM76XGGQMGQEWQKB4UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 510F046AA5A
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:23:00 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id u28-20020a2ea17c000000b0021126b5cca2sf3814482ljl.19
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:23:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825779; cv=pass;
        d=google.com; s=arc-20160816;
        b=rWHKj0F4+0743xPW4bduTzdMNi7VcaHalhnfAbThFwng2N5ef+L/2QgGBt7Ln8bgbV
         yXMsC7fKTp4gfbCtZUatucln2/xCSRZVmzW+dX7UPud1+n9JlU2gaO8AcbUwDEsyQ6zN
         uD0CKuKqsGiFcsOyT3YUfUg54SOMJGxEBeSPBDFc5fPiEMiIzBIbQgxiV4Y1Q2C31CD8
         SFff/KOCSPDNyLCHDheKXiRETy4h0G2nFCXWV7LoKZIKFZCxPdXJKskXcSZmS+bVXvvO
         G7A07+nkc5gpO27SmVczGewG4QwivOieEMrkNxAoYWC+WgcSjpLN+NqwoAS4axuVGGr4
         JktA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=I23vwlRx3IlO/WNV7tvEl/B/0qNNLf6EuJhHIvMIlqs=;
        b=zZb50MLWmiHl3mYv1pKtgwHFOV1iQjT/R2a2hdUhCJIMFrvH3ggJZRnYrf0ZRsDr7h
         ssUePkK3TNr8ZdcOWAhCNdTQMPxqZdr29lmva/Rnq+oy1DvpDih4WqOty3QDwn7RydUu
         JCD2vZlTZLhZ0WgEglk9eRAU+yxpATSDrnlHaBc3RWFKjPJfSDWLMqCj4HOqG/mMeyT8
         21k05aCVtBO7I/C5co1KJDDeAjd7P4Gs8YwTLU2AGDoXY51+MzVTeyRhOkKTyeS7GVJh
         jsQ3p0ExthFbjOylBQK46AJP7h7FL+xghK77UVR1lyow8TDipOxUbz+8zDGT3souIh/g
         wh9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ov4ZlEF7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I23vwlRx3IlO/WNV7tvEl/B/0qNNLf6EuJhHIvMIlqs=;
        b=DQphHqVV/WUzyEdv6gtw/CaYfwEQu1KH4LxW2+ZkWcDOT84FzxqmsyoXp8P6uTRMjJ
         aw7xKJNZNxERlOTR190F7+UzCxxi9L6CBH4tweca7XkqbR1SkXDVfo9aSOogYZ37Cb8m
         kDvoTX3Q3b/CiidtnZXXWhJRnQXSKMskOY+n2dArfU+yxi0z0oSFyCbhTPovnFu5EOJa
         9xX3+yFRQRjwv9q9gWtxZWSV4Lo9wSUxEnRhjlTgQWvbB/Bj8VzvIKdMkhcQ7zM/VOMV
         NuM4KUVHRQQYLnb/3aFrxXfVKtQDK+Q52HQUHCl0HTTjCCMPdboEVANc49VAJRW/r2O8
         zTcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I23vwlRx3IlO/WNV7tvEl/B/0qNNLf6EuJhHIvMIlqs=;
        b=VdI6S5Eea1FvAX/KY63BIMiKiCqRr2AFt8riR+JbRyuEMGN2Gx6LRxSl6qfbCu5dWy
         tyCscewtfOuLKYZm7GMyy9PiGhmG4oMuFeEg0clIjqw0yNU2fxgpNrIXSjeol9zwohwf
         VTD9GsMhW5axd/Wte6j/5SxJr9096wDDLHc9Pc9L/ikk3BIWT714nNRaBAqLYk6IEGqs
         g/9OGUhy4h1AGgWd6UC5otmZqSTgioQzXDTsIYG0/dZ38ZFjK2Wh1G5HmWd2xwU5+BxY
         0b2VWoZjcxFTgaYrE4QXXx53YP18o8FLDrZgKn5xGeCSsrYxC+oyxJfsPbaP9dYv2eWR
         w/zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OwybFEpEPNU54itTrv2X2eCaDvMDgiha0WJaHb4QfGtPKYVan
	mm8kYk6AVqgG8UH5yTox2WU=
X-Google-Smtp-Source: ABdhPJwXZtMNlLYHYqIpWPY2rXIXlGDl3B9X8XFCen329JYxlXCu4sH7yMsnyottJC8hDfsMo3UVMA==
X-Received: by 2002:a05:6512:b15:: with SMTP id w21mr36994026lfu.11.1638825779747;
        Mon, 06 Dec 2021 13:22:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b1f:: with SMTP id b31ls2811901ljr.0.gmail; Mon, 06
 Dec 2021 13:22:59 -0800 (PST)
X-Received: by 2002:a2e:8807:: with SMTP id x7mr37651932ljh.490.1638825778923;
        Mon, 06 Dec 2021 13:22:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825778; cv=none;
        d=google.com; s=arc-20160816;
        b=BUDVn/lyv7NrKeDAO8+yok5U1sDNWCboddsxYinPnLaHpLyXHMrrRwX8wILa/1q7ya
         yQ+sc3AnkKaCy9gvmvCZC6OrfNLxtcf989SR8JA5hWXniUfnB0ZHQNKmtG57fVMVXhr3
         ML8/2U+0jEwkqxxOCopg7BI3F8cvU9Lt1N2tMtPvpupKfm45JRZc8j2nX48JxcIHmbRV
         yZ1DWpw8GyBVQl2Hvrbhgd2S0dV0VMxvT60AEX1jrBwHXkd3zUOLaPAQtpWxLW/t8ZNq
         F2AvVEUHy2ewD2kD06bopOlaW1FONrae2tCpnyTj/LfWmOf22Mka/Hxi5n2mY/y3Pr2c
         LgWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=bUuIlOralgF5wobuBntA8UszOUI4AIJ5c+Gdq5HnW/w=;
        b=zI9oDrTYhxD/uWhVSby3CR15knY0Jr+Tqs3J6yGCt6TldB4Y75/yGcSUjyG/tX/ZDh
         Brjd+eiUZ2sW/FsSwp3ELizunuH9lyediKDbGXJfCOg4jplwZ9A8N+iqPlMe+vKHcDJI
         yi5XgBim7Lh4+h0F5D7IA6t30K0BBSusdk7T1OByln2TdneZ2BipZVjjy8LMrr2fdLiF
         kFOucvKTjGjYBD0M4va0zYM7hHIBMRSXeHNdPoDyB/5MmXQhZ517H7R6E8bIrdn/2Pco
         QdxHq/CxzcHZQkmwH4oqmnw9OywwUtKEld00j0M3lX5ScQGbg1pPYZ5ZQ7tYZUFMdmy7
         t4Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ov4ZlEF7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id l13si716442lfg.1.2021.12.06.13.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:22:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 00/34] kasan, vmalloc, arm64: add vmalloc tagging support for SW/HW_TAGS
Date: Mon,  6 Dec 2021 22:22:04 +0100
Message-Id: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ov4ZlEF7;       spf=pass
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

https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v2

About half of patches are cleanups I went for along the way. None of
them seem to be important enough to go through stable, so I decided
not to split them out into separate patches/series.

I'll keep the patchset based on the mainline for now. Once the
high-level issues are resolved, I'll rebase onto mm - there might be
a few conflicts right now.

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

Changes in v1->v2:
- Move memory init for vmalloc() into vmalloc code for HW_TAGS KASAN.
- Minor fixes and code reshuffling, see patches for lists of changes.

Thanks!

Andrey Konovalov (34):
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
  kasan, page_alloc: simplify kasan_unpoison_pages call site
  kasan: clean up metadata byte definitions
  kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
  kasan, x86, arm64, s390: rename functions for modules shadow
  kasan, vmalloc: drop outdated VM_KASAN comment
  kasan: reorder vmalloc hooks
  kasan: add wrappers for vmalloc hooks
  kasan, vmalloc: reset tags in vmalloc functions
  kasan, fork: don't tag stacks allocated with vmalloc
  kasan, vmalloc: add vmalloc support to SW_TAGS
  kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
  kasan, vmalloc: don't unpoison VM_ALLOC pages before mapping
  kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
  kasan, page_alloc: allow skipping memory init for HW_TAGS
  kasan, vmalloc: add vmalloc support to HW_TAGS
  kasan: mark kasan_arg_stacktrace as __initdata
  kasan: simplify kasan_init_hw_tags
  kasan: add kasan.vmalloc command line flag
  arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
  kasan: documentation updates
  kasan: improve vmalloc tests

 Documentation/dev-tools/kasan.rst |  17 ++-
 arch/arm64/Kconfig                |   2 +-
 arch/arm64/include/asm/vmalloc.h  |  10 ++
 arch/arm64/kernel/module.c        |   2 +-
 arch/s390/kernel/module.c         |   2 +-
 arch/x86/kernel/module.c          |   2 +-
 include/linux/gfp.h               |  28 +++--
 include/linux/kasan.h             |  91 +++++++++------
 include/linux/vmalloc.h           |  18 ++-
 kernel/fork.c                     |   1 +
 lib/Kconfig.kasan                 |  20 ++--
 lib/test_kasan.c                  | 181 +++++++++++++++++++++++++++++-
 mm/kasan/common.c                 |   4 +-
 mm/kasan/hw_tags.c                | 157 +++++++++++++++++++++-----
 mm/kasan/kasan.h                  |  16 ++-
 mm/kasan/shadow.c                 |  57 ++++++----
 mm/page_alloc.c                   | 150 +++++++++++++++++--------
 mm/vmalloc.c                      |  72 ++++++++++--
 18 files changed, 631 insertions(+), 199 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1638825394.git.andreyknvl%40google.com.
