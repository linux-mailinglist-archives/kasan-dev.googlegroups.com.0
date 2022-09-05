Return-Path: <kasan-dev+bncBAABBMWJ3GMAMGQECA5BGTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B1F315ADA8B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:05:59 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id h133-20020a1c218b000000b003a5fa79008bsf7910668wmh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:05:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662411954; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQ59yM5b3TTnx/CRoPNiAd7KrDR+WVcbrZov5YxqK64UHsyS3FkHhaTcPTqptjx06Y
         W/uhXqAmuPabjoNvZd6U7W3p5XLCVzQK7a1QcZZjod0f5vfXPfzEkpcF/+jznPQoSvkl
         m8WIb31yo7sy6p122bWd32WpqqYq13gRbf+JItMD2zuVLSxMrgKkM2U+l1cLkeiuaWJ/
         P6D2JRDkGfk4bAvxVvONmMP7CFcmdlIk1Bg3MpzxxAY8YMREA6rvk2jjsoRD+pX6Wizn
         iV7Tr6sXdf0dA6Q4r3yjyx7xPpBTdMF7Lf/DjcbknIfdmcbqYgeUkblxbZwEjIFHEvqZ
         0TbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xniCEqh8MvR5VSWLzyhMu852A7XKvplQBmYNYzXkMYs=;
        b=Vt5LhuC4k2PkjGCykaeB9f64/W5PCW29NyrUUqbEKj/3kVqQucREtBSZ0xMWNuswel
         avsKywUrA+GpxtaUdM7HnjLiOwP2/KTnHXMbBt8PjIzFmsmiI/1FKljE3FwrzwmXKdjn
         FMqTd0PXAIi/mpZf2BdxpcWIMo/h3ziEN5dDheX49u56+1YMNm9+ZQOxSaBF8m5soPWu
         1PsYSJalsZUWi0VPL0SWYz1O5OE7nZYY4Um90OIa1skwWvRXUTJwNlgoXlbBdvubGWVU
         k8slm53UflJaZqmCpLl19N8pysCHe5PAg+0X+UcBX2vvuWuK3npyaDXvvXqS1X/gbs99
         QgSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qOtF8iDA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=xniCEqh8MvR5VSWLzyhMu852A7XKvplQBmYNYzXkMYs=;
        b=WdYCC6Th4CuNBwz7My+19vFUuNf4NjLiNwhO5CaSsRqVKZMo5DN0bl7s9V8hT6fXGF
         U+pBoLB4iDG+BqWJ3avH5FrOLFZNZ5TC/o/g8YIkYPak7m8ME9bV5Sgdal5jk+Mb3TeG
         1SX/+jQwLGxotehS9Asys/AG3ion8lFwAIdEqAXnwooIVdIkEetxOaJZiBbQP+Lp9FZm
         Od5zHl0dOpHzVFkKBeyPwfxHtRuiCY5UmlhXwQ+p62o3XiRrspU7MeVN/Ce4QHoYwDJH
         gv/F+WjxoT64/AjX1EdvSr9deSH2xRH/lj5l5C53kCPL1tgh6GFe2Wgme+LbqRP9Y7jo
         zjqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=xniCEqh8MvR5VSWLzyhMu852A7XKvplQBmYNYzXkMYs=;
        b=YhK1TnV4s3bqrzd9y3z23g+b6Vn92/wNB/Bn4FmSRmLWDxanbNl8xIO5Njyq5nmwD5
         /ppm7GW258MlUfz2UiBx3BzaIqZo84nA1ZH7sjTANNjVeeNcLkdOIqT8QSIlpQBAGUoL
         iOG7o7nqKywC+5CoKGXDPfBxPtroHIHfHvgZ/QlwmVWdcwpIOUh5tL0BOv5OhiAWnJD6
         RQnvLuk2LNBHE2IA21UMv0/DGP+JCtzJ4A8s3EDNWobyDgQyKAVCSt2fBVYzWRm8tkUT
         f2IwECpgGtu7AQRLDxKjgXb0u7wo01Qd6DztB1vL0WDmFFwPB1WRjr4dOTEVqYVjW2aL
         UiDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1I06HgmcFNyGipXnTmWzUQvuOGUNDF3oR+Kt2zIJpo+s5xDzuM
	Uk89iT6fpKnADZSmf6UTbg0=
X-Google-Smtp-Source: AA6agR7xdy6amovn4Ol8hIwDNlUKezFJG4kMerKDZUdDwbyAIw+oh6TQVN+Zq1Qm3ZFBv+c7tmvebQ==
X-Received: by 2002:a05:600c:4fcb:b0:3a5:f2cc:2f19 with SMTP id o11-20020a05600c4fcb00b003a5f2cc2f19mr11484068wmq.142.1662411954312;
        Mon, 05 Sep 2022 14:05:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6018:b0:3a8:3c9f:7e90 with SMTP id
 az24-20020a05600c601800b003a83c9f7e90ls5122449wmb.1.-pod-canary-gmail; Mon,
 05 Sep 2022 14:05:53 -0700 (PDT)
X-Received: by 2002:a05:600c:3502:b0:3a6:edc:39f8 with SMTP id h2-20020a05600c350200b003a60edc39f8mr12024899wmq.200.1662411953562;
        Mon, 05 Sep 2022 14:05:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662411953; cv=none;
        d=google.com; s=arc-20160816;
        b=O0+wk9OD37k1e+a+lY8qX1wRbQf06huL05D8VyerQExP8pYThnvVlEy2vgCLBI2o6G
         nbU907UseNof3api10j43a2BAgQ55QFW2vk/tCjBrNlM4ycrOogyDCO2Hv1KekIvPZe0
         ym1jyYAyNpkFlQYDUeAU32tO47He4Hjd6/JI58a7DI/EanE0F18umwEwqba4tkQY6t9P
         HH7Z8gSKhi+H8Qc2JRau+ZqDvc01WfHP/bvFLPy528S78o3uARgadb7MZuqzSEsIUDj9
         ihQnSbiDpKdJDOJKtSxSbstygF+RtLug5ED6LM5A74kVS/V0sDDaTYF2j+GDAji6Yb6J
         mguQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=74N21uct3fvXsjJmGGSQz3ciXrjD4YvE3S6ir9HUu9Y=;
        b=F3jdC5Np4ypKo5IDj+IVPYUfB+dWKkFvgNEPQaP9sabEdJG4t9nhXnEE8c00wDGVhe
         yTD2RspT1zAILDcD4oqKjREEvRKyBr3xGDC+jPwuB7RFuvnHts4XJoSeV6hIx7fVG9/Z
         OyGaKuOilDfVDCd4Ii2uQiUSr5p/BGsF7uGiv6K6+QWdWyITUOwAN/hsu42+w4bD0Oni
         PuG9zFF/fmtPCs3A8D6IsnZZUQQmZ5Qc0r3PS8df0MXXy29IJwIz9ZIg96gKP3veq5mC
         v1KW1Q5zzzKkuudvlznM/dLm0fD/GHYYio3zdtBXGS7x4wPOhw7ZZLTmuVx0HD+pOO2n
         KmZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qOtF8iDA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b003a83fda1d81si986920wmq.2.2022.09.05.14.05.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:05:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 00/34] kasan: switch tag-based modes to stack ring from per-object metadata
Date: Mon,  5 Sep 2022 23:05:15 +0200
Message-Id: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qOtF8iDA;       spf=pass
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

This series makes the tag-based KASAN modes use a ring buffer for storing
stack depot handles for alloc/free stack traces for slab objects instead
of per-object metadata. This ring buffer is referred to as the stack ring.

On each alloc/free of a slab object, the tagged address of the object and
the current stack trace are recorded in the stack ring.

On each bug report, if the accessed address belongs to a slab object, the
stack ring is scanned for matching entries. The newest entries are used to
print the alloc/free stack traces in the report: one entry for alloc and
one for free.

The advantages of this approach over storing stack trace handles in
per-object metadata with the tag-based KASAN modes:

- Allows to find relevant stack traces for use-after-free bugs without
  using quarantine for freed memory. (Currently, if the object was
  reallocated multiple times, the report contains the latest alloc/free
  stack traces, not necessarily the ones relevant to the buggy allocation.)
- Allows to better identify and mark use-after-free bugs, effectively
  making the CONFIG_KASAN_TAGS_IDENTIFY functionality always-on.
- Has fixed memory overhead.

The disadvantage:

- If the affected object was allocated/freed long before the bug happened
  and the stack trace events were purged from the stack ring, the report
  will have no stack traces.

Discussion
==========

The proposed implementation of the stack ring uses a single ring buffer for
the whole kernel. This might lead to contention due to atomic accesses to
the ring buffer index on multicore systems.

At this point, it is unknown whether the performance impact from this
contention would be significant compared to the slowdown introduced by
collecting stack traces due to the planned changes to the latter part,
see the section below.

For now, the proposed implementation is deemed to be good enough, but this
might need to be revisited once the stack collection becomes faster.

A considered alternative is to keep a separate ring buffer for each CPU
and then iterate over all of them when printing a bug report. This approach
requires somehow figuring out which of the stack rings has the freshest
stack traces for an object if multiple stack rings have them.

Further plans
=============

This series is a part of an effort to make KASAN stack trace collection
suitable for production. This requires stack trace collection to be fast
and memory-bounded.

The planned steps are:

1. Speed up stack trace collection (potentially, by using SCS;
   patches on-hold until steps #2 and #3 are completed).
2. Keep stack trace handles in the stack ring (this series).
3. Add a memory-bounded mode to stack depot or provide an alternative
   memory-bounded stack storage.
4. Potentially, implement stack trace collection sampling to minimize
   the performance impact.

Thanks!

---

Changes v2->v3:
- Addressed Marco's comments, see the last 3 patches for list of changes.

Changes v1->v2:
- Rework synchronization in the stack ring implementation.
- Dynamically allocate stack ring based on the kasan.stack_ring_size
  command-line parameter.
- Multiple less significant changes, see the notes in patches for details.

Andrey Konovalov (34):
  kasan: check KASAN_NO_FREE_META in __kasan_metadata_size
  kasan: rename kasan_set_*_info to kasan_save_*_info
  kasan: move is_kmalloc check out of save_alloc_info
  kasan: split save_alloc_info implementations
  kasan: drop CONFIG_KASAN_TAGS_IDENTIFY
  kasan: introduce kasan_print_aux_stacks
  kasan: introduce kasan_get_alloc_track
  kasan: introduce kasan_init_object_meta
  kasan: clear metadata functions for tag-based modes
  kasan: move kasan_get_*_meta to generic.c
  kasan: introduce kasan_requires_meta
  kasan: introduce kasan_init_cache_meta
  kasan: drop CONFIG_KASAN_GENERIC check from kasan_init_cache_meta
  kasan: only define kasan_metadata_size for Generic mode
  kasan: only define kasan_never_merge for Generic mode
  kasan: only define metadata offsets for Generic mode
  kasan: only define metadata structs for Generic mode
  kasan: only define kasan_cache_create for Generic mode
  kasan: pass tagged pointers to kasan_save_alloc/free_info
  kasan: move kasan_get_alloc/free_track definitions
  kasan: cosmetic changes in report.c
  kasan: use virt_addr_valid in kasan_addr_to_page/slab
  kasan: use kasan_addr_to_slab in print_address_description
  kasan: make kasan_addr_to_page static
  kasan: simplify print_report
  kasan: introduce complete_report_info
  kasan: fill in cache and object in complete_report_info
  kasan: rework function arguments in report.c
  kasan: introduce kasan_complete_mode_report_info
  kasan: implement stack ring for tag-based modes
  kasan: support kasan.stacktrace for SW_TAGS
  kasan: dynamically allocate stack ring entries
  kasan: better identify bug types for tag-based modes
  kasan: add another use-after-free test

 Documentation/dev-tools/kasan.rst |  17 ++-
 include/linux/kasan.h             |  55 ++++------
 include/linux/slab.h              |   2 +-
 lib/Kconfig.kasan                 |   8 --
 lib/test_kasan.c                  |  24 ++++
 mm/kasan/common.c                 | 175 +++---------------------------
 mm/kasan/generic.c                | 154 ++++++++++++++++++++++++--
 mm/kasan/hw_tags.c                |  39 +------
 mm/kasan/kasan.h                  | 171 ++++++++++++++++++++---------
 mm/kasan/report.c                 | 117 +++++++++-----------
 mm/kasan/report_generic.c         |  45 +++++++-
 mm/kasan/report_tags.c            | 123 ++++++++++++++++-----
 mm/kasan/sw_tags.c                |   5 +-
 mm/kasan/tags.c                   | 141 +++++++++++++++++++-----
 14 files changed, 642 insertions(+), 434 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1662411799.git.andreyknvl%40google.com.
