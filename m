Return-Path: <kasan-dev+bncBAABBXFVT2KQMGQENMTGK4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id F3934549EAE
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:15:25 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id i26-20020a0565123e1a00b004792c615104sf3502731lfv.12
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151325; cv=pass;
        d=google.com; s=arc-20160816;
        b=weUg9KpIbH/8Zu5MZPqNTUyU8fZYPVTuQokso7CwX3Q26HHUvjZPSjkoWOJpaae0Kn
         luQDPwOpAAAV43UNXOV9yyBCs9zouWRdC903TIsg0X8LNw+sfJAUt/FiS38ieG90mYWZ
         LJfOixvkGMzUYF4nJ3r5kNYhJTj24CvbTv0ANPgkorb6XaIoudnSckGiuh5AXGkju0gG
         I6H+EwPAvMLHjKu77Jk026tAPLBXFK/BJA4ZKjgHhUvwvN51LJcoYGeJGXX7InZ8X07G
         AsFIAyToEOXyWH5P5O2gv7/rsps5BQwy8BPTy4A4cEUBYe6EHnNFJnNKsVeRGbv/5Cxb
         xb+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=78M3oqXTj2dsIYSnCm7r/1lS4uITePkOOJRhHtKre+g=;
        b=G9n1/JbRa/ngQxee80r4UsUvhJu9aoijYAY+3PJ0z9hyyCKWacf4vCiPU0yrIFc1pK
         YHgG/pUPYME8NR77FlMa+tfCetfaNApnFiYe4QX8iAcaBKCSPyY+hmRiUr7syQx3jX70
         QnJnORTVid7xC2BNz0rgfPM5qzpeCMo6YqwIKfSWBtr3h4GpTeTutEzE0Sc6AKKhIuKG
         GyTSL6UZ3uy15Xe+P0wlgX2oH/zZkd/msVhslUj7a92+xStPT0Di7VuVAv8dfzIe8hC/
         3XUxxmghI7GeNwAeh/4Z6v9vWy4FAyoL91KuiJilwho2ZcULJagD98yPcliZZE8J/dZm
         G3Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ArpbYjGf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=78M3oqXTj2dsIYSnCm7r/1lS4uITePkOOJRhHtKre+g=;
        b=DQfMOKFVHWhl6yDeRD3J/av6fYva9e76upp02FFS52fOLSzHyzjEOdmkRS8Vyd4Kz+
         IcUgqMC4KoT8HMEWoBfOwqwaXxv3rxXt/VDt23obnNN/k4eRe4ZLf85snSAjPejV+Sdv
         K0i/JtqQSJO8HD4KDjH+6e1OcEYFXtKa/X1TztIw4neHrR9lyuQeOzEk84Sv/ScTJ6hz
         pWJjbFuFI+onQJv5jxSEfiSINgDqHGl/3YyidQ4gXgYvk5s4oiesjh0YZCZmSDglW1oA
         kX4tqP1/TWrt/RgxeuTwtm565ZkX8ds4PbFM6dznTJsSRulpyMSeD9kDX9svC67csXIy
         ZzLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=78M3oqXTj2dsIYSnCm7r/1lS4uITePkOOJRhHtKre+g=;
        b=kyLT+Snoh3SMiQXa+QTvzf3x5nH3BZiOMxNScAzj0qxMhVLkwNEOOR2zO4QVm3SvpK
         dDq5or9QJe/ti/iLK90voTaYJSMK1EIvWUMAuWlxLiTa5oYpkcvs+l4dRdmF8GhaFinW
         pJZRfTgO0tQIgOgK7/1CMYtFJkJ4tS4vk1BI55RUQ8HIl4fyW7mzG1qwJ0/UN7TLTGOk
         2hq7Liav6UZj/CqRaMmjRV0+ThDaEK63ophdXJbxnyxk290Qa2UgYoJzFjVTkdoHkjLH
         D3d1Uy6qO7MG0ZsAfnI1PAtByEmJjBZSW4V0VE28YhvWY+oSrFlJb1CV2jsbazBNe8OU
         fdsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8hRVlQnolDp3GbEl1XM3dt7VOBpFMmHZvZ00U1ylgixrdi8pI0
	hOsWlnB1bHBycmRLW94o2oY=
X-Google-Smtp-Source: AGRyM1vR3uGGWyW7v+aSR7oRb6ZkLBR5CFwd7YV9hcNK9BN0pKaqEF/UWb/FHb3yO9PIUgUQrx3ZDg==
X-Received: by 2002:a05:6512:3991:b0:479:2e05:2ee4 with SMTP id j17-20020a056512399100b004792e052ee4mr926825lfu.64.1655151325184;
        Mon, 13 Jun 2022 13:15:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:860e:0:b0:255:7ff6:f956 with SMTP id a14-20020a2e860e000000b002557ff6f956ls456656lji.2.gmail;
 Mon, 13 Jun 2022 13:15:24 -0700 (PDT)
X-Received: by 2002:a2e:bf1a:0:b0:249:3a3b:e90e with SMTP id c26-20020a2ebf1a000000b002493a3be90emr632106ljr.317.1655151324327;
        Mon, 13 Jun 2022 13:15:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151324; cv=none;
        d=google.com; s=arc-20160816;
        b=uQp68Qo4724Xwdc1gQUIILUs74m1z/CWdApLgRV5Xg5+0RGgFDHxzJUjsZrGNC/eOZ
         4sbX/6oi8lHeHNwNOYA50QUN2FKaRsc6AgXxi4J2lfRAECSkbLusZlVPUJi2sUQt8TOI
         Wt+xoar7etN4IP4emoUG/+9rX2PJcXA691zKiK9fv7gF5gfH28FOlNP0alQK1mNuRV+A
         dxizfdddRSD6ALHTM3EYI+aCQ9xy+xuYzIpJG5bKf9qikp+RXGB+A0ROF8DNA1ago4Ed
         gmdoBzrINIcoYSMxK7fBes03JtbW5SqAgy2u3hlrKhzzxp+zYh8XtygG7PwvNl92l11F
         VJXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NgWb1VypNdq0w5pu2JKIcUVqOUrKW+cW7ICESNAaLXg=;
        b=GJQIbjakPT4ZO1BgnZKfQPJytjvsCnLgNJI8jje90ROjAcDSp5MbLH+S9pYoNoVqqx
         Na31SUYTk+Y3mN6/CtS6bE6wexpxqPzGECZFnUx6NJQT9YzW51T6k1rdjjZ+1DLYJJpW
         ss2aPErbRpzSnf2Kuh7UGX6VPJQGHmLprrE4P7HkhfYiTPKGnYDOZch5TQ8A7h0Bphgv
         W8ed+EQcVjv/PJC60cia7voTbDK/DDc976wW3peGyB+OUZqA0MyFdmz9+xBtdB1Ue9y3
         eOoiK95lkIqCQlL2b2xhuPsE/lGHXEiLHx/M9UbtoM++hWbcIz13oxmJd4nFKD7uj2ld
         O2eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ArpbYjGf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id bp22-20020a056512159600b004789faf5d76si301568lfb.12.2022.06.13.13.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:15:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 00/32] kasan: switch tag-based modes to stack ring from per-object metadata
Date: Mon, 13 Jun 2022 22:13:51 +0200
Message-Id: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ArpbYjGf;       spf=pass
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

This series makes the tag-based KASAN modes use a ring buffer for storing
stack depot handles for alloc/free stack traces for slab objects instead
of per-object metadata. This ring buffer is referred to as the stack ring.

On each alloc/free of a slab object, the tagged address of the object and
the current stack trace are recorded in the stack ring.

On each bug report, if the accessed address belongs to a slab object, the
stack ring is scanned for matching entries. The newest entries are used to
print the alloc/free stack traces in the report: one entry for alloc and
one for free.

The ring buffer is lock-free.

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

The current implementation of the stack ring uses a single ring buffer for
the whole kernel. This might lead to contention due to atomic accesses to
the ring buffer index on multicore systems.

It is unclear to me whether the performance impact from this contention
is significant compared to the slowdown introduced by collecting stack
traces.

While these patches are being reviewed, I will do some tests on the arm64
hardware that I have. However, I do not have a large multicore arm64
system to do proper measurements.

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

Andrey Konovalov (32):
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
  kasan: simplify invalid-free reporting
  kasan: cosmetic changes in report.c
  kasan: use kasan_addr_to_slab in print_address_description
  kasan: move kasan_addr_to_slab to common.c
  kasan: make kasan_addr_to_page static
  kasan: simplify print_report
  kasan: introduce complete_report_info
  kasan: fill in cache and object in complete_report_info
  kasan: rework function arguments in report.c
  kasan: introduce kasan_complete_mode_report_info
  kasan: implement stack ring for tag-based modes
  kasan: better identify bug types for tag-based modes

 include/linux/kasan.h     |  55 +++++-------
 include/linux/slab.h      |   2 +-
 lib/Kconfig.kasan         |   8 --
 mm/kasan/common.c         | 173 ++++----------------------------------
 mm/kasan/generic.c        | 154 ++++++++++++++++++++++++++++++---
 mm/kasan/kasan.h          | 138 ++++++++++++++++++++----------
 mm/kasan/report.c         | 130 +++++++++++++---------------
 mm/kasan/report_generic.c |  45 +++++++++-
 mm/kasan/report_tags.c    | 114 ++++++++++++++++++-------
 mm/kasan/tags.c           |  61 +++++++-------
 10 files changed, 491 insertions(+), 389 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1655150842.git.andreyknvl%40google.com.
