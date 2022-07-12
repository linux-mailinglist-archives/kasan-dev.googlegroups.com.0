Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPX7WWLAMGQEKGBRVOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CE3B571BEB
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 16:05:52 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id i15-20020a17090a2a0f00b001ef826b921dsf5041762pjd.5
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 07:05:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657634751; cv=pass;
        d=google.com; s=arc-20160816;
        b=sB+u04ABsj16At6M6T4f14IKlTpcs51qU2ptmj+1IkJHXzNcfdXKmMZkp4DR3BkILQ
         0tdLnbMsxw11UhmZMbVPk8BjYOJN4HuhRkJp/rli3F6A++APa5vmhPxFRa/YI8X4vOCt
         U3BrJL8JFcu+/ifxh8TEErAR31xw8Vh9yAQN3aPELDy6gWaPL6WwljOKvJ2br0OuBJoS
         qN4oRQ+kmZ1OpvEfoEsVSE3nujYgcutAJTu/BbmxTsy745GDxfX50gi85L3y5a4gPWMe
         ArjXutJa1+pg3HoumVhmTU1y30JyZ87nzJ70NRjje+/3r+y0M6gXxDH1Wn1d7eeEvbqw
         QTlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=W5KWIKRLicAYkIYkhKjGNiJP3Qttvu4UVyh7lNPIj0o=;
        b=sEmUIKXhGUlpOM1YIDZv5FKdvJ3dmnjtSog4f7DbvQCP6uPXcl5F50Si4u1hs2OZUV
         oSfFxQdPd/AnBmuLBdrVbYbNO8iYIZe+EkTyLx/urgOVSHVdj/c+nKDgTAiUCgyZOvrw
         h4EJAgX0oggBNuW4i6G45CbPdZGAB4o25ijyTH44jnkWgAKpzWKDCZ26X3V4tHpMkKUJ
         +nqeok0YC1pRp8lQz5/1sF1Vygk15ibmqhj0EdF86vSgszPPbxZtxTt6m4RlnVQZrVET
         UbfqjF7gGLnGmDddr9cip9O3PmdfIRUSp5y2sB0hN7mcF1X5FEp5m7R5qBJePIuWfrZa
         RY1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="DMb/e8q7";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W5KWIKRLicAYkIYkhKjGNiJP3Qttvu4UVyh7lNPIj0o=;
        b=MfFvuovOnipgZqWtnT+IwtsMM2JHQiH4ZV6QSy4jeBgMj6Xqri0Fv5AmyblfyV0r8J
         xVHuKeuoLecUV8/v7vsXi888vshESNNEVjhdTY2P36hyeAwe6YK5acPNGIC0hxNTSxJB
         Slxm8S3spnacvzPgPfo7fGjYpS6LN7d+iIMww7E8+msrHApszJMJ5Di5wM9DNO/5pneN
         b4lbTocItt8vprisxj1+OCY83jngQ8F1xjhMkhQG2W9fM1UgKJm/jTQjXgLkxkKwLNoA
         ED6VWIaZGRPHKbq8dkGx/GHb8KyqzEAjmUu3Xn9KOECdiUIqomNkP7woVGw/Zd03l9GS
         1SDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W5KWIKRLicAYkIYkhKjGNiJP3Qttvu4UVyh7lNPIj0o=;
        b=LEDqw8F8AjaBuLLeCJohByPxOVfOAf3H75L/h44lzCgaSGsM4v+pXmss4SMImxKGRX
         Hc29uvtP85N+CFHWNLx3ve6FDp+kMaJ5ZJ41CmIuiCR0K1D3dCI5bHwKd2lW5OeSu96L
         6rLD/15s6yDiQESHHG1EADDFfCi1GFHwxIb2ROuTphIML8frm3cazGRyq8VRM7i/LZy0
         JYOGsl8Rr7sRaPxmURpfl6ynfGITxXb7p+drIywYK0o41fLPyEf+eocc3Fk7B8CQvHyt
         GV5LlWAMgXDyAOeBPNs5kQGUscj1YSQPE8p9N9XZCxoONJ4E+HeOkCh8lQLpHwDdWAUG
         QwXg==
X-Gm-Message-State: AJIora+QWsk9Gn648w9yEmj47kzer4TCt7EITHGSrohH7l1XCeaWWxPv
	C5ZiBJmSD7ntJfQlQrBJLqA=
X-Google-Smtp-Source: AGRyM1uzH1K5t/xkKI3CvfjPsmAZ4J5WtYS2SYXVH6Mb0KuvK0Wt37cRJgfM7IZJ68zZcXQgy0Wz0A==
X-Received: by 2002:a17:902:cccf:b0:168:c4c3:e8ca with SMTP id z15-20020a170902cccf00b00168c4c3e8camr24740054ple.40.1657634750633;
        Tue, 12 Jul 2022 07:05:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecc6:b0:16c:474:d5c6 with SMTP id
 a6-20020a170902ecc600b0016c0474d5c6ls1506685plh.2.gmail; Tue, 12 Jul 2022
 07:05:49 -0700 (PDT)
X-Received: by 2002:a17:903:24e:b0:16b:a02d:41fc with SMTP id j14-20020a170903024e00b0016ba02d41fcmr24390172plh.121.1657634749848;
        Tue, 12 Jul 2022 07:05:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657634749; cv=none;
        d=google.com; s=arc-20160816;
        b=dw7IE1JOErP1BOxg1gUm09/sjV8Q6aXaScsg+43j4ru3sOmsVso7AkhsgZjduuww1c
         oe0jjMtM6KPgUh2juvAOJOv/fisTU05fPHXTZD30JAHO/AdAgckmMiCwjjtVtdn9QKPg
         ER3hsZvA7lWarQs6STzOyqqesXhIi303uPluxVd7p4kNQArERAD4+bva+p/Ybic7x21V
         AFZOdfCItawHZWHIl2paLwG4HIivUDJEmLOmaGgMtlkIYZD4ry9ZFCNecNoKEgQGkExO
         Fbyik8rPmxxzkYc3W8od3Mk0+CFNUmV9MqUfk4e7TGQDDF4qn4/Q0MggN13sWzUgq+6e
         3ntA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vd6O28VewSFhRewX03WzTG5J3zTXvR/VFa5UjMf0N0Y=;
        b=zxOPXXXOWmQRJWmCGUQUg37a9M01CWXsOemmW3kw+GQce0uxwEsc96Y9N/GXY5Eqhh
         InZQsL/CRQ/aFqWsJ/i8y/dVc/mM85j0fv1HyaxtmnQzFGqPb4syfeSbEG5geY1BN0jx
         5Met/NEEQWZ8i6f4oQ9LDGB78lt7UVydCCKYC6xKgQ0LGj9vKG5wpz3RkArEhmLOnWf9
         KAZMJGp4J7YaIldqDQtMqxBHaASoMRdCtFbmccWsI7YB3JU1aT0+7Q6h0IKATyvSwmyy
         42GadO3uNiHTs9XW72YEbrk6d8upyBEcT/0dfK3pfBxwF0LrG0vdY6ydRmmxPzzEXaEO
         6r/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="DMb/e8q7";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id s19-20020a17090aad9300b001ef9c90c4afsi478451pjq.3.2022.07.12.07.05.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 07:05:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id g4so14089080ybg.9
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 07:05:49 -0700 (PDT)
X-Received: by 2002:a25:94a:0:b0:668:df94:fdf4 with SMTP id
 u10-20020a25094a000000b00668df94fdf4mr21754860ybm.425.1657634748762; Tue, 12
 Jul 2022 07:05:48 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-18-glider@google.com>
In-Reply-To: <20220701142310.2188015-18-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 16:05:12 +0200
Message-ID: <CANpmjNNh0SP53s0kg_Lj2HUVnY_9k_grm==q4w6Bbq4hLmKtHA@mail.gmail.com>
Subject: Re: [PATCH v4 17/45] init: kmsan: call KMSAN initialization routines
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="DMb/e8q7";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 1 Jul 2022 at 16:24, Alexander Potapenko <glider@google.com> wrote:
>
> kmsan_init_shadow() scans the mappings created at boot time and creates
> metadata pages for those mappings.
>
> When the memblock allocator returns pages to pagealloc, we reserve 2/3
> of those pages and use them as metadata for the remaining 1/3. Once KMSAN
> starts, every page allocated by pagealloc has its associated shadow and
> origin pages.
>
> kmsan_initialize() initializes the bookkeeping for init_task and enables
> KMSAN.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v2:
>  -- move mm/kmsan/init.c and kmsan_memblock_free_pages() to this patch
>  -- print a warning that KMSAN is a debugging tool (per Greg K-H's
>     request)
>
> v4:
>  -- change sizeof(type) to sizeof(*ptr)
>  -- replace occurrences of |var| with @var
>  -- swap init: and kmsan: in the subject
>  -- do not export __init functions
>
> Link: https://linux-review.googlesource.com/id/I7bc53706141275914326df2345881ffe0cdd16bd
> ---
>  include/linux/kmsan.h |  48 +++++++++
>  init/main.c           |   3 +
>  mm/kmsan/Makefile     |   3 +-
>  mm/kmsan/init.c       | 238 ++++++++++++++++++++++++++++++++++++++++++
>  mm/kmsan/kmsan.h      |   3 +
>  mm/kmsan/shadow.c     |  36 +++++++
>  mm/page_alloc.c       |   3 +
>  7 files changed, 333 insertions(+), 1 deletion(-)
>  create mode 100644 mm/kmsan/init.c
>
> diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> index b71e2032222e9..82fd564cc72e7 100644
> --- a/include/linux/kmsan.h
> +++ b/include/linux/kmsan.h
> @@ -51,6 +51,40 @@ void kmsan_task_create(struct task_struct *task);
>   */
>  void kmsan_task_exit(struct task_struct *task);
>
> +/**
> + * kmsan_init_shadow() - Initialize KMSAN shadow at boot time.
> + *
> + * Allocate and initialize KMSAN metadata for early allocations.
> + */
> +void __init kmsan_init_shadow(void);
> +
> +/**
> + * kmsan_init_runtime() - Initialize KMSAN state and enable KMSAN.
> + */
> +void __init kmsan_init_runtime(void);
> +
> +/**
> + * kmsan_memblock_free_pages() - handle freeing of memblock pages.
> + * @page:      struct page to free.
> + * @order:     order of @page.
> + *
> + * Freed pages are either returned to buddy allocator or held back to be used
> + * as metadata pages.
> + */
> +bool __init kmsan_memblock_free_pages(struct page *page, unsigned int order);
> +
> +/**
> + * kmsan_task_create() - Initialize KMSAN state for the task.
> + * @task: task to initialize.
> + */
> +void kmsan_task_create(struct task_struct *task);
> +
> +/**
> + * kmsan_task_exit() - Notify KMSAN that a task has exited.
> + * @task: task about to finish.
> + */
> +void kmsan_task_exit(struct task_struct *task);

Something went wrong with patch shuffling here I think,
kmsan_task_create + kmsan_task_exit decls are duplicated by this
patch.

>  /**
>   * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
>   * @page:  struct page pointer returned by alloc_pages().
> @@ -172,6 +206,20 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
>
>  #else
>
> +static inline void kmsan_init_shadow(void)
> +{
> +}
> +
> +static inline void kmsan_init_runtime(void)
> +{
> +}
> +
> +static inline bool kmsan_memblock_free_pages(struct page *page,
> +                                            unsigned int order)
> +{
> +       return true;
> +}
> +
>  static inline void kmsan_task_create(struct task_struct *task)
>  {
>  }
> diff --git a/init/main.c b/init/main.c
> index 0ee39cdcfcac9..7ba48a9ff1d53 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -34,6 +34,7 @@
>  #include <linux/percpu.h>
>  #include <linux/kmod.h>
>  #include <linux/kprobes.h>
> +#include <linux/kmsan.h>
>  #include <linux/vmalloc.h>
>  #include <linux/kernel_stat.h>
>  #include <linux/start_kernel.h>
> @@ -835,6 +836,7 @@ static void __init mm_init(void)
>         init_mem_debugging_and_hardening();
>         kfence_alloc_pool();
>         report_meminit();
> +       kmsan_init_shadow();
>         stack_depot_early_init();
>         mem_init();
>         mem_init_print_info();
> @@ -852,6 +854,7 @@ static void __init mm_init(void)
>         init_espfix_bsp();
>         /* Should be run after espfix64 is set up. */
>         pti_init();
> +       kmsan_init_runtime();
>  }
>
>  #ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
> diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
> index 550ad8625e4f9..401acb1a491ce 100644
> --- a/mm/kmsan/Makefile
> +++ b/mm/kmsan/Makefile
> @@ -3,7 +3,7 @@
>  # Makefile for KernelMemorySanitizer (KMSAN).
>  #
>  #
> -obj-y := core.o instrumentation.o hooks.o report.o shadow.o
> +obj-y := core.o instrumentation.o init.o hooks.o report.o shadow.o
>
>  KMSAN_SANITIZE := n
>  KCOV_INSTRUMENT := n
> @@ -18,6 +18,7 @@ CFLAGS_REMOVE.o = $(CC_FLAGS_FTRACE)
>
>  CFLAGS_core.o := $(CC_FLAGS_KMSAN_RUNTIME)
>  CFLAGS_hooks.o := $(CC_FLAGS_KMSAN_RUNTIME)
> +CFLAGS_init.o := $(CC_FLAGS_KMSAN_RUNTIME)
>  CFLAGS_instrumentation.o := $(CC_FLAGS_KMSAN_RUNTIME)
>  CFLAGS_report.o := $(CC_FLAGS_KMSAN_RUNTIME)
>  CFLAGS_shadow.o := $(CC_FLAGS_KMSAN_RUNTIME)
> diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
> new file mode 100644
> index 0000000000000..abbf595a1e359
> --- /dev/null
> +++ b/mm/kmsan/init.c
> @@ -0,0 +1,238 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * KMSAN initialization routines.
> + *
> + * Copyright (C) 2017-2021 Google LLC
> + * Author: Alexander Potapenko <glider@google.com>
> + *
> + */
> +
> +#include "kmsan.h"
> +
> +#include <asm/sections.h>
> +#include <linux/mm.h>
> +#include <linux/memblock.h>
> +
> +#include "../internal.h"
> +
> +#define NUM_FUTURE_RANGES 128
> +struct start_end_pair {
> +       u64 start, end;
> +};
> +
> +static struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES] __initdata;
> +static int future_index __initdata;
> +
> +/*
> + * Record a range of memory for which the metadata pages will be created once
> + * the page allocator becomes available.
> + */
> +static void __init kmsan_record_future_shadow_range(void *start, void *end)
> +{
> +       u64 nstart = (u64)start, nend = (u64)end, cstart, cend;
> +       bool merged = false;
> +       int i;
> +
> +       KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
> +       KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
> +       nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
> +       nend = ALIGN(nend, PAGE_SIZE);
> +
> +       /*
> +        * Scan the existing ranges to see if any of them overlaps with
> +        * [start, end). In that case, merge the two ranges instead of
> +        * creating a new one.
> +        * The number of ranges is less than 20, so there is no need to organize
> +        * them into a more intelligent data structure.
> +        */
> +       for (i = 0; i < future_index; i++) {
> +               cstart = start_end_pairs[i].start;
> +               cend = start_end_pairs[i].end;
> +               if ((cstart < nstart && cend < nstart) ||
> +                   (cstart > nend && cend > nend))
> +                       /* ranges are disjoint - do not merge */
> +                       continue;
> +               start_end_pairs[i].start = min(nstart, cstart);
> +               start_end_pairs[i].end = max(nend, cend);
> +               merged = true;
> +               break;
> +       }
> +       if (merged)
> +               return;
> +       start_end_pairs[future_index].start = nstart;
> +       start_end_pairs[future_index].end = nend;
> +       future_index++;
> +}
> +
> +/*
> + * Initialize the shadow for existing mappings during kernel initialization.
> + * These include kernel text/data sections, NODE_DATA and future ranges
> + * registered while creating other data (e.g. percpu).
> + *
> + * Allocations via memblock can be only done before slab is initialized.
> + */
> +void __init kmsan_init_shadow(void)
> +{
> +       const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
> +       phys_addr_t p_start, p_end;
> +       int nid;
> +       u64 i;
> +
> +       for_each_reserved_mem_range(i, &p_start, &p_end)
> +               kmsan_record_future_shadow_range(phys_to_virt(p_start),
> +                                                phys_to_virt(p_end));
> +       /* Allocate shadow for .data */
> +       kmsan_record_future_shadow_range(_sdata, _edata);
> +
> +       for_each_online_node(nid)
> +               kmsan_record_future_shadow_range(
> +                       NODE_DATA(nid), (char *)NODE_DATA(nid) + nd_size);
> +
> +       for (i = 0; i < future_index; i++)
> +               kmsan_init_alloc_meta_for_range(
> +                       (void *)start_end_pairs[i].start,
> +                       (void *)start_end_pairs[i].end);
> +}
> +
> +struct page_pair {

'struct shadow_origin_pages' for a more descriptive name?

> +       struct page *shadow, *origin;
> +};
> +static struct page_pair held_back[MAX_ORDER] __initdata;
> +
> +/*
> + * Eager metadata allocation. When the memblock allocator is freeing pages to
> + * pagealloc, we use 2/3 of them as metadata for the remaining 1/3.
> + * We store the pointers to the returned blocks of pages in held_back[] grouped
> + * by their order: when kmsan_memblock_free_pages() is called for the first
> + * time with a certain order, it is reserved as a shadow block, for the second
> + * time - as an origin block. On the third time the incoming block receives its
> + * shadow and origin ranges from the previously saved shadow and origin blocks,
> + * after which held_back[order] can be used again.
> + *
> + * At the very end there may be leftover blocks in held_back[]. They are
> + * collected later by kmsan_memblock_discard().
> + */
> +bool kmsan_memblock_free_pages(struct page *page, unsigned int order)
> +{
> +       struct page *shadow, *origin;

Can this just be 'struct page_pair'?

> +       if (!held_back[order].shadow) {
> +               held_back[order].shadow = page;
> +               return false;
> +       }
> +       if (!held_back[order].origin) {
> +               held_back[order].origin = page;
> +               return false;
> +       }
> +       shadow = held_back[order].shadow;
> +       origin = held_back[order].origin;
> +       kmsan_setup_meta(page, shadow, origin, order);
> +
> +       held_back[order].shadow = NULL;
> +       held_back[order].origin = NULL;
> +       return true;
> +}
> +
> +#define MAX_BLOCKS 8
> +struct smallstack {
> +       struct page *items[MAX_BLOCKS];
> +       int index;
> +       int order;
> +};
> +
> +static struct smallstack collect = {
> +       .index = 0,
> +       .order = MAX_ORDER,
> +};
> +
> +static void smallstack_push(struct smallstack *stack, struct page *pages)
> +{
> +       KMSAN_WARN_ON(stack->index == MAX_BLOCKS);
> +       stack->items[stack->index] = pages;
> +       stack->index++;
> +}
> +#undef MAX_BLOCKS
> +
> +static struct page *smallstack_pop(struct smallstack *stack)
> +{
> +       struct page *ret;
> +
> +       KMSAN_WARN_ON(stack->index == 0);
> +       stack->index--;
> +       ret = stack->items[stack->index];
> +       stack->items[stack->index] = NULL;
> +       return ret;
> +}
> +
> +static void do_collection(void)
> +{
> +       struct page *page, *shadow, *origin;
> +
> +       while (collect.index >= 3) {
> +               page = smallstack_pop(&collect);
> +               shadow = smallstack_pop(&collect);
> +               origin = smallstack_pop(&collect);
> +               kmsan_setup_meta(page, shadow, origin, collect.order);
> +               __free_pages_core(page, collect.order);
> +       }
> +}
> +
> +static void collect_split(void)
> +{
> +       struct smallstack tmp = {
> +               .order = collect.order - 1,
> +               .index = 0,
> +       };
> +       struct page *page;
> +
> +       if (!collect.order)
> +               return;
> +       while (collect.index) {
> +               page = smallstack_pop(&collect);
> +               smallstack_push(&tmp, &page[0]);
> +               smallstack_push(&tmp, &page[1 << tmp.order]);
> +       }
> +       __memcpy(&collect, &tmp, sizeof(tmp));
> +}
> +
> +/*
> + * Memblock is about to go away. Split the page blocks left over in held_back[]
> + * and return 1/3 of that memory to the system.
> + */
> +static void kmsan_memblock_discard(void)
> +{
> +       int i;
> +
> +       /*
> +        * For each order=N:
> +        *  - push held_back[N].shadow and .origin to @collect;
> +        *  - while there are >= 3 elements in @collect, do garbage collection:
> +        *    - pop 3 ranges from @collect;
> +        *    - use two of them as shadow and origin for the third one;
> +        *    - repeat;
> +        *  - split each remaining element from @collect into 2 ranges of
> +        *    order=N-1,
> +        *  - repeat.
> +        */
> +       collect.order = MAX_ORDER - 1;
> +       for (i = MAX_ORDER - 1; i >= 0; i--) {
> +               if (held_back[i].shadow)
> +                       smallstack_push(&collect, held_back[i].shadow);
> +               if (held_back[i].origin)
> +                       smallstack_push(&collect, held_back[i].origin);
> +               held_back[i].shadow = NULL;
> +               held_back[i].origin = NULL;
> +               do_collection();
> +               collect_split();
> +       }
> +}
> +
> +void __init kmsan_init_runtime(void)
> +{
> +       /* Assuming current is init_task */
> +       kmsan_internal_task_create(current);
> +       kmsan_memblock_discard();
> +       pr_info("Starting KernelMemorySanitizer\n");
> +       pr_info("ATTENTION: KMSAN is a debugging tool! Do not use it on production machines!\n");
> +       kmsan_enabled = true;
> +}
> diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
> index c7fb8666607e2..2f17912ef863f 100644
> --- a/mm/kmsan/kmsan.h
> +++ b/mm/kmsan/kmsan.h
> @@ -66,6 +66,7 @@ struct shadow_origin_ptr {
>  struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
>                                                      bool store);
>  void *kmsan_get_metadata(void *addr, bool is_origin);
> +void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
>
>  enum kmsan_bug_reason {
>         REASON_ANY,
> @@ -188,5 +189,7 @@ bool kmsan_internal_is_module_addr(void *vaddr);
>  bool kmsan_internal_is_vmalloc_addr(void *addr);
>
>  struct page *kmsan_vmalloc_to_page_or_null(void *vaddr);
> +void kmsan_setup_meta(struct page *page, struct page *shadow,
> +                     struct page *origin, int order);
>
>  #endif /* __MM_KMSAN_KMSAN_H */
> diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
> index 416cb85487a1a..7b254c30d42cc 100644
> --- a/mm/kmsan/shadow.c
> +++ b/mm/kmsan/shadow.c
> @@ -259,3 +259,39 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
>         kfree(s_pages);
>         kfree(o_pages);
>  }
> +
> +/* Allocate metadata for pages allocated at boot time. */
> +void __init kmsan_init_alloc_meta_for_range(void *start, void *end)
> +{
> +       struct page *shadow_p, *origin_p;
> +       void *shadow, *origin;
> +       struct page *page;
> +       u64 addr, size;
> +
> +       start = (void *)ALIGN_DOWN((u64)start, PAGE_SIZE);
> +       size = ALIGN((u64)end - (u64)start, PAGE_SIZE);
> +       shadow = memblock_alloc(size, PAGE_SIZE);
> +       origin = memblock_alloc(size, PAGE_SIZE);
> +       for (addr = 0; addr < size; addr += PAGE_SIZE) {
> +               page = virt_to_page_or_null((char *)start + addr);
> +               shadow_p = virt_to_page_or_null((char *)shadow + addr);
> +               set_no_shadow_origin_page(shadow_p);
> +               shadow_page_for(page) = shadow_p;
> +               origin_p = virt_to_page_or_null((char *)origin + addr);
> +               set_no_shadow_origin_page(origin_p);
> +               origin_page_for(page) = origin_p;
> +       }
> +}
> +
> +void kmsan_setup_meta(struct page *page, struct page *shadow,
> +                     struct page *origin, int order)
> +{
> +       int i;
> +
> +       for (i = 0; i < (1 << order); i++) {

Noticed this in many places, but we can just make these "for (int i =.." now.

> +               set_no_shadow_origin_page(&shadow[i]);
> +               set_no_shadow_origin_page(&origin[i]);
> +               shadow_page_for(&page[i]) = &shadow[i];
> +               origin_page_for(&page[i]) = &origin[i];
> +       }
> +}
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 785459251145e..e8d5a0b2a3264 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1731,6 +1731,9 @@ void __init memblock_free_pages(struct page *page, unsigned long pfn,
>  {
>         if (early_page_uninitialised(pfn))
>                 return;
> +       if (!kmsan_memblock_free_pages(page, order))
> +               /* KMSAN will take care of these pages. */
> +               return;

Add {} because the then-statement is not right below the if.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNh0SP53s0kg_Lj2HUVnY_9k_grm%3D%3Dq4w6Bbq4hLmKtHA%40mail.gmail.com.
