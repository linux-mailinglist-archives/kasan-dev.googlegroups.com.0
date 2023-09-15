Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ76SKUAMGQEHSUDALI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id ED3727A281C
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 22:32:04 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-3f5df65f9f4sf19333205e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 13:32:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694809924; cv=pass;
        d=google.com; s=arc-20160816;
        b=V1sgyscCgJr4yHgSZLG4QdnPXJlTEoXtaSSpmzXEvFrVWuIGS+GxHzUPV07T5Hy0Ms
         PTU40zQvFPh44eoaO9EEsMmbFOjOs9HmJ65LL9JUiC57ZYzHh1yNUHKwAyc1HWCly6u2
         evXpBByIKdVAttKwu8JgDx2e8+s42fzgOdh67eFHCDCRK6Woghp4oMfE1wjVHKw02mj9
         P/znZbvZgVwx/TPtIpmaKXdp845vUP44qQxM7sZL+eak6Ygr6AsQsxO5vTQSnehqwWo8
         1MN8C7CS6eserakwClNfAEba0BsLq/SG+QzleIpgWuLqn/5LxY8fQWjsdbNs13J8t8LF
         dVtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wjYw0d5PeDEV1pBt4GjPCc4EFPp855o/DdJuqAyXK3o=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=DLMzn3jOLKulHVrdNm+YZBhbE2Tl4wCbVx5AWLMTTu2a+mntfu509WEF45oUVoFmLg
         bW1SLWB9/ZfQd+RuDQMjtnSYoS4ZFbfunWhYWSXiV+3iuFdW6y4WF71eU69Hw2u6gWt0
         gD0qye+X45ChX5HunlzpknUWUF2eg+niVXRtq2iA9uDQf/nl7CQ4lR+HftcwIZWRj4do
         WTX6wrPw8MTDrfF1ovnLPwmUP0YkyAuUy9e72R98UJpgujCzgTSy2K8BMRDZueoxdpra
         w2E2Kd9NpK1JQbAi3InRiIXpWv/GcQ/wXcnoVQFzUFsB9Uqs6fX1x4b57ZJaPhE9AEzn
         zlfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FWwH7tZI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694809924; x=1695414724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wjYw0d5PeDEV1pBt4GjPCc4EFPp855o/DdJuqAyXK3o=;
        b=RUz597Fmwzym2Clf2nzLvX4RAfmHMNUwRHsc25TM2E1j7XEruxsFg3g32YyTrCkWnd
         iuU8QhdE14awlvTQkuhxIxilYKohFlgO9/46N6TqZm0ThfPNko2cgmWls7g0yZFdN4ee
         AB6rhUA2uDNd4qcpmebp7cJJQLriruH3O+9NPR8u2RhEAE//uA3Np535tfhywVOnzgSY
         JGKOjvyLIXm4dyURg3TYsFNDg3rdHxfp7ENeCWKiiOUGVFLIL0HJ5MSvvAXNEQI/8XzD
         adM554kHwALFJyaZnN2OmQy6pw4JyvkjRFfZP8Awfvy41X/Z5ksP1wN2V2kKHO3PSnNo
         qPUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694809924; x=1695414724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wjYw0d5PeDEV1pBt4GjPCc4EFPp855o/DdJuqAyXK3o=;
        b=iBC25MmyPPx2fmYm7LWbZEJZR8ttYzGOvnUShJencdgfR8Iv0xwFPCOJbvHQ/ak8aq
         mhryhsmP5TeINXj2fH5Ce6J6/ubE6B9/igfCNAQrWd5ezxEg+Y7I0+FvZMaq/U4Q2qzn
         obmcYq038474yoN7tcuGpaYWQDaRPW/Vh8wwxxxP7O8Gv21PN9/ZDj4I73ogEO8m9AKH
         owfBVqkHu9pst0fhb8PpX8Uee1Ll6fBykoz/sLdlDwDEqoLTIGSN4khIk187vbpdvwAh
         vVoV6XAK/C/yhzKp0gmQXSbgMJ7Uo2dkz0+aqVDWHyTNIzAK5sqhXbQCH5BjKIw/BFwS
         d1fQ==
X-Gm-Message-State: AOJu0Yz9f+/+6De/8Bs8P8QSLOScY13j29fqE6I7TF+Mk3FUFvLoLNs0
	1FFDFDor5/Nu7vOUtyZ0v80=
X-Google-Smtp-Source: AGHT+IGfXl4mow9f06TVv27+OEFDXlQ5x73BK4VB1HIDRMffJFs9wVPlIRnwtjaGlZmKza5XBXJAqw==
X-Received: by 2002:a05:600c:2491:b0:3fe:2f80:8394 with SMTP id 17-20020a05600c249100b003fe2f808394mr2618763wms.15.1694809923684;
        Fri, 15 Sep 2023 13:32:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6025:b0:3fe:e525:caee with SMTP id
 az37-20020a05600c602500b003fee525caeels1190123wmb.0.-pod-prod-04-eu; Fri, 15
 Sep 2023 13:32:01 -0700 (PDT)
X-Received: by 2002:adf:a303:0:b0:31f:f84e:f63e with SMTP id c3-20020adfa303000000b0031ff84ef63emr1838690wrb.54.1694809921809;
        Fri, 15 Sep 2023 13:32:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694809921; cv=none;
        d=google.com; s=arc-20160816;
        b=Runk6BZfEu4cevx2u6b+1EZg/4EYHn1zEBgJeKK3RZyZGGzx5ILjH++uz0gxYy56WC
         wxPSvbz4WXlvXYDNZ2OvCFCp+G10n/QCvBD7oGilPjz1+yu/TSpiusRG9tG1KZNheUqz
         TAD1w1V0mLsDW4XowhAjl5/KHB7ql77lW1hCj3VCW11r0kpCfKPhifU2FVT7QvXOzNjS
         sgZqsLQtp0GZ2KqMSwaUYDIrCj+FFsxnIR8w9zMXmyEK9QFGfjCvTx951iGx98O7CbBh
         9O/CyhrG1gBw4lWZSnRz/i2mVN7fm+w/aZMYfrth4Z4tQB97CTI/L0P1w/9AlbZGlBN3
         ukTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6aCgnXJdDdEagEQtDfeKQJl/I/7HuJOZio3xGVS/z3M=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=T192EH5RGsvwrlWG+F4p4XEJEP2fNuQtOM5SLyKtEoHnJ5pkJHctYzfxg0/F3xgFk7
         8dSKfBG7YH/+VcXqBUSCfODFvq7Vr6LIOdFZkh//0DYCKfRlM9FXi7/BtM9X1RYIe4+3
         NyWoJ0qDiiwQMjU1iK9bv/yuDLNrE84CI1HqNadfFXty5kH93sFHTLHLHQSZ2mMd9GGb
         8d9YAV9InXeHVoNAx751po8kOpKBQ5I79QB9FK0g4BVL8qL7AWxmxILw5wXgcUnngX3K
         VysFPStyWe0j0ik0r1+LqfRASUsXHWb5nMBmQjbYEjAegWqXrjokmA60hlFRDX5qshIW
         QXgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FWwH7tZI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id bk24-20020a0560001d9800b0031aef8a5defsi324930wrb.1.2023.09.15.13.32.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 13:32:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-402cc6b8bedso29501605e9.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 13:32:01 -0700 (PDT)
X-Received: by 2002:a05:600c:3641:b0:401:b652:b6cf with SMTP id
 y1-20020a05600c364100b00401b652b6cfmr2697790wmq.13.1694809921161; Fri, 15 Sep
 2023 13:32:01 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl@google.com>
In-Reply-To: <2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Sep 2023 22:31:21 +0200
Message-ID: <CANpmjNMfpgE0J4e-nk7d0LQi2msX9KcMwK-j37BPuvnPhKPYKg@mail.gmail.com>
Subject: Re: [PATCH v2 14/19] lib/stackdepot, kasan: add flags to
 __stack_depot_save and rename
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FWwH7tZI;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
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

On Wed, 13 Sept 2023 at 19:17, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Change the bool can_alloc argument of __stack_depot_save to a
> u32 argument that accepts a set of flags.
>
> The following patch will add another flag to stack_depot_save_flags
> besides the existing STACK_DEPOT_FLAG_CAN_ALLOC.
>
> Also rename the function to stack_depot_save_flags, as __stack_depot_save
> is a cryptic name,
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v1->v2:
> - This is a new patch.
> ---
>  include/linux/stackdepot.h | 36 +++++++++++++++++++++++++-----------
>  lib/stackdepot.c           | 16 +++++++++++-----
>  mm/kasan/common.c          |  7 ++++---
>  mm/kasan/generic.c         |  9 +++++----
>  mm/kasan/kasan.h           |  2 +-
>  mm/kasan/tags.c            |  3 ++-
>  6 files changed, 48 insertions(+), 25 deletions(-)
>
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index e58306783d8e..0b262e14144e 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -32,6 +32,17 @@ typedef u32 depot_stack_handle_t;
>   */
>  #define STACK_DEPOT_EXTRA_BITS 5
>
> +typedef u32 depot_flags_t;
> +
> +/*
> + * Flags that can be passed to stack_depot_save_flags(); see the comment next
> + * to its declaration for more details.
> + */
> +#define STACK_DEPOT_FLAG_CAN_ALLOC     ((depot_flags_t)0x0001)
> +
> +#define STACK_DEPOT_FLAGS_NUM  1
> +#define STACK_DEPOT_FLAGS_MASK ((depot_flags_t)((1 << STACK_DEPOT_FLAGS_NUM) - 1))
> +
>  /*
>   * Using stack depot requires its initialization, which can be done in 3 ways:
>   *
> @@ -69,31 +80,34 @@ static inline int stack_depot_early_init(void)      { return 0; }
>  #endif
>
>  /**
> - * __stack_depot_save - Save a stack trace to stack depot
> + * stack_depot_save_flags - Save a stack trace to stack depot
>   *
>   * @entries:           Pointer to the stack trace
>   * @nr_entries:                Number of frames in the stack
>   * @alloc_flags:       Allocation GFP flags
> - * @can_alloc:         Allocate stack pools (increased chance of failure if false)
> + * @depot_flags:       Stack depot flags
> + *
> + * Saves a stack trace from @entries array of size @nr_entries.
>   *
> - * Saves a stack trace from @entries array of size @nr_entries. If @can_alloc is
> - * %true, stack depot can replenish the stack pools in case no space is left
> - * (allocates using GFP flags of @alloc_flags). If @can_alloc is %false, avoids
> - * any allocations and fails if no space is left to store the stack trace.
> + * If STACK_DEPOT_FLAG_CAN_ALLOC is set in @depot_flags, stack depot can
> + * replenish the stack pools in case no space is left (allocates using GFP
> + * flags of @alloc_flags). Otherwise, stack depot avoids any allocations and
> + * fails if no space is left to store the stack trace.
>   *
>   * If the provided stack trace comes from the interrupt context, only the part
>   * up to the interrupt entry is saved.
>   *
> - * Context: Any context, but setting @can_alloc to %false is required if
> + * Context: Any context, but setting STACK_DEPOT_FLAG_CAN_ALLOC is required if
>   *          alloc_pages() cannot be used from the current context. Currently
>   *          this is the case for contexts where neither %GFP_ATOMIC nor
>   *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
>   *
>   * Return: Handle of the stack struct stored in depot, 0 on failure
>   */
> -depot_stack_handle_t __stack_depot_save(unsigned long *entries,
> -                                       unsigned int nr_entries,
> -                                       gfp_t gfp_flags, bool can_alloc);
> +depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
> +                                           unsigned int nr_entries,
> +                                           gfp_t gfp_flags,
> +                                           depot_flags_t depot_flags);
>
>  /**
>   * stack_depot_save - Save a stack trace to stack depot
> @@ -103,7 +117,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>   * @alloc_flags:       Allocation GFP flags
>   *
>   * Context: Contexts where allocations via alloc_pages() are allowed.
> - *          See __stack_depot_save() for more details.
> + *          See stack_depot_save_flags() for more details.
>   *
>   * Return: Handle of the stack trace stored in depot, 0 on failure
>   */
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 1b08897ebd2b..e5121225f124 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -438,19 +438,24 @@ static inline struct stack_record *find_stack(struct list_head *bucket,
>         return NULL;
>  }
>
> -depot_stack_handle_t __stack_depot_save(unsigned long *entries,
> -                                       unsigned int nr_entries,
> -                                       gfp_t alloc_flags, bool can_alloc)
> +depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
> +                                           unsigned int nr_entries,
> +                                           gfp_t alloc_flags,
> +                                           depot_flags_t depot_flags)
>  {
>         struct list_head *bucket;
>         struct stack_record *found = NULL;
>         depot_stack_handle_t handle = 0;
>         struct page *page = NULL;
>         void *prealloc = NULL;
> +       bool can_alloc = depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
>         bool need_alloc = false;
>         unsigned long flags;
>         u32 hash;
>
> +       if (depot_flags & ~STACK_DEPOT_FLAGS_MASK)
> +               return 0;
> +

Shouldn't this be a WARN due to invalid flags?

>         /*
>          * If this stack trace is from an interrupt, including anything before
>          * interrupt entry usually leads to unbounded stack depot growth.
> @@ -529,13 +534,14 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                 handle = found->handle.handle;
>         return handle;
>  }
> -EXPORT_SYMBOL_GPL(__stack_depot_save);
> +EXPORT_SYMBOL_GPL(stack_depot_save_flags);
>
>  depot_stack_handle_t stack_depot_save(unsigned long *entries,
>                                       unsigned int nr_entries,
>                                       gfp_t alloc_flags)
>  {
> -       return __stack_depot_save(entries, nr_entries, alloc_flags, true);
> +       return stack_depot_save_flags(entries, nr_entries, alloc_flags,
> +                                     STACK_DEPOT_FLAG_CAN_ALLOC);
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_save);
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 256930da578a..825a0240ec02 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -22,6 +22,7 @@
>  #include <linux/sched.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/slab.h>
> +#include <linux/stackdepot.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> @@ -37,19 +38,19 @@ struct slab *kasan_addr_to_slab(const void *addr)
>         return NULL;
>  }
>
> -depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
> +depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
>  {
>         unsigned long entries[KASAN_STACK_DEPTH];
>         unsigned int nr_entries;
>
>         nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -       return __stack_depot_save(entries, nr_entries, flags, can_alloc);
> +       return stack_depot_save_flags(entries, nr_entries, flags, depot_flags);
>  }
>
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
>  {
>         track->pid = current->pid;
> -       track->stack = kasan_save_stack(flags, true);
> +       track->stack = kasan_save_stack(flags, STACK_DEPOT_FLAG_CAN_ALLOC);
>  }
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 4d837ab83f08..5d168c9afb32 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -25,6 +25,7 @@
>  #include <linux/sched.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/slab.h>
> +#include <linux/stackdepot.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> @@ -472,7 +473,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
>                         sizeof(struct kasan_free_meta) : 0);
>  }
>
> -static void __kasan_record_aux_stack(void *addr, bool can_alloc)
> +static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>  {
>         struct slab *slab = kasan_addr_to_slab(addr);
>         struct kmem_cache *cache;
> @@ -489,17 +490,17 @@ static void __kasan_record_aux_stack(void *addr, bool can_alloc)
>                 return;
>
>         alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] = kasan_save_stack(0, can_alloc);
> +       alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
>  }
>
>  void kasan_record_aux_stack(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr, true);
> +       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
>  }
>
>  void kasan_record_aux_stack_noalloc(void *addr)
>  {
> -       return __kasan_record_aux_stack(addr, false);
> +       return __kasan_record_aux_stack(addr, 0);
>  }
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index f70e3d7a602e..de3206e11888 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -370,7 +370,7 @@ static inline void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int
>  static inline void kasan_init_object_meta(struct kmem_cache *cache, const void *object) { }
>  #endif
>
> -depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
> +depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
>  void kasan_set_track(struct kasan_track *track, gfp_t flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
>  void kasan_save_free_info(struct kmem_cache *cache, void *object);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 7dcfe341d48e..4fd32121b0fd 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -13,6 +13,7 @@
>  #include <linux/memblock.h>
>  #include <linux/memory.h>
>  #include <linux/mm.h>
> +#include <linux/stackdepot.h>
>  #include <linux/static_key.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> @@ -101,7 +102,7 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>         struct kasan_stack_ring_entry *entry;
>         void *old_ptr;
>
> -       stack = kasan_save_stack(gfp_flags, true);
> +       stack = kasan_save_stack(gfp_flags, STACK_DEPOT_FLAG_CAN_ALLOC);
>
>         /*
>          * Prevent save_stack_info() from modifying stack ring
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMfpgE0J4e-nk7d0LQi2msX9KcMwK-j37BPuvnPhKPYKg%40mail.gmail.com.
