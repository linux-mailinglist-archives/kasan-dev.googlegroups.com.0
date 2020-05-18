Return-Path: <kasan-dev+bncBCMIZB7QWENRBLGDRH3AKGQEFBBEZZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 929861D7506
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 12:21:33 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id z20sf3332372uag.19
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 03:21:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589797292; cv=pass;
        d=google.com; s=arc-20160816;
        b=e1q/Mn1y8tS7oRmEjrkeh4N1SHfrad9q60/lX+Bz5Fc25hUQnvT1DxRYA3W/Zd+os6
         VTWEdlv38GbO2d2alOCv6XVAvJTpzg56E3M0kUKs3vME8R0tfTsptqJK/GHcoh4mnQrM
         ghDXBFVP1PRoNL9OfSQ3edrpFltH4K+8XITyc5zKhYTgRVSdzemTIn4KvcIVA+2K/E3S
         eHb2rhmyWBYy8CZWQfwP9AY3zt89NczFqGsZu8TFgUtb7TWs7KFnYnT9uaJEInMz+Um+
         C8rzUHYrJKVCMPneRiLpOgsWYe7aw0VZkPFJ6Ey1TBZOv1qY+CS/Rv95oo4OcGHzry2Q
         tEsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7PBTl8VPWTQM3KA/JqUpUDBzHGsvmtlBQ+zLT+dcxxg=;
        b=Jx0ivATx6oj/zOTKhHWWiqWfd6icwxT80p6WIY73AVscPPQJwap2ayqqYieH//GRfg
         LUsZdnLgtcE1eviMVRcZOrFujEsm1LZZe+3FAko6qrSDtiKP4fbKjqANAFuGEkzlVZ5X
         gnmTy4BqwWZ8ofjoUNd6yJT0J5l0COx3lCC0m3LpoB8N8xZ0POtxKtR75Tszf9BzIrmd
         CnhQidxeUFQVB0yB2H7aOwiLhoyzLHrel0g9Ek8Q01AZ/k4wLEpOtNDMtqIRgRu1cXbC
         XkNgLnGZOuQ/OP2U5UU9k0EftqKuFZLicUvXyFFE+e/z3xcT+735ybZ01X2QyX0+p3Rp
         NW1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XrEl9sHF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7PBTl8VPWTQM3KA/JqUpUDBzHGsvmtlBQ+zLT+dcxxg=;
        b=g1YCrBhO5ysf2PDPNg0YqiYBsds/zJLNdHRalkPeJZDnRdW807f0or1EuKEF8Qpyot
         aipdTdIrMHbTzYSO1EBxAjbRTczbAATmwLOEC/ejA6+EKc6K8RYhDUYXXidTAl4RRc9c
         3kmQvaW7oCeGNa4Ji3OVn/xjkMezEsDCQ4BvUob35XwU8BqIl1F1EL56TAfcYeXQa4bm
         VNF4olxQmOlKRFtyL2RdeiTpn7NMC+UhiH+T8oXs+qP5tuIrrl+cr0PnKPgwqeKnSvm1
         XzCpJ1RrJw05RmRGCNpzHld1s6I0tXhGiCgsOYq75VhWCN+mIPF3OWZ1fvnJHKBWIwV6
         Q5ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7PBTl8VPWTQM3KA/JqUpUDBzHGsvmtlBQ+zLT+dcxxg=;
        b=Dm9XA+dPc52Dr3iYG3X7hM+RWgaA54z+J44/1khr0GaRkEE5KPp6LYGkzk2LhvcV9D
         gqJHVGpczDEGqNbF2HuJdNHZLLeinjC6xg/Yp/QKAyQRUJPH4rgjQB6XtIy9VwXQPWC/
         SFjjUlfIAggHVqyvA5JcIWXwtoxd1mhEd3zSEiOa4B/Aj6WKD66vg3pbWC5+a4DJOji1
         fqi2sbHOnMDCF2s9aZy6NxsQSnFDqh9xoLfv1cSEKj7tYOKNzg8qbdoWt/UUVrIIhRaj
         S1YNDP5+qKlaU2lFw0fCjHHKhdrVmOincuOS7bgz7nx0XgNHzTrX1qAHUvE1+Fi4w4pS
         r2FA==
X-Gm-Message-State: AOAM533KV55kAbRQgqrEYG0XIkqyVe1AU5h5H73xe3CbJykacmwofEky
	m8ROYvgPu7Ua9KPgcoSJOxc=
X-Google-Smtp-Source: ABdhPJy5EEum8lcMTjtt4Jnbu4UNDUIR2qXvCvuKRyh1rHecBa0cRMCG4yOLPOyBvAuSPKxxet0hVw==
X-Received: by 2002:ab0:2f5:: with SMTP id 108mr5175284uah.122.1589797292533;
        Mon, 18 May 2020 03:21:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:9c1:: with SMTP id g1ls883335vsi.0.gmail; Mon, 18
 May 2020 03:21:32 -0700 (PDT)
X-Received: by 2002:a67:eec9:: with SMTP id o9mr10856103vsp.160.1589797292123;
        Mon, 18 May 2020 03:21:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589797292; cv=none;
        d=google.com; s=arc-20160816;
        b=kroqRJObKGBWzE4O/AblkCJOwtxnszQvqwiqBML2OpdmkCLPcZXfiurRhBpcrgVhUH
         HqTlMz+IrQ2Vc+RjwyWCs+H0mSVn/cpsqQI2rn1vsDK4Le1M3qv6Qjk4pWEGCck0sxLp
         FolM8nLNCuAi82HkPgmGLviTrx+zW5NziePiCL/AEra/VD3TJFA2/wuZT8hdne94OXDK
         YjTd2sWvW//u2w8y3PpYjNY0TK8Aj7n6iIkRNx9jxaFHeKVIpuZ6+kbI/SMmvB2asV/E
         QLDjCtXK+toA6c/EhfRmhCPZeXms0vILXDSaw7A3BqeXQeYjUw1lJbsCiHHUaOJYRKKm
         +46w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4UrcruNgjCGo7KZXCgHiav/SoRCLnqO+sVxO468jQxk=;
        b=UxvmsifNyrQB3IeIPLG4c0vTUr7D7bmcw85LH7RIPJlO3P4akXEmPWqjn6rdFtmhDl
         41UwI6Ws2PQY+BkcZwCLPHogts3oNks0ervq2kWjeqROwsNx9xPxTNeqX1lCzUy95Y62
         nTDTuFakc7+xzuL+oQ9uNLj1iYPlg1EhIj1q0peAp5ziRSuPoCGCII9jMqd1Y9myQYV8
         hoW1J9aVpP+hyEGpmgQ+rxxYy8yMcQ5jmORYRJXFtmI6Gd7nuYc5lxG+zEZ8UQHy4cRT
         4/8VNXX7qqv2C2+6F/uyP57HuqX2Q3RQaJmWFRdVmWBjE8eSUINTaQq95w9kpRrcv75A
         lZ7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XrEl9sHF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id b10si693872vso.1.2020.05.18.03.21.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 May 2020 03:21:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id x13so4430808qvr.2
        for <kasan-dev@googlegroups.com>; Mon, 18 May 2020 03:21:32 -0700 (PDT)
X-Received: by 2002:a0c:db03:: with SMTP id d3mr15524799qvk.80.1589797291392;
 Mon, 18 May 2020 03:21:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200518062603.4570-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200518062603.4570-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 May 2020 12:21:19 +0200
Message-ID: <CACT4Y+aSmcoSeC7J7RgoVV8CanwCrEz=zNZYG=_8KX3U-57A5Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/4] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XrEl9sHF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, May 18, 2020 at 8:26 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This feature will record the last two call_rcu() call stack and
> prints up to 2 call_rcu() call stacks in KASAN report.
>
> When call_rcu() is called, we store the call_rcu() call stack into
> slub alloc meta-data, so that the KASAN report can print rcu stack.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Josh Triplett <josh@joshtriplett.org>
> Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> Cc: Joel Fernandes <joel@joelfernandes.org>
> ---
>  include/linux/kasan.h |  2 ++
>  kernel/rcu/tree.c     |  2 ++
>  lib/Kconfig.kasan     |  2 ++
>  mm/kasan/common.c     |  4 ++--
>  mm/kasan/generic.c    | 20 ++++++++++++++++++++
>  mm/kasan/kasan.h      | 10 ++++++++++
>  mm/kasan/report.c     | 24 ++++++++++++++++++++++++
>  7 files changed, 62 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 31314ca7c635..23b7ee00572d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -174,11 +174,13 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>
>  void kasan_cache_shrink(struct kmem_cache *cache);
>  void kasan_cache_shutdown(struct kmem_cache *cache);
> +void kasan_record_aux_stack(void *ptr);
>
>  #else /* CONFIG_KASAN_GENERIC */
>
>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> +static inline void kasan_record_aux_stack(void *ptr) {}
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index 06548e2ebb72..36a4ff7f320b 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -57,6 +57,7 @@
>  #include <linux/slab.h>
>  #include <linux/sched/isolation.h>
>  #include <linux/sched/clock.h>
> +#include <linux/kasan.h>
>  #include "../time/tick-internal.h"
>
>  #include "tree.h"
> @@ -2668,6 +2669,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
>         head->func = func;
>         head->next = NULL;
>         local_irq_save(flags);
> +       kasan_record_aux_stack(head);
>         rdp = this_cpu_ptr(&rcu_data);
>
>         /* Add the callback to our list. */
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..4e83cf6e3caa 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -58,6 +58,8 @@ config KASAN_GENERIC
>           For better error detection enable CONFIG_STACKTRACE.
>           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>           (the resulting kernel does not boot).
> +         In generic mode KASAN prints the last two call_rcu() call stacks in
> +         reports.
>
>  config KASAN_SW_TAGS
>         bool "Software tag-based mode"
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2906358e42f0..8bc618289bb1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -41,7 +41,7 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -static inline depot_stack_handle_t save_stack(gfp_t flags)
> +depot_stack_handle_t kasan_save_stack(gfp_t flags)
>  {
>         unsigned long entries[KASAN_STACK_DEPTH];
>         unsigned int nr_entries;
> @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
>  static inline void set_track(struct kasan_track *track, gfp_t flags)
>  {
>         track->pid = current->pid;
> -       track->stack = save_stack(flags);
> +       track->stack = kasan_save_stack(flags);
>  }
>
>  void kasan_enable_current(void)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 56ff8885fe2e..78d8e0a75a8a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -325,3 +325,23 @@ DEFINE_ASAN_SET_SHADOW(f2);
>  DEFINE_ASAN_SET_SHADOW(f3);
>  DEFINE_ASAN_SET_SHADOW(f5);
>  DEFINE_ASAN_SET_SHADOW(f8);
> +
> +void kasan_record_aux_stack(void *addr)
> +{
> +       struct page *page = kasan_addr_to_page(addr);
> +       struct kmem_cache *cache;
> +       struct kasan_alloc_meta *alloc_info;
> +       void *object;
> +
> +       if (!(page && PageSlab(page)))
> +               return;
> +
> +       cache = page->slab_cache;
> +       object = nearest_obj(cache, page, addr);
> +       alloc_info = get_alloc_info(cache, object);
> +
> +       /* record last two call_rcu() call stacks */
> +       if (alloc_info->rcu_stack[0])

Do we need this if?

If we do "alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0]"
unconditionally, then we will just move 0 from [0] to [1], which
should be 0 at this point anyway.

I think it will be more reasonable to rename rcu_stack to aux_stack,
the function that stores the stacks is kasan_record_aux_stack.

> +               alloc_info->rcu_stack[1] = alloc_info->rcu_stack[0];
> +       alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..870c5dd07756 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -104,7 +104,15 @@ struct kasan_track {
>
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
> +#ifdef CONFIG_KASAN_GENERIC
> +       /*
> +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +        * The free stack is stored into struct kasan_free_meta.
> +        */
> +       depot_stack_handle_t rcu_stack[2];
> +#else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#endif
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>         u8 free_track_idx;
> @@ -159,6 +167,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>
>  struct page *kasan_addr_to_page(const void *addr);
>
> +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..5ee66cf7e27c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -179,6 +179,17 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>         return &alloc_meta->free_track[i];
>  }
>
> +#ifdef CONFIG_KASAN_GENERIC
> +static void print_stack(depot_stack_handle_t stack)
> +{
> +       unsigned long *entries;
> +       unsigned int nr_entries;
> +
> +       nr_entries = stack_depot_fetch(stack, &entries);
> +       stack_trace_print(entries, nr_entries, 0);
> +}
> +#endif
> +
>  static void describe_object(struct kmem_cache *cache, void *object,
>                                 const void *addr, u8 tag)
>  {
> @@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 free_track = kasan_get_free_track(cache, object, tag);
>                 print_track(free_track, "Freed");
>                 pr_err("\n");
> +
> +#ifdef CONFIG_KASAN_GENERIC
> +               if (alloc_info->rcu_stack[0]) {
> +                       pr_err("Last one call_rcu() call stack:\n");
> +                       print_stack(alloc_info->rcu_stack[0]);
> +                       pr_err("\n");
> +               }
> +               if (alloc_info->rcu_stack[1]) {
> +                       pr_err("Second to last call_rcu() call stack:\n");
> +                       print_stack(alloc_info->rcu_stack[1]);
> +                       pr_err("\n");
> +               }
> +#endif
>         }
>
>         describe_object_addr(cache, object, addr);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200518062603.4570-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaSmcoSeC7J7RgoVV8CanwCrEz%3DzNZYG%3D_8KX3U-57A5Q%40mail.gmail.com.
