Return-Path: <kasan-dev+bncBCMIZB7QWENRBUNMV33AKGQERZF6Q5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 16BE31E0B15
	for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 11:56:35 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id ck14sf15280875pjb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 May 2020 02:56:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590400593; cv=pass;
        d=google.com; s=arc-20160816;
        b=pu8RnkzKGYOhACz3KyFKAVMHAoHL0qIxz7mGKivMCtq8P5wBN+uNrDX4br/tOZm88N
         HIRlAEHInnQ2/0joesiQgWrCs3/QDorJleGaI9azsqHb+p0/uyxDjdiO0IcIlYwPa/NN
         3Gp0qaclVS7dgWu2rYykqfjYcOPVkIc0jefkT7JiNb/QMgERsRjYhyIuz3Yiiz50gtMb
         51CQeKaMS0tax83sqfBWQ0eFILnXAGCePzwrGau4WajwmDogxEw5MQ72Lyl2t27KJmt0
         auUZ1q1ob7dcvEEIfLghRrfy7G4E0GxUxsx9GxF4ErpTXvkBR63PdD1+BqHG7Ffre8xz
         X6Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=P57L0XyTmk3W039TWY95Bdh5e0YK8waCzCfx7hzABlg=;
        b=Rt3eC/G+3GzcoV7StYWgPrKmtB8YfBtu76wrreeJPW2e3iTC1ww+wF/Th77QZfoFwx
         aSEZmLkhyiQmeP+zKhcSHf+hwNxcyPRAqHsmcQxmeA9mHi3XCiBKlgSioWuaAyeV33cJ
         5Pmez029RMx1cJuRXCSUU2ty7A1EySW6JNAQn3shl4DsZ6XoLxJnPbq6Frd5km/csmj7
         0ctA+qFIGm9ReB1gTUFZ5750pBvwB2u0R2q0wWzRFWrBHJ0DolX+HV5ULIBVjs+C4Ssm
         40P8DA6+fVICzkjYzEWXPw/sHj599QrSs8jckpNrl5xmF8gaK2qV+oFK48srQKTPBWFW
         PK+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cxm5wBQU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P57L0XyTmk3W039TWY95Bdh5e0YK8waCzCfx7hzABlg=;
        b=fSY01qJtjYCDxg/orREAqZ8N4pK//vEygHdAX9YZNwpt7sEHTPlckifc32bEequ2gv
         uWMMlgBOCHEow/9u76mUz/Ure38gNLM36aD8VFQzWk8sjNQSbdFY31rKxtu+uo4dseDM
         Na0zxHY9ffTWQ+YMAEdWEoM7DC0lTyWaOQhVJFUyor//6pRlvtE6h8jZe6Kp+58cZ3Tf
         P067CcPpN5ettUc8l5eMr9UxPgE4X9zC4vQ7tqurIGafGubAK6r5en/QFiJBop1MxicI
         MFw3GNDdqLJOnTDYRt7PceGezTr3ckxbNRmr8SMwcvR8C0+/H6cQsxYxw6Sx34lu54eq
         Nnhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P57L0XyTmk3W039TWY95Bdh5e0YK8waCzCfx7hzABlg=;
        b=BYKvRz6Md58zp5u/TlJ28XNwYJ/XwMT+8T4PhxiIIVUe6w830dP0fQZ+/BIL1BDi4C
         GQnq3rOWItyK4eQ1KoiQZ/1fQ4JTSgrPonbdpsC5Olzh1kcc61kH1/EpvI4C4gA8CS0+
         QWCAvQ/MmMxsoGaQoWhZlb4CusI07zu9Octjd5LCpRc9kdrwW3FG5tnejCakmEJiIiNV
         2F8vPw9HVUvm+qAImriQJ0LBapEO3mZ6kip76CslYh62v4Zotrk3vKDiD0kI2YWs9UqC
         vK9Ay2P6AV5XRHhTNgnlUa9KmR41rwCaurOzuiyoAmB/5UXO1KO629s+wFTJXELNfek7
         SKGg==
X-Gm-Message-State: AOAM530jeXZMs2nva4mcYyizGt1WmZW+m+FI2J2r8V7nzetwKYjQH3I3
	KzYJjY/V9a0u4k6rHjjP2aE=
X-Google-Smtp-Source: ABdhPJzv6/KW/1C5H1RXv/eiMAZ251L1McaFgZmiaEzbcw117MlUmb0WNLwuEmu6+IXeZjA3dhSaAg==
X-Received: by 2002:a17:902:868b:: with SMTP id g11mr7521478plo.225.1590400593274;
        Mon, 25 May 2020 02:56:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1703:: with SMTP id 3ls2848364pfx.8.gmail; Mon, 25 May
 2020 02:56:32 -0700 (PDT)
X-Received: by 2002:a63:c44b:: with SMTP id m11mr24385118pgg.404.1590400592850;
        Mon, 25 May 2020 02:56:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590400592; cv=none;
        d=google.com; s=arc-20160816;
        b=uKVaxl+ehXnvqm7SgwLrs3pXnTytgQQk7cMm0vWagfdGq1ofX2XdnJYIn7vtU7u8Wo
         jgpQAffAisHhyMISgwwv7ClIJo1sllbi4dxWXAZh9upkaL/CUVajNR4mGhefwnou8J2/
         zDjR8v+WJR3JDngZrttH6GzCyrzqXDX/e2DUkpfq7+bJuLhc/xqHC1tFJxyjSfYwPNTD
         hg+ISvZIWVM1WzXX3MpxbCvdC+vr3ycKwNg96knIXXKu0D7INA8QkjNFLIhBT31INk7V
         jqViHFuGDay93LJEpvMUIouKBsFeBNacmL2wVlh4K7WlToAo6bdcDCqIaRVvfM/SRNPs
         wTyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CMPkAnqOp+8OxXk8fKVTR6aNVdBXjbmCqODMZoYVJi4=;
        b=MrXwMLIp2oa3uP+trSRCq5dlUL2yRQC0/F+/ZXrYAYhBGcJyT0zgVC3RRF7C8Li7J3
         uMYOuEVe7dH7N0VE/E2FwYjULAyAiRfXutY7NXTcKbuLWa4LO2F1l9hArhFgpTFvShSV
         GMyl5uVNL5csfGVCleVdPNUbZ5/sYvF/AA8TDncGWcTrk5OVqjbsUtdGJcsg/cRTZy38
         Y+pMyxg/jGov9cAJTWBoOoVUS9JIjD0Kv6tHVRYqT/iFaFTEGul+kQQRRE3d+XeroiYu
         AJk7aIwqU+cxS2wJguk4kkPhBCFhiZVPdurgTNbr9ns+BOYwVgy9Mkeajc3p+cmXLSJw
         0dWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cxm5wBQU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id b8si1771533pjk.2.2020.05.25.02.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 May 2020 02:56:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id h9so3214242qtj.7
        for <kasan-dev@googlegroups.com>; Mon, 25 May 2020 02:56:32 -0700 (PDT)
X-Received: by 2002:ac8:74d9:: with SMTP id j25mr1708889qtr.257.1590400591745;
 Mon, 25 May 2020 02:56:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200522020059.22332-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200522020059.22332-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 May 2020 11:56:20 +0200
Message-ID: <CACT4Y+Zn9eMAPwCMEo710NnsUEoXP+H7xge8a1essu2F9DeFRw@mail.gmail.com>
Subject: Re: [PATCH v6 1/4] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Cxm5wBQU;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Fri, May 22, 2020 at 4:01 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This feature will record the last two call_rcu() call stacks and
> prints up to 2 call_rcu() call stacks in KASAN report.
>
> When call_rcu() is called, we store the call_rcu() call stack into
> slub alloc meta-data, so that the KASAN report can print rcu stack.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Hi Walter,

The series look good to me. Thanks for bearing with me. I am eager to
see this in syzbot reports.

Reviewed-and-tested-by: Dmitry Vyukov <dvyukov@google.com>

> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Acked-by: Paul E. McKenney <paulmck@kernel.org>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Josh Triplett <josh@joshtriplett.org>
> Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> Cc: Joel Fernandes <joel@joelfernandes.org>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/kasan.h |  2 ++
>  kernel/rcu/tree.c     |  2 ++
>  mm/kasan/common.c     |  4 ++--
>  mm/kasan/generic.c    | 21 +++++++++++++++++++++
>  mm/kasan/kasan.h      | 10 ++++++++++
>  mm/kasan/report.c     | 28 +++++++++++++++++++++++-----
>  6 files changed, 60 insertions(+), 7 deletions(-)
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
> index 56ff8885fe2e..8acf48882ba2 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -325,3 +325,24 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
> +       /*
> +        * record the last two call_rcu() call stacks.
> +        */
> +       alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> +       alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..a7391bc83070 100644
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
> +       depot_stack_handle_t aux_stack[2];
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
> index 80f23c9da6b0..2421a4bd9227 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -105,15 +105,20 @@ static void end_report(unsigned long *flags)
>         kasan_enable_current();
>  }
>
> +static void print_stack(depot_stack_handle_t stack)
> +{
> +       unsigned long *entries;
> +       unsigned int nr_entries;
> +
> +       nr_entries = stack_depot_fetch(stack, &entries);
> +       stack_trace_print(entries, nr_entries, 0);
> +}
> +
>  static void print_track(struct kasan_track *track, const char *prefix)
>  {
>         pr_err("%s by task %u:\n", prefix, track->pid);
>         if (track->stack) {
> -               unsigned long *entries;
> -               unsigned int nr_entries;
> -
> -               nr_entries = stack_depot_fetch(track->stack, &entries);
> -               stack_trace_print(entries, nr_entries, 0);
> +               print_stack(track->stack);
>         } else {
>                 pr_err("(stack is not available)\n");
>         }
> @@ -192,6 +197,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                 free_track = kasan_get_free_track(cache, object, tag);
>                 print_track(free_track, "Freed");
>                 pr_err("\n");
> +
> +#ifdef CONFIG_KASAN_GENERIC
> +               if (alloc_info->aux_stack[0]) {
> +                       pr_err("Last call_rcu():\n");
> +                       print_stack(alloc_info->aux_stack[0]);
> +                       pr_err("\n");
> +               }
> +               if (alloc_info->aux_stack[1]) {
> +                       pr_err("Second to last call_rcu():\n");
> +                       print_stack(alloc_info->aux_stack[1]);
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522020059.22332-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZn9eMAPwCMEo710NnsUEoXP%2BH7xge8a1essu2F9DeFRw%40mail.gmail.com.
