Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIGISX3AKGQEGV5GFFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CD1E1DBAC4
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 19:08:50 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id z2sf3391999pje.9
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 10:08:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589994529; cv=pass;
        d=google.com; s=arc-20160816;
        b=PW1FEwvA7ZKJ0UjV7z/D0oW31sA7bG1UzbS3Ayr3TtWmJzbNKjXHrD6WffiQBRKJOi
         1/wRocCPNYYgA+UOkACyzu7yaDIQx5IMjiAVIQfeKb8NIh3lvdHMNkRTgWBwxx/z5Pr0
         zCZj5tElNjeFQw9s6edBq0Tb2dPibjbWZpoSFXzEMVQWPBlHNxXv7qEnVwKeZuA0NekQ
         rbeU4ocrKd5EcqUNGIUqoszHpB0qaJjLEz8mQJfQvoYz6szd1iXKzCw77yx4poSDJTtH
         GNV/PFn08LKeJTiiI5s7XOmGsXOwigWSTXCNYPfHLQlILf/GrNZeniqFB3gz9CV/X0/4
         PEww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hMuVJchfet/2O8FxjGSu3MulJovPIRhQkWye2B/GyyQ=;
        b=FRakRZBbmvT2hRfl0FNwgBr7l4z8R26+yvbunV4kAdNxo8tvuFO5uMXZ2BLPnhB/HI
         K89HEyspElnzXqFS/N6DHTQefu6wq8gKIuTLxB1VjCdycGr62SUJRhO1H10wxSSrRpsA
         JQAAEYjnOApdbgH0AwkuePw3RCsjhzQId27MOhcgKq8tEfvaZgv9c0U0Su/JqV4Fghq+
         AxW5dxnEGExMVYTSR0XzwkPZmvLyc2k417OhxPMBjRwSRJC/1SWJbfgK75w194AuNR/z
         2hOCSBkAv6DvN7xwb6CxfTZXWB4XAf4fmHGaIKSjd4M99YhWFiXErWPOICRDjTwNSvwy
         JWeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ekEr6ftz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hMuVJchfet/2O8FxjGSu3MulJovPIRhQkWye2B/GyyQ=;
        b=rPla6cH1PzcIBZ2fWLKOs6i/qlDVkMqjukfaqi5gsGIdnU2DD8JOhWCbZRADXVVuct
         ZVFfraEZ/Yf/+nFg+rOXFgSrgEWJ5ti/oOOG6wZkM0AVrdP/d+OYxeHoBRseYDXt4On9
         QtJCyIOG62bJf6V51iQlC4TMBSiEHZ8p64LSdN+KxwVGwbRIcEsqAp2tdhFBMG2/8h8A
         Rhul/UpoAE19rP7MnkuxPc92dX/RsmqNA+OIrwhJ2yQLJprO5MgumDxl9qJPk57mNbJW
         Fzst4BNOKa/T2F0RTcQgQktJB9e0rngCSjrxH7EIy+aDwfnUICV/igcXHadAVAIdJ0CA
         wg0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hMuVJchfet/2O8FxjGSu3MulJovPIRhQkWye2B/GyyQ=;
        b=Kni+54V9zBlf53SPRodj/yxrwDgzOhfhJQfx5BReYprmG8lEOFPxBcslTB2xzqIW0X
         YKCtp62mKQs6FkEoaFLuHRkRpiTeC+e2yZlO6IB1GIlMC3DuNgM9ExoSoUs4zjrdNFb+
         Tf8uiBtWIraboxt6XfMeGFrGvFnk+n1kgS/0ppd3JGc2zMi3kb8XdIHRCqbcw9VxdmkR
         3lSETRecls/hc1xRzxGhF7Sz4T3kX8yLhmMGE6P4RzVyymvDgmwDcq3ziuqgujEXjp2h
         MsuQKnLSIa7dnr8PubgbQYP3oMZD+Nd2HYEOXdzwoEYJ7N8c3keHHWvOUvPjA9qemq+B
         xuLQ==
X-Gm-Message-State: AOAM532PmXllR9x0iQDRIcFN4FdPskeuNYhKyK/HCwuyNm2DWSo9S8Vg
	N7MV4dpfhtP35rXwOfF0Be8=
X-Google-Smtp-Source: ABdhPJyXnYhfq5rneP6tAkFHgqRF0GP63u82ueVceSv9S/oNYOhVQOFzKYqZ2zdOE8fBXmVKGIfNIg==
X-Received: by 2002:a63:790a:: with SMTP id u10mr4839306pgc.126.1589994528918;
        Wed, 20 May 2020 10:08:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8ccf:: with SMTP id m198ls1108863pfd.10.gmail; Wed, 20
 May 2020 10:08:48 -0700 (PDT)
X-Received: by 2002:a62:7acf:: with SMTP id v198mr5615635pfc.166.1589994528486;
        Wed, 20 May 2020 10:08:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589994528; cv=none;
        d=google.com; s=arc-20160816;
        b=ve8fL7ECXkY3iJlQwASZhEJq/BigPDzaaJ2qCffVro5JVfcTf63NQOUVhGO3n2ADey
         fFMhKUwpjnEHyaI9wugGhdSeKR3UwIojiXc8MmLHnufBC+Sa8XHFal3of718ZV+JNovC
         2m46soLUz36ENAdzl/jYa2EyTO+L4GhPV5c16arhVAYLu11z0v6hZu/pzLnfFvR5/eIv
         lhM8qw5LheY6kOcw8u1Wgku9/9mT9bYnXufWmxvN6dXmqMJFcs2B/cpHSSRxLwJVFDSg
         OmnqmAc6dvI4BLQUP1Vs4vpEi2+/7iTQN20fbx4hHjahdCz4Tolj+4HWRV4Odn2lc3Fv
         L4/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qv8ZHds2eTWQ0EUWvVRBqR2tiVx11jw6rlo5/Ez4dVU=;
        b=bAoHZj02Wbu/bbo7ADYPfwcSPPD14hnDzPjuYlwcO3PRctAvUgGzpGIrDHtGTD8zld
         45T6v3OeWp5BEbwML+scaikk0CWcZ0eEnnwbJXlywNKdqxkWtg7XwIRNf1G+LGX4goOT
         vCkdC6+ju7Zj+dWS5AvEgBg6qyJDzHjaR7xep3sTMukVCVA7Oq4w/3DUM7IgAsZNv59A
         f6i/f+cPATxjZqZFttMWC+h5oPDZZSsVNplsKrzV2EmTKKYrDsBGakROHiZYp5UT8nGO
         +Z7QsCF7ObgWlWFqfo6gfXA16TCYcinAE64nYLafVsHPDa7V4N1lira5NG2I68ShrvqP
         wy/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ekEr6ftz;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id i4si165971pgl.0.2020.05.20.10.08.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 May 2020 10:08:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id n15so1614336pjt.4
        for <kasan-dev@googlegroups.com>; Wed, 20 May 2020 10:08:48 -0700 (PDT)
X-Received: by 2002:a17:90a:21c9:: with SMTP id q67mr6204249pjc.166.1589994527943;
 Wed, 20 May 2020 10:08:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200520123434.3888-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200520123434.3888-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 May 2020 19:08:36 +0200
Message-ID: <CAAeHK+wyg90Tw_Fp+A1vkW3rK+WKwPi_oS4T4SVL-fEYYaU0Lw@mail.gmail.com>
Subject: Re: [PATCH v5 1/4] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ekEr6ftz;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, May 20, 2020 at 2:34 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This feature will record the last two call_rcu() call stacks and
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
>  mm/kasan/report.c     | 24 ++++++++++++++++++++++++
>  6 files changed, 61 insertions(+), 2 deletions(-)
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
> index 80f23c9da6b0..29a801d5cd74 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -105,6 +105,17 @@ static void end_report(unsigned long *flags)
>         kasan_enable_current();
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

The idea of moving it here was to reuse print_stack() in print_track() :)

> +
>  static void print_track(struct kasan_track *track, const char *prefix)
>  {
>         pr_err("%s by task %u:\n", prefix, track->pid);
> @@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200520123434.3888-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwyg90Tw_Fp%2BA1vkW3rK%2BWKwPi_oS4T4SVL-fEYYaU0Lw%40mail.gmail.com.
