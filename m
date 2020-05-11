Return-Path: <kasan-dev+bncBCMIZB7QWENRBIUG4X2QKGQETF4LRLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id D28031CD985
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 14:20:51 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id b13sf8667828pfp.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 05:20:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589199650; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpbdZm9gCHd9NGBl4t+/PtDJuFc4mKOcGLkweZ0vbeylpMPVnt8YhabGZpPpOqL2hr
         vAyjCOrpbH7olvrER/LTbZ8FXHAgB/1DfJP9urdpmllkXc6ZxiUqMpV3KjcVFBkObx9p
         oEFk/bTVFdquxdL1e9Va3gS8BYu2ueAJ/gVV0PyIIcJwgPMgZWTOWkxXHD1pjn5Y7Pqi
         /Sgf9QRqAyLPxNodP0238mLaOSRZX+W5jlXMJD0DI1GrqUOUOCqqGqhXMob0qqJ9hI91
         1k2+ykQSqw+/VCdJ+P976Gdr/WHek8Weci5y8fwzEzGH+wd75Ex8/X7Vhf6gsfkXE8+n
         l6+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+bwJrDpByKGhfo1WfGeaPgEsqheCd/ow9ZvinNM1JNw=;
        b=EWGVsAiD7ZRY48Ar0qI0jGrSZSb0hAlzZtL/HHk8VMbnQJMkO17iPw6iOkAKk20ila
         j65N6ESPIA38EgHXBZQG+PAMX/zikaxgod5/k9Nj/90Lql+QswYOdSwY90jObUFQ3sWK
         sF2tO0sMyhJWYlvOkD5Cf6TkkJn0ENv62wga0A0zIhaFevh2oAcqezPeuF9HXZT6bQFX
         1xdQZt/5+3tI2A1JYCt9H6LoS8tfoW4Ltys1KDt3byP+uziv2jojU7DX0GBxBuoeHdC/
         /E1/M6MdFj2snVacQqnNuwSUmHC2Pjxx16aPQ6/5f3DO7ViQnMd7+lC3A++cCVB6TXN4
         fFJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lceb2SyN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+bwJrDpByKGhfo1WfGeaPgEsqheCd/ow9ZvinNM1JNw=;
        b=YDoEaCvx5Cu8udrap+2aYy6ujFnaXxEhLu4+Py10aDQeolTVpcnvANFF5MASDl256P
         wk66Wf4LnLrU4rUryIwTbx99rOepavVTNPm5i0llkB5+C31ncLKe2S33ipKRZfp3eT81
         mSX6BqV/7BKfa2NOm40ubPynX1FeDTqcVj/pylhjoPFf+c9jL6EqVZJTUI8NatNi9AwV
         UlAXBhxK7FyQhztcD3kYbDDeO28Uwpw71N3k7hLYWqyJRIpkp2b+MWYbb5EQW8QZ4JtB
         jKctOD6dRanTWMw4qUQX/IbU6wdsfVZjKEltg+RfMdcV5uMZKF0lG+8K72taIdDZ3ZUs
         0Sxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+bwJrDpByKGhfo1WfGeaPgEsqheCd/ow9ZvinNM1JNw=;
        b=jOIyTyJj9KP0GaZp5BhWYuSMKuBpRn8NtXgV3P8eghGaMLZeTnSoI17t8dQe9dt4Ni
         9faKsQDvxFpQS3CoynP/5CJ5RYDvHAYo3eXBS/oIuun5gcJbJC5RPFHPCL8USyh2OWkg
         TVCtPhNQqYQKa/E80DUnFPuvFZ2NDRoqfy8gkqN67TF35mP0IoBuU9LZPzeZh7983FGA
         J9S++FNnVbVt8Uzfz80FlNfNF+mAti5WwDPBgoeWgKSAP39u3JAsxCf2e3J2QmYKL/tQ
         geSU0d6wQ61caoWYwxtdLZeKGElECR5P1wbTSzzUwC/BPhrSCb5s7s7wvhclLxjsaYeJ
         tsAw==
X-Gm-Message-State: AGi0Pubo1km1gr5dBLM7g8nDQOcSvGAko1lzEU8kNoZyTSI0ckObyxaS
	nAjbdlNDSjWxxL30YVJZA3c=
X-Google-Smtp-Source: APiQypIgQ1QcgEY2orypUQOIqfdiPN5bKLj6Yb9x6vwrQxXEvPgFSnntFs8Ts0S9gdoeytQaFjQlJA==
X-Received: by 2002:a63:b11:: with SMTP id 17mr14458221pgl.3.1589199650529;
        Mon, 11 May 2020 05:20:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ca12:: with SMTP id x18ls16514438pjt.2.canary-gmail;
 Mon, 11 May 2020 05:20:50 -0700 (PDT)
X-Received: by 2002:a17:90a:e28c:: with SMTP id d12mr22727731pjz.19.1589199650102;
        Mon, 11 May 2020 05:20:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589199650; cv=none;
        d=google.com; s=arc-20160816;
        b=KGrHV4gGnGysjM8PI56dJkma/MHpgHsULrxGCmTW5TteVvqUDLq/gQdv5u9mFFbdPv
         sf/HdVvSu5Gs2h2e7alf8QaG4GJDRMxX2OVNRUyDmjassJR0pZFT4bVMZ/nVUVlPgDnx
         PW3nnG4F8zoNsNqyS88C38KtU7I2ijb+znHR0UAy2uVYW14QqPmvnkZwU+4q9VlYJbiV
         jqfW12IJzIJIFvqASfRtoQ/uP4TY3KGsy5+gHlVrUagUuNR0iLr2TGZnPA+ZgDvnFJ+G
         de4/gfXgEsmPA2HdWU6WSCd5s4e8V5B3G6rrQ8VWfhGlaCbB+EA9GwIuWHBXG96NZo2j
         Ritw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gHerBltEFbSQB6JpCoZUBJ5FOBr384eNhmsbaYTRVmE=;
        b=ZFAlW6vgIRHt4gCo5H+gskLqM/kLsfHEgKNiQTQ59hhUJn0HjaU76w8Lwda11JHQ0T
         aoz4+4RnMcaaH81bDFH4jLPEVzQ2Pz7sEXDdjpe+qHXjmG9kfCqZLqG29N3/DRhS07Od
         +zrP5ccwtdli6AXKKRCP9rhXxHGBIuKHq+FL/z0ZW2uW5s4DRK9TQ9v8ywszDZHY9DOy
         LrhlqXhUX0LvnXzDyYB1u4r4hUZzgrk4dKttuKIr7f4wPKHPWy6C5HV7m/cQ6nG0iMh6
         PGTk760Dqxyr+K3aRxK/EF2lx/7e+52lQFz6TxrFlUKFXkmuuhfYNJSldsWApe1eOjdv
         9y7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lceb2SyN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id x5si48064pjo.0.2020.05.11.05.20.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 May 2020 05:20:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id 4so7684574qtb.4
        for <kasan-dev@googlegroups.com>; Mon, 11 May 2020 05:20:50 -0700 (PDT)
X-Received: by 2002:aed:3668:: with SMTP id e95mr16523921qtb.50.1589199648859;
 Mon, 11 May 2020 05:20:48 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 May 2020 14:20:37 +0200
Message-ID: <CACT4Y+beDTzGrDx9uWSjbr67j0encwBa_1PKpyQCejiddLhOxA@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
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
 header.i=@google.com header.s=20161025 header.b=Lceb2SyN;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Mon, May 11, 2020 at 4:31 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This feature will record first and last call_rcu() call stack and
> print two call_rcu() call stack in KASAN report.
>
> When call_rcu() is called, we store the call_rcu() call stack into
> slub alloc meta-data, so that KASAN report can print rcu stack.
>
> It doesn't increase the cost of memory consumption. Because we don't
> enlarge struct kasan_alloc_meta size.
> - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> - remove free track from kasan_alloc_meta, size is 8 bytes.
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
>  kernel/rcu/tree.c     |  3 +++
>  lib/Kconfig.kasan     |  2 ++
>  mm/kasan/common.c     |  4 ++--
>  mm/kasan/generic.c    | 29 +++++++++++++++++++++++++++++
>  mm/kasan/kasan.h      | 19 +++++++++++++++++++
>  mm/kasan/report.c     | 21 +++++++++++++++++----
>  7 files changed, 74 insertions(+), 6 deletions(-)
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
> index 06548e2ebb72..de872b6cc261 100644
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
> @@ -2694,6 +2695,8 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
>                 trace_rcu_callback(rcu_state.name, head,
>                                    rcu_segcblist_n_cbs(&rdp->cblist));
>
> +       kasan_record_aux_stack(head);
> +
>         /* Go handle any RCU core processing required. */
>         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
>             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..56a89291f1cc 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -58,6 +58,8 @@ config KASAN_GENERIC
>           For better error detection enable CONFIG_STACKTRACE.
>           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>           (the resulting kernel does not boot).
> +         Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> +         call stack. It doesn't increase the cost of memory consumption.
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
> index 56ff8885fe2e..b86880c338e2 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -325,3 +325,32 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
> +       if (!alloc_info->rcu_stack[0])
> +               /* record first call_rcu() call stack */
> +               alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +       else
> +               /* record last call_rcu() call stack */
> +               alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> +                                               u8 idx)
> +{
> +       return container_of(&alloc_info->rcu_stack[idx],
> +                                               struct kasan_track, stack);

This is not type safe, there is no kasan_track object. And we create a
pointer to kasan_track just to carefully not treat it as valid
kasan_track in print_track.

This adds an unnecessary if to print_track. And does not seem to be
useful/nice to print:

First call_rcu() call stack:
(stack is not available)

Last call_rcu() call stack:
(stack is not available)

when no rcu stacks are memorized.
Your intention seems to be to reuse 2 lines of code from print_track.
I would factor them out into a function:

static void print_stack(depot_stack_handle_t stack)
{
        unsigned long *entries;
        unsigned int nr_entries;

        nr_entries = stack_depot_fetch(stack, &entries);
        stack_trace_print(entries, nr_entries, 0);
}

And then this can expressed as:

        if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
            stack = alloc_info->rcu_stack[0];
            if (stack) {
                pr_err("First call_rcu() call stack:\n");
                print_stack(stack);
                pr_err("\n");
            }
            stack = alloc_info->rcu_stack[1];
            if (stack) {
                pr_err("Last call_rcu() call stack:\n");
                print_stack(stack);
                pr_err("\n");
            }
        }


Or with another helper function it becomes:

        if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
            print_aux_stack(alloc_info->rcu_stack[0], "First");
            print_aux_stack(alloc_info->rcu_stack[1], "Last");
        }


> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..1cc1fb7b0de3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -96,15 +96,28 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> +#ifdef CONFIG_KASAN_GENERIC
> +#define SIZEOF_PTR sizeof(void *)
> +#define KASAN_NR_RCU_CALL_STACKS 2
> +#else /* CONFIG_KASAN_GENERIC */
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
>  #endif
> +#endif /* CONFIG_KASAN_GENERIC */
>
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
> +#ifdef CONFIG_KASAN_GENERIC
> +       /*
> +        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +        * The free stack is stored into freed object.
> +        */
> +       depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> +#else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#endif
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>         u8 free_track_idx;
> @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>
>  struct page *kasan_addr_to_page(const void *addr);
>
> +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
>  void quarantine_reduce(void);
>  void quarantine_remove_cache(struct kmem_cache *cache);
> +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> +                       u8 idx);
>  #else
>  static inline void quarantine_put(struct kasan_free_meta *info,
>                                 struct kmem_cache *cache) { }
>  static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> +static inline struct kasan_track *kasan_get_aux_stack(
> +                       struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
>  #endif
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..f16a1a210815 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
>         kasan_enable_current();
>  }
>
> -static void print_track(struct kasan_track *track, const char *prefix)
> +static void print_track(struct kasan_track *track, const char *prefix,
> +                                               bool is_callrcu)
>  {
> -       pr_err("%s by task %u:\n", prefix, track->pid);
> +       if (is_callrcu)
> +               pr_err("%s:\n", prefix);
> +       else
> +               pr_err("%s by task %u:\n", prefix, track->pid);
>         if (track->stack) {
>                 unsigned long *entries;
>                 unsigned int nr_entries;
> @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
>         if (cache->flags & SLAB_KASAN) {
>                 struct kasan_track *free_track;
>
> -               print_track(&alloc_info->alloc_track, "Allocated");
> +               print_track(&alloc_info->alloc_track, "Allocated", false);
>                 pr_err("\n");
>                 free_track = kasan_get_free_track(cache, object, tag);
> -               print_track(free_track, "Freed");
> +               print_track(free_track, "Freed", false);
>                 pr_err("\n");
> +
> +               if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +                       free_track = kasan_get_aux_stack(alloc_info, 0);
> +                       print_track(free_track, "First call_rcu() call stack", true);
> +                       pr_err("\n");
> +                       free_track = kasan_get_aux_stack(alloc_info, 1);
> +                       print_track(free_track, "Last call_rcu() call stack", true);
> +                       pr_err("\n");
> +               }
>         }
>
>         describe_object_addr(cache, object, addr);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511023111.15310-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbeDTzGrDx9uWSjbr67j0encwBa_1PKpyQCejiddLhOxA%40mail.gmail.com.
