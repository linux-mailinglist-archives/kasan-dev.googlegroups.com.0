Return-Path: <kasan-dev+bncBAABB2FH432QKGQECVIUYRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AAB41CE23A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 20:05:30 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id 91sf4805984pld.12
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 11:05:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589220328; cv=pass;
        d=google.com; s=arc-20160816;
        b=jsjJvuyHaGehRbVxGHevDhDEtej3/7QwzKlL/J5zryyx7x/M2pIKhbhP+a+A0bIdSJ
         M2DWcGeGg7fgiqaEDkPM2ZWf/CUM9942PNZzJsuz4obg9M2d0EAHBsBY35T4cg0/zueS
         atQhNT/BJCLU/XunM4RWHdzcp0o8qD1reaUeAWhgJcmUPyB5TNWrHGkdnSGO8BX48/NS
         6aManYk6k82kJrBZFMM6GARaBMrMkiHh3twm7N6GJdI8spvn70LRnz29qRIzUHPmYfnA
         Jb/KDOIf+PqsRoyHiKqaG/xryYWLCN8houPxqIFYGhicG7p+8vjIFcjbRi3bDeDMZ7QO
         /TNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=FMZKaJj2IMaV45rtxuf5hZJtWZlhSL0JIZT4JTmVfbI=;
        b=izAUIXLj9joPNwqt5Bd3h+CgpABkgHay/nS/1JxDKjvG9r071GB29Z9ZBS6MNsHkOv
         RSmX02v62j/xOx04WCI2BLC/lHWueoqAK8F6x4rP5tK5Ye5r7tm4AhNW9SoFpHtP0zMJ
         IHXSLdTMS5GtONanBM1cJir7rBDFGcRJAFu8UHBMeTjxi4Iy8kKgIyf3IrjOmSPDkPK9
         zCRRd9bd0SbXqEZJHFE1q7NCWQn31h//lgaY8hGrHt4/+EMBGrqfgeP/m5ouKbrDZT3K
         dXF4Mzy3NucChQGYhZ5ro2yGlod4oR+H4nc/jWwULLDHJsGTLCaco6Y3VWpiMZnfnjAV
         BN8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Z/n5ZySK";
       spf=pass (google.com: domain of srs0=k328=6z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=K328=6Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FMZKaJj2IMaV45rtxuf5hZJtWZlhSL0JIZT4JTmVfbI=;
        b=qiiPpQ7oqhbClO0tZCkR7RKwAFxPyOTZeOUZb/Uq6eF+QsEpeSNb+TAUT18mDVqhGc
         /OE5GeI72PB0SZB/EZ/hBMJHWomLhzE2uzzy/jBOb1RnLNKYQgSaA+uJm2InwB30slzn
         F2JMan+dbXeocjs1D0Lc8AurDpYKfcKDbGLkSgoDLk59CHJOlM3uj4e42IXmmA0PToN2
         X4SMUmYWBOGYBnWv3fZ2vbj7mxvjyHrJv+vSDKYm7MmmqKfD8z1g2IH3oyvZgJQIYmnL
         BP8X1JU6HSkgmqrXtrTinge6fj3Nf2jm9uq1e3/tr5rd3WJm2Eg8dKi2PzlHaeqSiBi3
         df2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FMZKaJj2IMaV45rtxuf5hZJtWZlhSL0JIZT4JTmVfbI=;
        b=HskvTsE3rVbqo9ZYlsAn/Kj5gY7vC0r/F3TeuBMQFFwaOLhpULXear6SjEumlVnOAG
         oObSTfBKPTxAYWaeAKUA9kb+ENi3gIhgLXl++4Odv+wQXdf3X/R3v47ZsffmzJ4c4xvy
         YFNRFEfSuXUm61Xl0Tv4jz0ag08K3pCOTggrsIso9OtajyT37UXpGKh7Gl0j6StXTapq
         hiL2aUurgRWAkO5Hq/Hq1bFNvHPSKl7r6a1eHXgb9/U0Kz5wSYPxxK7LvknSBzlbgw2j
         MAhrEqKNB4FKw6itXCX1YtemaFOosta/nRjOH4EpcynNO2JLXOtvNFEMVt/XdXngzWty
         6ZvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZMy6iQ16XmBadjwDjimKWFHXDuqGIewTORQ5PxhhpLQveWlJh5
	05hNVdgjye2lUbTxMn4bthI=
X-Google-Smtp-Source: APiQypK6tE33+gjjkdph8UIjnmeFha6iBUjTny18mcG7vj3CAzMEeYMk1OJgZGeoea0WyW4UAODZNA==
X-Received: by 2002:a63:d909:: with SMTP id r9mr15284495pgg.245.1589220328468;
        Mon, 11 May 2020 11:05:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a717:: with SMTP id w23ls5148656plq.7.gmail; Mon, 11
 May 2020 11:05:28 -0700 (PDT)
X-Received: by 2002:a17:90a:37ea:: with SMTP id v97mr25263077pjb.206.1589220328078;
        Mon, 11 May 2020 11:05:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589220328; cv=none;
        d=google.com; s=arc-20160816;
        b=VV6SFbUUi+pb8/u9o6TaDfLpsLl72WkLG98E3wUxunOVz3zlTX7inMpmU8pfa5wQwZ
         LNh/+136uBkhazSp7lJztdIF4leIfyjgOvkTnjuhoY11pj4EpDwSv8DX56Igy9vDcN0u
         Gp/zjega4yrZDV9SvUUHtLH+HjYC8aPMtoJRYCojEV2y325epoMeIHQyPvVIXfmGDPhl
         +xi1Yd8HslZQ+7HgZzmaoTO3QvhQqZnh5nCb6Kw/lmNVRruRoVOJbN6Uxc1tNPh7izQQ
         6R86XuKbXf7SK5ISAEfph8BWAsdWyZh1fnY9/Mh6Qvu1mrE0oK4NjB5jHpimjq70GtYq
         uLEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=EiT/zxijE03tTIzd/vH9odEb+ms8X76XQjy/RjUpIe4=;
        b=JWAv+QgI/C7OQ3ea+WWpjhGtEcyPO0t9fz5l5+rYsXJNv/khn/9B7E1Huu4zNTcMZl
         FCvFgzuGkGKXfJi9m55GbEyn/Y/eBh3cMCohHw8S3dGR7hAgXAqyuUh4I3flWMnjxvcd
         X9FU131gR5WfO97ZrmDgWGTJKKjocwlBNsZ7/GjEwod0W5doGM5T4VBjAYH+LsR9rcEw
         j9m0aZPTlQkL/41YZr/44RgVNFWj9J8BMq+BrirweZpPnc2HQowGKeslzbGWxteA9pem
         p8iXYqCqpuHswlaOYQdI3rmtL10vkEkS2dlEuwWpAggyLZLgwdPEBtnNOA5XO96jRltJ
         uKqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Z/n5ZySK";
       spf=pass (google.com: domain of srs0=k328=6z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=K328=6Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x5si169554pjo.0.2020.05.11.11.05.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 May 2020 11:05:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=k328=6z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BC0E1206B9;
	Mon, 11 May 2020 18:05:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id A3CBB352271C; Mon, 11 May 2020 11:05:27 -0700 (PDT)
Date: Mon, 11 May 2020 11:05:27 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Josh Triplett <josh@joshtriplett.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	wsd_upstream <wsd_upstream@mediatek.com>,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
Message-ID: <20200511180527.GZ2869@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="Z/n5ZySK";       spf=pass
 (google.com: domain of srs0=k328=6z=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=K328=6Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, May 11, 2020 at 10:31:11AM +0800, Walter Wu wrote:
> This feature will record first and last call_rcu() call stack and
> print two call_rcu() call stack in KASAN report.

Suppose that a given rcu_head structure is passed to call_rcu(), then
the grace period elapses, the callback is invoked, and the enclosing
data structure is freed.  But then that same region of memory is
immediately reallocated as the same type of structure and again
passed to call_rcu(), and that this cycle repeats several times.

Would the first call stack forever be associated with the first
call_rcu() in this series?  If so, wouldn't the last two usually
be the most useful?  Or am I unclear on the use case?

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
>  		trace_rcu_callback(rcu_state.name, head,
>  				   rcu_segcblist_n_cbs(&rdp->cblist));
>  
> +	kasan_record_aux_stack(head);

Just for the record, at this point we have not yet queued the callback.
We have also not yet disabled interrupts.  Which might be OK, but I
figured I should call out the possibility of moving this down a few
lines to follow the local_irq_save().

If someone incorrectly invokes concurrently invokes call_rcu() on this
same region of memory, possibly from an interrupt handler, we are OK
corrupting the stack traces, right?

But what happens if a given structure has more than one rcu_head
structure?  In that case, RCU would be just fine with it being
concurrently passed to different call_rcu() invocations as long as the
two invocations didn't both use the same rcu_head structure.  (In that
case, they had best not be both freeing the object, and if even one of
them is freeing the object, coordination is necessary.)

If this is a problem, one approach would be to move the
kasan_record_aux_stack(head) call to kfree_rcu().  After all, it is
definitely illegal to pass the same memory to a pair of kfree_rcu()
invocations!  ;-)

							Thanx, Paul

> +
>  	/* Go handle any RCU core processing required. */
>  	if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
>  	    unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..56a89291f1cc 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -58,6 +58,8 @@ config KASAN_GENERIC
>  	  For better error detection enable CONFIG_STACKTRACE.
>  	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>  	  (the resulting kernel does not boot).
> +	  Currently CONFIG_KASAN_GENERIC will print first and last call_rcu()
> +	  call stack. It doesn't increase the cost of memory consumption.
>  
>  config KASAN_SW_TAGS
>  	bool "Software tag-based mode"
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
>  	unsigned long entries[KASAN_STACK_DEPTH];
>  	unsigned int nr_entries;
> @@ -54,7 +54,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
>  static inline void set_track(struct kasan_track *track, gfp_t flags)
>  {
>  	track->pid = current->pid;
> -	track->stack = save_stack(flags);
> +	track->stack = kasan_save_stack(flags);
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
> +	struct page *page = kasan_addr_to_page(addr);
> +	struct kmem_cache *cache;
> +	struct kasan_alloc_meta *alloc_info;
> +	void *object;
> +
> +	if (!(page && PageSlab(page)))
> +		return;
> +
> +	cache = page->slab_cache;
> +	object = nearest_obj(cache, page, addr);
> +	alloc_info = get_alloc_info(cache, object);
> +
> +	if (!alloc_info->rcu_stack[0])
> +		/* record first call_rcu() call stack */
> +		alloc_info->rcu_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +	else
> +		/* record last call_rcu() call stack */
> +		alloc_info->rcu_stack[1] = kasan_save_stack(GFP_NOWAIT);
> +}
> +
> +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> +						u8 idx)
> +{
> +	return container_of(&alloc_info->rcu_stack[idx],
> +						struct kasan_track, stack);
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..1cc1fb7b0de3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -96,15 +96,28 @@ struct kasan_track {
>  	depot_stack_handle_t stack;
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
>  	struct kasan_track alloc_track;
> +#ifdef CONFIG_KASAN_GENERIC
> +	/*
> +	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +	 * The free stack is stored into freed object.
> +	 */
> +	depot_stack_handle_t rcu_stack[KASAN_NR_RCU_CALL_STACKS];
> +#else
>  	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#endif
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>  	u8 free_track_idx;
> @@ -159,16 +172,22 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>  
>  struct page *kasan_addr_to_page(const void *addr);
>  
> +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +
>  #if defined(CONFIG_KASAN_GENERIC) && \
>  	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
>  void quarantine_reduce(void);
>  void quarantine_remove_cache(struct kmem_cache *cache);
> +struct kasan_track *kasan_get_aux_stack(struct kasan_alloc_meta *alloc_info,
> +			u8 idx);
>  #else
>  static inline void quarantine_put(struct kasan_free_meta *info,
>  				struct kmem_cache *cache) { }
>  static inline void quarantine_reduce(void) { }
>  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> +static inline struct kasan_track *kasan_get_aux_stack(
> +			struct kasan_alloc_meta *alloc_info, u8 idx) { return NULL; }
>  #endif
>  
>  #ifdef CONFIG_KASAN_SW_TAGS
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..f16a1a210815 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
>  	kasan_enable_current();
>  }
>  
> -static void print_track(struct kasan_track *track, const char *prefix)
> +static void print_track(struct kasan_track *track, const char *prefix,
> +						bool is_callrcu)
>  {
> -	pr_err("%s by task %u:\n", prefix, track->pid);
> +	if (is_callrcu)
> +		pr_err("%s:\n", prefix);
> +	else
> +		pr_err("%s by task %u:\n", prefix, track->pid);
>  	if (track->stack) {
>  		unsigned long *entries;
>  		unsigned int nr_entries;
> @@ -187,11 +191,20 @@ static void describe_object(struct kmem_cache *cache, void *object,
>  	if (cache->flags & SLAB_KASAN) {
>  		struct kasan_track *free_track;
>  
> -		print_track(&alloc_info->alloc_track, "Allocated");
> +		print_track(&alloc_info->alloc_track, "Allocated", false);
>  		pr_err("\n");
>  		free_track = kasan_get_free_track(cache, object, tag);
> -		print_track(free_track, "Freed");
> +		print_track(free_track, "Freed", false);
>  		pr_err("\n");
> +
> +		if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +			free_track = kasan_get_aux_stack(alloc_info, 0);
> +			print_track(free_track, "First call_rcu() call stack", true);
> +			pr_err("\n");
> +			free_track = kasan_get_aux_stack(alloc_info, 1);
> +			print_track(free_track, "Last call_rcu() call stack", true);
> +			pr_err("\n");
> +		}
>  	}
>  
>  	describe_object_addr(cache, object, addr);
> -- 
I> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511180527.GZ2869%40paulmck-ThinkPad-P72.
