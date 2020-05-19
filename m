Return-Path: <kasan-dev+bncBAABBRH7R73AKGQE46GQEAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DAC41D9B9D
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 17:48:21 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id n14sf11073391pgr.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 08:48:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589903300; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xwo+JJHmCgR6kzMxjyP8xtAiQlk87yiz1eHJa0kVZ5MZEJTZTziyl3f36YY2CGrY9+
         DTIvG7ZcS9RbMkDzHOGJvnqGRjg83Zh4TWQscXv+7wo7Ffn8vr0TH2NqKScLIKkKLLiB
         omlsrhc42IzB5Q1M3FVzL7avqT6jGAJTi9Lx9dQK2GYRUE0UD8mB/Ox0mmYBSksnStzY
         eJ2nnuB4h8fDoVyoSXpebzaLu5fysU5/TOymT6/f9XCNQAQsJrE2rBZz14EPRYORfuIj
         gRvKvECra8pAHuNjnpv7BwiphqwEtFFQQEioXIKMsDaSRTW9fE5y24cEtQPaZ0gAOc38
         8p8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+qAajrMq3ydAz/N0yBR9HTuaIns/UJ3XQ0r5VLjBN3k=;
        b=G5zYxnd2YY9cD7NSS2AXbvJbqVLu03pMtATz6mfOjeaKi9CjL8h3fifqtxCh6NZj26
         cXU0XGcNJh9+VdyJ0DvhvQcj8o9GqtkIJw1pRkLFzFVZ3QGVVOXSLGDfnHfYJoRfvOGl
         yvG47wAI0aQVJjTeQQHxDKhB4QmuPuf8pX0IXMWPSpoTarpXisOEMppxYAeo/VBbfsU1
         kpe02+p0DPvUwQl4W1Uk1G4jwMJ0Jk/Qc/xhbXaCOTl0nr3E+XgG4g7wTsfCFAO1Ii3D
         7ZukayD46M0Rjp8Z1Ng7gTX09Fw5tUR6sTLktdLF39xUq+cByZ2rePz7GkfIHm7cFL8f
         tV+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="bn/NLnfD";
       spf=pass (google.com: domain of srs0=+ilb=7b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+iLB=7B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+qAajrMq3ydAz/N0yBR9HTuaIns/UJ3XQ0r5VLjBN3k=;
        b=bcWuOveoUeYTz/BtHuYD9yk2MTrknbCurgbnh4Zwr5K8iiYibp7RAPgyXjsA5wNtbt
         QoA64AbQMSCnsZ0OMR17OiyqFQr8bddfIf5q5PXItK5Xm70gav8kaMfr8H1n9gDaVE84
         CFPERYXWOV7Zn35CKrx/SctH2T5CNiJ/x713p4OHM/2h58nw5E0TT7V7afSUyG5GzKNZ
         kSzN1aI0a4vcXz5PzWKTxvLl/ovTv2S6N5vmOLYB/4M4DcemOhxWU4w36MnzOqtCVEZ8
         EI0sS49KgRVqzfE0mtGIhgCPjvwhZfnOFtfVm9XCvABqO+JZ65HC4lR423LuxlisodAD
         Q0OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+qAajrMq3ydAz/N0yBR9HTuaIns/UJ3XQ0r5VLjBN3k=;
        b=gZ2gIE28AIh6Q7njalNSuCaO3WOaC8qiFwdqNGGTZPpxVJHIH8SXQgohxsPI+JD4x6
         RslGCSkLyAemZC6WvLFCDwqGYYSbF7F3IBumWWPUtlbyRUHvAt6jxvMGRTXikYoeLP8r
         Cf3K/dji0oBK57ZthU1/5YyT3XQbPPX30hxAakk9aNiTif04Wyws8JXjSqk/uelHtS1+
         th/2jagqtSxu3zMrlFCmGvmate1vxsELWF56EDzFmw94DKtgUlLv/N1SiF/kid4BR00f
         upFHSIAYS6Py04SvzM0u9ePl+c/Zpdm54v7Bz3RHONtQ5A6DOjOFPVvDCv6HR4E+b2Cm
         4fbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mvyqeRj0OTC79R3Ej0pE5RDXwCgtPAN8hpxqO2G4PCPcajzlW
	o4Yx06Adz7o8M7gnSjAp0SA=
X-Google-Smtp-Source: ABdhPJxZvgnXXtLMHg07wAJXRC9ptm1QtkT1ZGhBQrbrr9UwV8/YpFumzigRtmyxrY5HRP4Q1y7MeQ==
X-Received: by 2002:a17:90a:2e82:: with SMTP id r2mr216101pjd.128.1589903300248;
        Tue, 19 May 2020 08:48:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9638:: with SMTP id r24ls2496572pfg.3.gmail; Tue, 19 May
 2020 08:48:19 -0700 (PDT)
X-Received: by 2002:a62:5289:: with SMTP id g131mr23402830pfb.318.1589903299804;
        Tue, 19 May 2020 08:48:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589903299; cv=none;
        d=google.com; s=arc-20160816;
        b=HGPUyxGaq1E9N0nQLhFYYLtk1L4WM5LCuWQIMXZ6MQwGB9RBnlRIkFTqBXbyaYp8N4
         kd2r7SCUlZM8sLJIM058nQ2cRqu0l18x4YBNjklH2kDcgoDYbOo5DMVN/0LjqCXaWhGL
         ZD984wfbId8irlx0yyT2LdvdRWs54EanlH4XDMgr0o/1pj75iF2UBKhSZdj79jSsl91N
         JJBmAP7tgCoZiZkNLDg7oTncVlwXSfcGG5aeQWrxvh+/NoqxvSWIfdvGFSNVKXOAjBCp
         wuDYmcJsioN5FZcIRTSovj9MowMRlxTTyIYC3rL5yjBlb9O/qDi0gQycP8+AKcn2OTcx
         IqKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=+IRK0AQJjbaazCRQwCi/jf84bWBb4wnwrRIzoYNanGg=;
        b=GjP4iINqXXHXzUQ3lyga4D3YdR4jjZW14X6dVtkJ+74LVHspg2Gwwrjb4dZ6DN2U/O
         ZHKkG4iHQUUECIn7f6ag/DFw+rbe+pHQpSO5wdnTujZ/r8EqIqYxexJqTOsdUWL0LD3N
         8sKlb86JKqUi13CQgNoFrVO7kelYw6R8Ejd+5miDwlBufyCVt0BjGaYeUmFDeIBRWSxI
         cyxq35wpVSSzGPuSX1EKoLIWs/8kyVfBA6cKcm5GMY4utWx33VEocwWZGUTEM3KSHc40
         bjsAwKKSAEJgf+EWdZoJ8WEX90Qn8IbafIWXCDmMOCi9GpD8FwPmaLdKkpA0rlO7FuRd
         3X/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="bn/NLnfD";
       spf=pass (google.com: domain of srs0=+ilb=7b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+iLB=7B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e6si226546pjp.3.2020.05.19.08.48.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 May 2020 08:48:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=+ilb=7b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7C5C920709;
	Tue, 19 May 2020 15:48:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 649EE3523462; Tue, 19 May 2020 08:48:19 -0700 (PDT)
Date: Tue, 19 May 2020 08:48:19 -0700
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
Subject: Re: [PATCH v4 1/4] rcu/kasan: record and print call_rcu() call stack
Message-ID: <20200519154819.GJ2869@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200519022359.24115-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200519022359.24115-1-walter-zh.wu@mediatek.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="bn/NLnfD";       spf=pass
 (google.com: domain of srs0=+ilb=7b=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+iLB=7B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, May 19, 2020 at 10:23:59AM +0800, Walter Wu wrote:
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
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Josh Triplett <josh@joshtriplett.org>
> Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> Cc: Joel Fernandes <joel@joelfernandes.org>

From an RCU perspective:

Acked-by: Paul E. McKenney <paulmck@kernel.org>

> ---
>  include/linux/kasan.h |  2 ++
>  kernel/rcu/tree.c     |  2 ++
>  lib/Kconfig.kasan     |  2 ++
>  mm/kasan/common.c     |  4 ++--
>  mm/kasan/generic.c    | 19 +++++++++++++++++++
>  mm/kasan/kasan.h      | 10 ++++++++++
>  mm/kasan/report.c     | 24 ++++++++++++++++++++++++
>  7 files changed, 61 insertions(+), 2 deletions(-)
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
>  	head->func = func;
>  	head->next = NULL;
>  	local_irq_save(flags);
> +	kasan_record_aux_stack(head);
>  	rdp = this_cpu_ptr(&rcu_data);
>  
>  	/* Add the callback to our list. */
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..4e83cf6e3caa 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -58,6 +58,8 @@ config KASAN_GENERIC
>  	  For better error detection enable CONFIG_STACKTRACE.
>  	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
>  	  (the resulting kernel does not boot).
> +	  In generic mode KASAN prints the last two call_rcu() call stacks in
> +	  reports.
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
> index 56ff8885fe2e..3372bdcaf92a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -325,3 +325,22 @@ DEFINE_ASAN_SET_SHADOW(f2);
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
> +	/* record the last two call_rcu() call stacks */
> +	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
> +	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +}
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..a7391bc83070 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -104,7 +104,15 @@ struct kasan_track {
>  
>  struct kasan_alloc_meta {
>  	struct kasan_track alloc_track;
> +#ifdef CONFIG_KASAN_GENERIC
> +	/*
> +	 * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +	 * The free stack is stored into struct kasan_free_meta.
> +	 */
> +	depot_stack_handle_t aux_stack[2];
> +#else
>  	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#endif
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>  	u8 free_track_idx;
> @@ -159,6 +167,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip);
>  
>  struct page *kasan_addr_to_page(const void *addr);
>  
> +depot_stack_handle_t kasan_save_stack(gfp_t flags);
> +
>  #if defined(CONFIG_KASAN_GENERIC) && \
>  	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..6f8f2bf8f53b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -179,6 +179,17 @@ static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  	return &alloc_meta->free_track[i];
>  }
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +static void print_stack(depot_stack_handle_t stack)
> +{
> +	unsigned long *entries;
> +	unsigned int nr_entries;
> +
> +	nr_entries = stack_depot_fetch(stack, &entries);
> +	stack_trace_print(entries, nr_entries, 0);
> +}
> +#endif
> +
>  static void describe_object(struct kmem_cache *cache, void *object,
>  				const void *addr, u8 tag)
>  {
> @@ -192,6 +203,19 @@ static void describe_object(struct kmem_cache *cache, void *object,
>  		free_track = kasan_get_free_track(cache, object, tag);
>  		print_track(free_track, "Freed");
>  		pr_err("\n");
> +
> +#ifdef CONFIG_KASAN_GENERIC
> +		if (alloc_info->aux_stack[0]) {
> +			pr_err("Last one call_rcu() call stack:\n");
> +			print_stack(alloc_info->aux_stack[0]);
> +			pr_err("\n");
> +		}
> +		if (alloc_info->aux_stack[1]) {
> +			pr_err("Second to last call_rcu() call stack:\n");
> +			print_stack(alloc_info->aux_stack[1]);
> +			pr_err("\n");
> +		}
> +#endif
>  	}
>  
>  	describe_object_addr(cache, object, addr);
> -- 
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519154819.GJ2869%40paulmck-ThinkPad-P72.
