Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBS5D5HVQKGQEP32DAAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 16B54B10C0
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 16:10:21 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id p35sf3019424pgl.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 07:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568297419; cv=pass;
        d=google.com; s=arc-20160816;
        b=YfNnB8e5/+O2vI8Ri/C254jKmm74QqlVYZC/7UlEs1yTFDD6JmgArOP+IWJtRzIXCK
         prBK2gc6GRY8KKfYRA9+cInziPZkuvB926Qn7LSzIqM74cvqUme88scSdmqVE3faS1K0
         6c9TpvtfgT1AvtE5AljYO8cnU0/R64k84dEAacboE2NK25tME6wa1bZoKlQoFRaUAogd
         lKbi6vz3zIubewz0DJZ6gwKwK0bt4FEsYMTahUQWCsUj2Rbgreqn4y2Cye2AvyfcXmEI
         1A2uGE6Zugai+A5eNHGtZkkVFcpE/hsk0pnXzWHMy3hUgpYihvsRW2cwUQOSbFVTtLdZ
         nk2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=R5AC9PGYiiQPWFEA/m+lLvI+clfcJkuKAJmj9+VMjbs=;
        b=RquilFGIKvex3ZCz24/RnDi5rmJiBiHlWCahe/mRRAXF2jMxqBzbqD9ZAdeGXgzCLP
         S+vsHv8CGTMJJftO44IgjqwzPeG/HKzf5tCCbCDJxhBXBk9JkDqkdiDDvY+EPOqHNtu+
         3s4A8nxrjfQqawW8eaBSaguZqPr7W80W21z/0ILbOz0nqE77No5Id5iYSyjvkyuE56OF
         vgi0dapY5MmATXUXC9NbzpQV4Paowb2bUaVkyUFBavyC55Qlpo3ackn6kE8Lj8gboW+l
         YQyJ9ygv5EVkcCCDdBuw7LRkkewMUqmWCYjuliCu8eF0N4SBZeYFNUcDrW6/YywehAgV
         4Udw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=IPApOKeT;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R5AC9PGYiiQPWFEA/m+lLvI+clfcJkuKAJmj9+VMjbs=;
        b=dehvpdnvEEjO5wvog6E6LmHrExHQHVO8I8Q2OA+XIdW1MzyUqphDCxwpry1xrogn4L
         l3fCWZaP63qH+n8Iazmn3/Gg/PBnYgXVd2XzOk/XqR+GKG6Gv0IF3nxKxFQDWsHitVbf
         HaP1gtHtX5G37JNkSO7IJkse1H43JRb08165y9950s56y9C/U6qHvNvj6+DhJBwIZEq3
         /LUkxmDvPqjslXieTvlU9gshWN7PQcmQvyZDJoXNJ2RrxC/jl5zT+gNirg7/txO0EdLa
         HDoGcncI0YleD52OUpSC7WCxle31YdFiybLONjnJieBv62vXv1W/IE4kE2+H7Yea0ivu
         svFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R5AC9PGYiiQPWFEA/m+lLvI+clfcJkuKAJmj9+VMjbs=;
        b=Jyv0rJSZp6NrGoL+99EdqKSqMzYmaH6fms2htxyzLaE/Bf5SbB0TgFjVga39iJdfN8
         5HMhOqqvLA6p7Sn3IzbnJFCaoLk7Kcsc0QKlpKBc2dJGQJ7A5U4YkVmoowoTqWFB4MOD
         qowu7zqEXt8KFhNqo82ouRuf4L6M2rxMSfaFVhfhKnZydIK1RfASrOyy1hVZNQtqxxA+
         wioFZyriIxaDA7POIjpEB60Bdi2WoE+hVcM88EjLByl4ZZq1rxSfBnsOsjwbVJaF4oVs
         jsnIpy1uSBvwC7/N8t727FtPNDWa5BYPYqRXKxjpoNoRrmJ7oOeYa2jZ5MBmlUF9LzUi
         hbLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUHDUEtRDvgU/0Xrf4LM+zvSlCSS61gApJc6oJrYi6KZDsNKoPd
	13BOCfFTkoLdFDi8aulkcs0=
X-Google-Smtp-Source: APXvYqxY0XNJAIfE5IrZltTCfrs8n4AZhhXjXA0pbyxyCoq/yzIW+jN0c6ZOLg6kxQsSQVr+mio4eg==
X-Received: by 2002:a17:90a:b118:: with SMTP id z24mr204798pjq.79.1568297419206;
        Thu, 12 Sep 2019 07:10:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:20c8:: with SMTP id v8ls6370060plg.11.gmail; Thu, 12
 Sep 2019 07:10:18 -0700 (PDT)
X-Received: by 2002:a17:902:9b97:: with SMTP id y23mr4935279plp.212.1568297418843;
        Thu, 12 Sep 2019 07:10:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568297418; cv=none;
        d=google.com; s=arc-20160816;
        b=IUUhzK5IefNgXzpg9bIrImMwyIFOj7jrwB9A/JkiQh0mIAqov6rDSUFwrNS+XNitJf
         L6lXL79r94XUQiwkDEGfp08fShWNxWBhLnMA63E9568b84aj6gK2BUyCUuVS1tX0KqLq
         mcm7Q+KrBXTyMOwMR1A1awaNA6ijDUEP5clTyIbxelkpVfk7cHmEd4PnMEJW/xgGimhH
         eHT7Zrs5fPglgjAge18a4YJ4xEPgQTyHpQQtY6iur9bczIznoiGHp1euMEF4fU1FOjc9
         1/fp/kmbkwfp8WhCzJ2FGPy7+OCrFYjCRh4E1CKdXKzP1aUyp64MfHN/qg4QsdNVBgsb
         x4Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=GCjjLgVtFgvLpF7hk0kQsXY9fbLxlC94ZIxVciM5Jrc=;
        b=qKk1buqVBYxN2SXIbcio9ZtHxmK0V+XZZ5Qhu3bvXt+MoOqBY9RxcCyoHIixtYkLHe
         8PfeksMTOUJCo5Zmq9U8jkVS0/aVVCeAJ9PNW1BK7reirA/l/pEsmXtgEAOzA5VGvN1S
         bCD9BRs8OgO9ziGUfKiR2JcjDUv7jIxhlMCIuRBTlGVBOBBujGSMGp6pgngZiNqjysuJ
         T8D+zb52Rx4VQKI3iEvkqjLfC5Lm4SV3k+uFiA5i3/zyQtReEkpdWXYpg012SInxW3g4
         z81dvjja8H0jj0YAKvqKS6TAoV/4aKDaiIruGCHG5kOb6uEMUBbPi5bMQfP8rUrFeiQ3
         K8Mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=IPApOKeT;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id i184si1355712pge.5.2019.09.12.07.10.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Sep 2019 07:10:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id z67so24507801qkb.12
        for <kasan-dev@googlegroups.com>; Thu, 12 Sep 2019 07:10:18 -0700 (PDT)
X-Received: by 2002:a37:aa96:: with SMTP id t144mr29539420qke.275.1568297418177;
        Thu, 12 Sep 2019 07:10:18 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id i4sm6615004qke.93.2019.09.12.07.10.16
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Sep 2019 07:10:17 -0700 (PDT)
Message-ID: <1568297415.5576.143.camel@lca.pw>
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page
 allocator
From: Qian Cai <cai@lca.pw>
To: Vlastimil Babka <vbabka@suse.cz>, Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Martin
 Schwidefsky <schwidefsky@de.ibm.com>, Andrey Konovalov
 <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
Date: Thu, 12 Sep 2019 10:10:15 -0400
In-Reply-To: <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
	 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
	 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=IPApOKeT;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Thu, 2019-09-12 at 15:53 +0200, Vlastimil Babka wrote:
> On 9/11/19 5:19 PM, Qian Cai wrote:
> > 
> > The new config looks redundant and confusing. It looks to me more of a document update
> > in Documentation/dev-tools/kasan.txt to educate developers to select PAGE_OWNER and
> > DEBUG_PAGEALLOC if needed.
> 
>  
> Agreed. But if you want it fully automatic, how about something
> like this (on top of mmotm/next)? If you agree I'll add changelog
> and send properly.
> 
> ----8<----
> 
> From a528d14c71d7fdf5872ca8ab3bd1b5bad26670c9 Mon Sep 17 00:00:00 2001
> From: Vlastimil Babka <vbabka@suse.cz>
> Date: Thu, 12 Sep 2019 15:51:23 +0200
> Subject: [PATCH] make KASAN enable page_owner with free stack capture
> 
> ---
>  include/linux/page_owner.h |  1 +
>  lib/Kconfig.kasan          |  4 ++++
>  mm/Kconfig.debug           |  5 +++++
>  mm/page_alloc.c            |  6 +++++-
>  mm/page_owner.c            | 37 ++++++++++++++++++++++++-------------
>  5 files changed, 39 insertions(+), 14 deletions(-)
> 
> diff --git a/include/linux/page_owner.h b/include/linux/page_owner.h
> index 8679ccd722e8..6ffe8b81ba85 100644
> --- a/include/linux/page_owner.h
> +++ b/include/linux/page_owner.h
> @@ -6,6 +6,7 @@
>  
>  #ifdef CONFIG_PAGE_OWNER
>  extern struct static_key_false page_owner_inited;
> +extern bool page_owner_free_stack_disabled;
>  extern struct page_ext_operations page_owner_ops;
>  
>  extern void __reset_page_owner(struct page *page, unsigned int order);
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 6c9682ce0254..dc560c7562e8 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -41,6 +41,8 @@ config KASAN_GENERIC
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	select STACKDEPOT
> +	select PAGE_OWNER
> +	select PAGE_OWNER_FREE_STACK
>  	help
>  	  Enables generic KASAN mode.
>  	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
> @@ -63,6 +65,8 @@ config KASAN_SW_TAGS
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	select STACKDEPOT
> +	select PAGE_OWNER
> +	select PAGE_OWNER_FREE_STACK
>  	help
>  	  Enables software tag-based KASAN mode.
>  	  This mode requires Top Byte Ignore support by the CPU and therefore

I don't know how KASAN people will feel about this. Especially, KASAN_SW_TAGS
was designed for people who complain about memory footprint of KASAN_GENERIC is
too high as far as I can tell.

I guess it depends on them to test the new memory footprint of KASAN to see if
they are happy with it.

> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index 327b3ebf23bf..a71d52636687 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -13,6 +13,7 @@ config DEBUG_PAGEALLOC
>  	depends on DEBUG_KERNEL
>  	depends on !HIBERNATION || ARCH_SUPPORTS_DEBUG_PAGEALLOC && !PPC && !SPARC
>  	select PAGE_POISONING if !ARCH_SUPPORTS_DEBUG_PAGEALLOC
> +	select PAGE_OWNER_FREE_STACK if PAGE_OWNER
>  	---help---
>  	  Unmap pages from the kernel linear mapping after free_pages().
>  	  Depending on runtime enablement, this results in a small or large
> @@ -62,6 +63,10 @@ config PAGE_OWNER
>  
>  	  If unsure, say N.
>  
> +config PAGE_OWNER_FREE_STACK
> +	def_bool n
> +	depends on PAGE_OWNER
> +
>  config PAGE_POISONING
>  	bool "Poison pages after freeing"
>  	select PAGE_POISONING_NO_SANITY if HIBERNATION
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index c5d62f1c2851..d9e44671af3f 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -710,8 +710,12 @@ static int __init early_debug_pagealloc(char *buf)
>  	if (kstrtobool(buf, &enable))
>  		return -EINVAL;
>  
> -	if (enable)
> +	if (enable) {
>  		static_branch_enable(&_debug_pagealloc_enabled);
> +#ifdef CONFIG_PAGE_OWNER
> +		page_owner_free_stack_disabled = false;
> +#endif
> +	}
>  
>  	return 0;
>  }
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index dee931184788..d4551d7012d0 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -24,13 +24,15 @@ struct page_owner {
>  	short last_migrate_reason;
>  	gfp_t gfp_mask;
>  	depot_stack_handle_t handle;
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
>  	depot_stack_handle_t free_handle;
>  #endif
>  };
>  
>  static bool page_owner_disabled = true;
> +bool page_owner_free_stack_disabled = true;
>  DEFINE_STATIC_KEY_FALSE(page_owner_inited);
> +static DEFINE_STATIC_KEY_FALSE(page_owner_free_stack);
>  
>  static depot_stack_handle_t dummy_handle;
>  static depot_stack_handle_t failure_handle;
> @@ -46,6 +48,11 @@ static int __init early_page_owner_param(char *buf)
>  	if (strcmp(buf, "on") == 0)
>  		page_owner_disabled = false;
>  
> +	if (IS_ENABLED(CONFIG_KASAN)) {
> +		page_owner_disabled = false;
> +		page_owner_free_stack_disabled = false;
> +	}
> +
>  	return 0;
>  }
>  early_param("page_owner", early_page_owner_param);
> @@ -91,6 +98,8 @@ static void init_page_owner(void)
>  	register_failure_stack();
>  	register_early_stack();
>  	static_branch_enable(&page_owner_inited);
> +	if (!page_owner_free_stack_disabled)
> +		static_branch_enable(&page_owner_free_stack);
>  	init_early_allocated_pages();
>  }
>  
> @@ -148,11 +157,11 @@ void __reset_page_owner(struct page *page, unsigned int order)
>  {
>  	int i;
>  	struct page_ext *page_ext;
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
>  	depot_stack_handle_t handle = 0;
>  	struct page_owner *page_owner;
>  
> -	if (debug_pagealloc_enabled())
> +	if (static_branch_unlikely(&page_owner_free_stack))
>  		handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
>  #endif
>  
> @@ -161,8 +170,8 @@ void __reset_page_owner(struct page *page, unsigned int order)
>  		if (unlikely(!page_ext))
>  			continue;
>  		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> -		if (debug_pagealloc_enabled()) {
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
> +		if (static_branch_unlikely(&page_owner_free_stack)) {
>  			page_owner = get_page_owner(page_ext);
>  			page_owner->free_handle = handle;
>  		}
> @@ -451,14 +460,16 @@ void __dump_page_owner(struct page *page)
>  		stack_trace_print(entries, nr_entries, 0);
>  	}
>  
> -#ifdef CONFIG_DEBUG_PAGEALLOC
> -	handle = READ_ONCE(page_owner->free_handle);
> -	if (!handle) {
> -		pr_alert("page_owner free stack trace missing\n");
> -	} else {
> -		nr_entries = stack_depot_fetch(handle, &entries);
> -		pr_alert("page last free stack trace:\n");
> -		stack_trace_print(entries, nr_entries, 0);
> +#ifdef CONFIG_PAGE_OWNER_FREE_STACK
> +	if (static_branch_unlikely(&page_owner_free_stack)) {
> +		handle = READ_ONCE(page_owner->free_handle);
> +		if (!handle) {
> +			pr_alert("page_owner free stack trace missing\n");
> +		} else {
> +			nr_entries = stack_depot_fetch(handle, &entries);
> +			pr_alert("page last free stack trace:\n");
> +			stack_trace_print(entries, nr_entries, 0);
> +		}
>  	}
>  #endif
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1568297415.5576.143.camel%40lca.pw.
