Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV6G2KCQMGQEMEYP4ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 352CB395764
	for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 10:50:32 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id k25-20020a5d52590000b0290114dee5b660sf2008813wrc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 01:50:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622451032; cv=pass;
        d=google.com; s=arc-20160816;
        b=a4Yxm2V4tfQ1mXddbUYHoJsAYDyFAD2bnjrQLWgTYEk5kN3vAgluSOfK7ZKG7UUoox
         Av52UgVOlCHj8gz/O50P9gIU2OIyTMv1hI2fE0nuebIrBTXJLmssORprQNj+mdeDWXY/
         Hm7hVO57rngt8IUehJtehLkxEAtVdPq2sdtmdu0lz/L1K5BId81H7O306T6ie0xRutJh
         S7T2VlQnam7Gr0dpaM0vyUNTL3+0XLkHo3S9nV15WUFIIvr+7o9+ZGU+sgYCGfzRCxhC
         GC52fjOo+g3A5R3szyFpAod8sijtBm/1i6tpCgKzOAh6cn6c1ld8AbWX8c+eyIr4GlsZ
         mfVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LhGWTOY5P3CSoKNNiySjilgsFHLG5c4bk0gk0juSXaU=;
        b=i916uD3Xdf0QxLtMZ7rDTn7A/h1tXqzEce9vkJTftYzTekWxX8UAqIuZm9lBlgsEE+
         6nG9L43NwvEoaZdmqt77z7UFWPM49Ne2wmEwqR9Dim2UI1LtJaEE4toorfZSg1Z/pXKL
         26pmzPO4YxHxDQ9lTLdC2ycTf5msdXQmQobpFQ5thA1w6Ivmauh3RyXJS20CDwojgM/F
         JJtBleddZg7PLGzkJ1uSTXcUWlYutb28I/GFASvzzJB26pJGF6dfwDZ5B97UOOd/AASo
         uU5PiyHvu8BSkDkXc29AQ29YjUbEzoUMYX/MLLKMGG6pLEU5aHJX0b2xY/YV/fjCnhRR
         +NJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sRi9Gk3h;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=LhGWTOY5P3CSoKNNiySjilgsFHLG5c4bk0gk0juSXaU=;
        b=Sj3osNO1kTeF/whdMxPpiM1N8lEDWccxmjo0QN7PTzUsdCb1Sh08bxAN+y06d4tzNj
         AFVv0blM+apEDEf+/kuoF8onWOJJU2heG3ObiBooIM7sN3Tw4PnzvXT/kvpOk/qFZ0uL
         aBCBUFZsqpmeZpdmM8g25gZbvBfs7HKoAaxajL49HJFhYetHZcYk4Dfh/KOo82RigLZa
         pNIdEEhnwwdP4RN0GGQ8IX0cGKq5R1hKTDhraWzIUkM8Hj6L6/jcg64Ohn9mmikkWDff
         cGqPTp19O6i7kJC/xtEr4kkSzER9kD1QXccbpnkcfLuBNFoOR0ISBSri4Isl66OFhg/b
         2L9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LhGWTOY5P3CSoKNNiySjilgsFHLG5c4bk0gk0juSXaU=;
        b=hO/vcJcwmMUonZzAXuyRBE+GfeHydhnhwJwo4p3UWIERTG+O/CPR9YALHJFChTJQNd
         hJUe++lZkojezUTcrEERZEkrPfaa1VHaHBCufzSOXrFR1C1X+21sTaQfDG+h8inw2UnQ
         vVQIQ5eQtWSqtqxIeUZ7dckvj6jgNUKbHLKp/c4unfgY8F5svMMPABFehpG6f87N+jQs
         IJU72OeB++tf6vqZ7kWa2AC2+jreg8JcBalEYLzo8RQRdd+qo8Bo1HijfSmmkxFTpSPQ
         7fmD4xDTLpdACp7PvOmKOmmIePitSRCqDLZdM+pkdDGLmSfdA6i8CehW/ICV4NbfhR5Z
         NXEw==
X-Gm-Message-State: AOAM5322a1LYXDBNoBWLUtgcF1/zKN7spE24/7a0XLl23bZWVauAUKKk
	kCrH5NadHUf9B4H0WBTOd/o=
X-Google-Smtp-Source: ABdhPJwgUcB/o+bdp2tiQ4WT35yuojPHMdO3GRgVupQu3VfpPXIUQpUAiBcPmSd22yWSTTwoKC/gdw==
X-Received: by 2002:a05:600c:29a:: with SMTP id 26mr7628660wmk.161.1622451031914;
        Mon, 31 May 2021 01:50:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1909:: with SMTP id j9ls5237450wmq.3.canary-gmail;
 Mon, 31 May 2021 01:50:31 -0700 (PDT)
X-Received: by 2002:a05:600c:3786:: with SMTP id o6mr1249568wmr.170.1622451031003;
        Mon, 31 May 2021 01:50:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622451031; cv=none;
        d=google.com; s=arc-20160816;
        b=hLWuPoglfaZvG4f1e4cQqMeBCc1wl9At1tJX8VRGY6t7vU+bM5bRRxalPYOw2MHrSa
         T2s+V98o70y2OldyTfJw3gkyWUnBL0XGOX89iPrx23TqSdhFt6aYe8kK48jKiWAzj+3c
         bRWWuVKs51y0mbiNAB2f/43uVJQ6P0ta3Y3Z2lCZ6S37RCaFnvV+S/bUtwiGkdVSr4UX
         7VwihTYWHVpqLzh4iYGF45dY/fO3dGlJK4/oUxM3icGGZKR2D7WZW5STB2MqSHZNSqHe
         tiHRCNti/25dbdypn02wtaGDf2pHqjoRl6VPpBEaVhCYcxqomEIGuSuFcQutXoCnV/7K
         OeSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xzFWtmO7IWsEOm3BlqiJN4JSZLZ8qP1HgDEe5DSYe7k=;
        b=zH5Tps8lke02LMLcz0mBDmhnh6qX0qd2sd0FjqC0byrbc14Hc4WrIESeXR5gJJj6Wz
         ezn0mHOZ9wSXAxxgd7koCnImPKzBd8dR3dvocV7IW5Q4f6PJTeVwMqlj/QSjOttDeW1i
         qO3NEMbzbUo2yJ7Q/+LlqNVNnkK+QaJEdtVoimJSphHayoXqiYrs9PvVweE4UzYb0GGw
         Stz2fsnfsfGDWLbxmnv43/5/2buH57qb6VfYZmCYDYwVW/4Y/KC+Gw5oUe5I7WJmA9G1
         2NfmDEdYZa9Zl+Qr0vElfoHWKAmfzUelqsaXbDWmA9je2GtNDISTCpGqu/VAGLY9hbyv
         lClw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sRi9Gk3h;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id g18si739397wmc.0.2021.05.31.01.50.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 May 2021 01:50:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id z17so10089795wrq.7
        for <kasan-dev@googlegroups.com>; Mon, 31 May 2021 01:50:30 -0700 (PDT)
X-Received: by 2002:a5d:64eb:: with SMTP id g11mr21462862wri.260.1622451030640;
        Mon, 31 May 2021 01:50:30 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:79b2:9d30:345a:1523])
        by smtp.gmail.com with ESMTPSA id q3sm16285716wrr.43.2021.05.31.01.50.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 May 2021 01:50:29 -0700 (PDT)
Date: Mon, 31 May 2021 10:50:24 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kuan-Ying Lee <kylee0686026@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH 1/1] kasan: add memory corruption identification for
 hardware tag-based mode
Message-ID: <YLSjUOVo5c+gTbzA@elver.google.com>
References: <20210530044708.7155-1-kylee0686026@gmail.com>
 <20210530044708.7155-2-kylee0686026@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210530044708.7155-2-kylee0686026@gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sRi9Gk3h;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
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

On Sun, May 30, 2021 at 12:47PM +0800, Kuan-Ying Lee wrote:
> Add memory corruption identification at bug report for hardware tag-based
> mode. The report shows whether it is "use-after-free" or "out-of-bound"
> error instead of "invalid-access" error. This will make it easier for
> programmers to see the memory corruption problem.
> 
> We extend the slab to store five old free pointer tag and free backtrace,
> we can check if the tagged address is in the slab record and make a good
> guess if the object is more like "use-after-free" or "out-of-bound".
> therefore every slab memory corruption can be identified whether it's
> "use-after-free" or "out-of-bound".
> 
> Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>

On a whole this makes sense because SW_TAGS mode supports this, too.

My main complaints are the copy-paste of the SW_TAGS code.

Does it make sense to refactor per my suggestions below?

This is also a question to KASAN maintainers (Andrey, any preference?).

> ---
>  lib/Kconfig.kasan         |  8 ++++++++
>  mm/kasan/hw_tags.c        | 25 ++++++++++++++++++++++---
>  mm/kasan/kasan.h          |  4 ++--
>  mm/kasan/report_hw_tags.c | 28 ++++++++++++++++++++++++++++
>  4 files changed, 60 insertions(+), 5 deletions(-)
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..f7e666b23058 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -163,6 +163,14 @@ config KASAN_SW_TAGS_IDENTIFY
>  	  (use-after-free or out-of-bounds) at the cost of increased
>  	  memory consumption.
>  
> +config KASAN_HW_TAGS_IDENTIFY
> +	bool "Enable memory corruption identification"
> +	depends on KASAN_HW_TAGS
> +	help
> +	  This option enables best-effort identification of bug type
> +	  (use-after-free or out-of-bounds) at the cost of increased
> +	  memory consumption.

Can we rename KASAN_SW_TAGS_IDENTIFY -> KASAN_TAGS_IDENTIFY in a
separate patch and then use that?

Or do we have a problem renaming this options if there are existing
users of it?

>  config KASAN_VMALLOC
>  	bool "Back mappings in vmalloc space with real shadow memory"
>  	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 4004388b4e4b..b1c6bb116600 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -220,22 +220,41 @@ void kasan_set_free_info(struct kmem_cache *cache,
>  				void *object, u8 tag)
>  {
>  	struct kasan_alloc_meta *alloc_meta;
> +	u8 idx = 0;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
> -	if (alloc_meta)
> -		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> +	if (!alloc_meta)
> +		return;
> +
> +#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
> +	idx = alloc_meta->free_track_idx;
> +	alloc_meta->free_pointer_tag[idx] = tag;
> +	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> +#endif
> +
> +	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
>  }
>  
>  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>  				void *object, u8 tag)
>  {
>  	struct kasan_alloc_meta *alloc_meta;
> +	int i = 0;
>  
>  	alloc_meta = kasan_get_alloc_meta(cache, object);
>  	if (!alloc_meta)
>  		return NULL;
>  
> -	return &alloc_meta->free_track[0];
> +#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
> +	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +		if (alloc_meta->free_pointer_tag[i] == tag)
> +			break;
> +	}
> +	if (i == KASAN_NR_FREE_STACKS)
> +		i = alloc_meta->free_track_idx;
> +#endif
> +
> +	return &alloc_meta->free_track[i];
>  }

Again, we now have code duplication. These functions are now identical
to the sw_tags.c ones?

Does it make sense to also move them in a preparatory patch to a new
'tags.c'?

>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..41b47f456130 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,7 +153,7 @@ struct kasan_track {
>  	depot_stack_handle_t stack;
>  };
>  
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
> @@ -170,7 +170,7 @@ struct kasan_alloc_meta {
>  #else
>  	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
>  #endif
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
>  	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>  	u8 free_track_idx;
>  #endif
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> index 42b2168755d6..d77109b85a09 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -14,9 +14,37 @@
>  #include <linux/types.h>
>  
>  #include "kasan.h"
> +#include "../slab.h"
>  
>  const char *kasan_get_bug_type(struct kasan_access_info *info)
>  {
> +#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
> +	struct kasan_alloc_meta *alloc_meta;
> +	struct kmem_cache *cache;
> +	struct page *page;
> +	const void *addr;
> +	void *object;
> +	u8 tag;
> +	int i;
> +
> +	tag = get_tag(info->access_addr);
> +	addr = kasan_reset_tag(info->access_addr);
> +	page = kasan_addr_to_page(addr);
> +	if (page && PageSlab(page)) {
> +		cache = page->slab_cache;
> +		object = nearest_obj(cache, page, (void *)addr);
> +		alloc_meta = kasan_get_alloc_meta(cache, object);
> +
> +		if (alloc_meta) {
> +			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +				if (alloc_meta->free_pointer_tag[i] == tag)
> +					return "use-after-free";
> +			}
> +		}
> +		return "out-of-bounds";
> +	}
> +
> +#endif
>  	return "invalid-access";
>  }

This function is an almost copy-paste of what we have in
report_sw_tags.c. Does it make sense to try and share this code or would
it complicate things?

I imagine we could have a header report_tags.h, which defines a static
const char *kasan_try_get_bug_type(..), and simply returns NULL if it
couldn't identify it:

	#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
	static const char *kasan_try_get_bug_type(struct kasan_access_info *info)
	{
		... the code above ...

		return NULL;
	}
	#else
	static const char *kasan_try_get_bug_type(struct kasan_access_info *info) { return NULL; }
	#endif


Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YLSjUOVo5c%2BgTbzA%40elver.google.com.
