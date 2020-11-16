Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFN5ZL6QKGQEJ6DSYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E90222B49B8
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:45:25 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id r18sf5591072lff.18
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:45:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605541525; cv=pass;
        d=google.com; s=arc-20160816;
        b=tE+m+D6p+/9GCFqa1CuH29jTJF0c0rqzoOWKxkAke4rE59wPbdEePK3LwFp6Ai5NGO
         XGU328boFZTq6nCRXvivBUqhabWBkq5gYx45HyZzgRX513qyXpTOV+zYcLLraazXp6BW
         3J2dlQ6tkXSUX0RvzoPlY06P0plaWkUhb2yWnXCt5qcyh5vynQyg6er/OMSWXOhR/7mm
         /9rrKhg8VkZ5OMGP+M8T70CrjNU1lAzygJxmyJeHwiZlOfVwYoELHBaXJaipGZ2QS1lX
         iiRqJMU0N6z7ckqjOfARAvYFtiomp5Dd7kQ0rgDV2VSdNG5TaYM3swFNiJXdSl6fthRA
         3wTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+603Llw0TzLibUemVIfDYE4gjzUxwfRJTM0g3Ru9r9g=;
        b=VpnBgTLJiunmOICerfE4HVkekfK3GNunEYol7NVjZELvHn13uP+6YiKA6kASySMlz1
         hEw4vDWeBtnJrOHWmG8fIhfH3XVFnedSoNe1t7m608nFPZDr54xtYVsEPLTsqFdDQhbi
         velBma/gjYQ4z5tU4Xu37BkAPRznSgoKzsR1AVgxpSf21KjHtFBkZtPxHQLlZqL1GNbM
         HHgMgWR3XVbLD0aB8pzjMzBeVd8XsLdP38/IKPhahlIizrUXobBYPQZ5y/IcRLssIvjS
         /e6QIK/JmLe5XaJ/Ki8mhEyFMikF4+dUy0hChlMojKqs3812fVfsDTCjCHMzNoO4kCKV
         0GLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C4zcZnUO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+603Llw0TzLibUemVIfDYE4gjzUxwfRJTM0g3Ru9r9g=;
        b=LaMK/4YV1M02watzJI/wN+eVOoCzQ5NfOltsPfN/xq87EuUjPRu85KQMlxxW96nn6S
         3TwlfQM4XaP3uSGVtpW9RxzgfAlRiyszfATaDxSk6MCumh00gzOXATsZxnEXkb7GtcPr
         BNLVPV4C2K9k8WG0nU78O6lr9iTUH222M9Lz4Lb82tNZbhbhwp60iqm7aKpQqRZy9fGx
         EYZUOU0lmOoCO6k7XSWv191Zf7aYoQbzEvom0DPr4IOSHtEId6HCtVxzG6xckXyL9V9O
         cynwC65KooJddzXydG33N2fRdoLEhRocRjSrOS5Stye9pIcW2ak+NCAP8D/2TAPmsX53
         AbRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+603Llw0TzLibUemVIfDYE4gjzUxwfRJTM0g3Ru9r9g=;
        b=tlNTVZWG4yHM4u1mANMjTdwuPu4l1xp5zPLQTnGrCU1B2p3+SJhi0zwfSnOuN2qCvR
         opiOkXIYpVnTPsbn/IuezbdBGAa1MO/9AiEZ8UHmZKMmXZnkwLC4V+zpowvydAuBjb0y
         erAlPX9RL7LRD7B24nSDALVI+NADNWRJN2dYjDdcIbzANd4BInLUYUco2nOMwA47nJIj
         tRFRSdawiHl2ELb+VdcHMlO0Pks1jr4hNbDDvXTP+X4EwKs8liXfCQjv+xvrrfbPXVN/
         kdC7T4yp4FU6P+/CFZb6/PTXF8Mx8LTIqkOAqW4I3FRSTo5+HrWdzzStO59sNQrVRmT1
         tL8w==
X-Gm-Message-State: AOAM530iTQUu9ElRdPXHjbxOtipysG/tEGcWFNvGWo38IDwkEZNdYc3O
	fkWm1lhoCi1+T57R0OhDelM=
X-Google-Smtp-Source: ABdhPJzZVzysd/bExb3hDKTSdIS3prkpfpizt9EzkD/5nZPxvE9iNjw9KUSl+/EnCZF+u7PiS4gMPQ==
X-Received: by 2002:a2e:9205:: with SMTP id k5mr3444ljg.38.1605541525496;
        Mon, 16 Nov 2020 07:45:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2122:: with SMTP id a34ls1715923ljq.9.gmail; Mon,
 16 Nov 2020 07:45:24 -0800 (PST)
X-Received: by 2002:a2e:bc04:: with SMTP id b4mr7111321ljf.101.1605541524243;
        Mon, 16 Nov 2020 07:45:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605541524; cv=none;
        d=google.com; s=arc-20160816;
        b=MVMedzGH6uahrwQXt+/6Xrxawl1+JDLjldxw8WtZfvvCe92r1dCswlRLnGj31WpRgz
         Q4TNK8AnL3K8G0/KLlv7XCbGPg6wW+WejJrzG0dKWroZCSVA/lr1hRTxkpRaLRWpTRkq
         eeeJ7SvMwR39M2+CQeOXNCIedfKenKM/LD3zGBS5MG/dTlNI+GGL3noZoeB+2k6/Kc0n
         xQspunaQwpa4JU/kRaYA/kj18wAu5Qpth+nyLh577kopisVksEF0kZwkOetvFgOPv0GY
         3EBfGlSEuxi6ohGOx/7FO8e6gSNDONN7wFl/iNWlaFQWOBCqOgn84I6FzwTmIYOWvn6A
         eFig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=KbFqzMvWkwy7nQ4a/oXAq0hKgif40IyQfOuqmDIS5m0=;
        b=v/lMt75rRF4PCPc5xafBpWqua0kjNuNS9WWYaA+mjiYUObhy/IxmIyQ12g+bP2SiqE
         FESL5Z+0FiGNnfajRgbV6HJZ5fl5l4wvLbCqKZts8SdBPFa+J7VkRS0xhVxLTkUfOgo8
         7+bTj1qADnADmbz6nLDPTgRo4Uv+sDd+Nx15Y9NX/YFBUL3L5hLbU0KkVcACI3xd6Ms/
         YOs9qDdLDhXBaivZq0kPDMFGc8VRtKGfZDztFDf1tbTSZ3+EvvV4L4Pyed89jLswy4sa
         dnrE6MvMlOiogoJlpFU6k4wbRQBI4v7NyR2lGnGOE7frOv6M756m7878/uDEymkmGj5f
         tE3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C4zcZnUO;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id f9si551029lfl.3.2020.11.16.07.45.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:45:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id p22so24132510wmg.3
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:45:24 -0800 (PST)
X-Received: by 2002:a1c:f20d:: with SMTP id s13mr16738373wmc.156.1605541523649;
        Mon, 16 Nov 2020 07:45:23 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id h62sm23337450wrh.82.2020.11.16.07.45.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Nov 2020 07:45:22 -0800 (PST)
Date: Mon, 16 Nov 2020 16:45:17 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v3 18/19] kasan, mm: allow cache merging with no
 metadata
Message-ID: <20201116154517.GG1357314@elver.google.com>
References: <cover.1605305978.git.andreyknvl@google.com>
 <6f0a1e72783ddac000ac08e7315b1d7c0ca4ec51.1605305978.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6f0a1e72783ddac000ac08e7315b1d7c0ca4ec51.1605305978.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C4zcZnUO;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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

On Fri, Nov 13, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> The reason cache merging is disabled with KASAN is because KASAN puts its
> metadata right after the allocated object. When the merged caches have
> slightly different sizes, the metadata ends up in different places, which
> KASAN doesn't support.
> 
> It might be possible to adjust the metadata allocation algorithm and make
> it friendly to the cache merging code. Instead this change takes a simpler
> approach and allows merging caches when no metadata is present. Which is
> the case for hardware tag-based KASAN with kasan.mode=prod.
> 
> Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kasan.h | 21 +++++++++++++++++++--
>  mm/kasan/common.c     | 11 +++++++++++
>  mm/slab_common.c      |  3 ++-
>  3 files changed, 32 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 16cf53eac29b..173a8e81d001 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -81,17 +81,30 @@ struct kasan_cache {
>  };
>  
>  #ifdef CONFIG_KASAN_HW_TAGS
> +
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +
>  static __always_inline bool kasan_enabled(void)
>  {
>  	return static_branch_likely(&kasan_flag_enabled);
>  }
> -#else
> +
> +#else /* CONFIG_KASAN_HW_TAGS */
> +
>  static inline bool kasan_enabled(void)
>  {
>  	return true;
>  }
> -#endif
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
> +slab_flags_t __kasan_never_merge(void);
> +static __always_inline slab_flags_t kasan_never_merge(void)
> +{
> +	if (kasan_enabled())
> +		return __kasan_never_merge();
> +	return 0;
> +}
>  
>  void __kasan_unpoison_range(const void *addr, size_t size);
>  static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
> @@ -238,6 +251,10 @@ static inline bool kasan_enabled(void)
>  {
>  	return false;
>  }
> +static inline slab_flags_t kasan_never_merge(void)
> +{
> +	return 0;
> +}
>  static inline void kasan_unpoison_range(const void *address, size_t size) {}
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index cf874243efab..a5a4dcb1254d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -87,6 +87,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  }
>  #endif /* CONFIG_KASAN_STACK */
>  
> +/*
> + * Only allow cache merging when stack collection is disabled and no metadata
> + * is present.
> + */
> +slab_flags_t __kasan_never_merge(void)
> +{
> +	if (kasan_stack_collection_enabled())
> +		return SLAB_KASAN;
> +	return 0;
> +}
> +
>  void __kasan_alloc_pages(struct page *page, unsigned int order)
>  {
>  	u8 tag;
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 0b5ae1819a8b..075b23ce94ec 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -19,6 +19,7 @@
>  #include <linux/seq_file.h>
>  #include <linux/proc_fs.h>
>  #include <linux/debugfs.h>
> +#include <linux/kasan.h>
>  #include <asm/cacheflush.h>
>  #include <asm/tlbflush.h>
>  #include <asm/page.h>
> @@ -54,7 +55,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>  		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> -		SLAB_FAILSLAB | SLAB_KASAN)
> +		SLAB_FAILSLAB | kasan_never_merge())
>  
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>  			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
> -- 
> 2.29.2.299.gdc1121823c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201116154517.GG1357314%40elver.google.com.
