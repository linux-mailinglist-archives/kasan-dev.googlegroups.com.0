Return-Path: <kasan-dev+bncBCKLZ4GJSELRBFOF22XAMGQE6YD5BSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 7454985D0FA
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 08:13:27 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2d243193975sf19136541fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 23:13:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708499607; cv=pass;
        d=google.com; s=arc-20160816;
        b=xOyE4UCuleWp1mqDUne97R/mgDZM9pFvzuHrt/oHXtq8FDicfqokSNpTVHExyKNLpZ
         8IcfkDIouWCoC1rHtcivqrHAFmobX//uIxQt1XjMNT0rdbhzHRljMMz+8QM8QRzuYlK3
         nte4KAT9/HUllF4NP3Lz7mt4m6s2/1U/Q+bUqAsINR169yg7wlYL9VDbGqGN6isi42dB
         h3i07X1rnEGgOqlqd8cdlVK2kp/zjFjW0tGmJZU7M92UiujXNKVoaBwArHJsoE2K0arr
         HTuDjEIvkSGj90KV4D8RVnt2XWQLzju+4C5xsM6ltnnheh2InxzA1a+HQOFJeU6kxXFj
         1Qfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=/42KGqOPTNvI/ciuoK11J0hGbPdeuebiarG3o8Aau7E=;
        fh=ZG1BiTEMMGgCi+FjqUnJtj/uKkD2Ae9nOnDNjtCORlw=;
        b=iQvGRGeQcQhZSjeOn1W0fiHo3pZ2W4SEW8wm7LuL8sXq9Eje/6q6fl/SoD5QTk1csz
         zA2G7OZuiY0BJyJdyN6+4UAa3N8r0FhQlFZ1ywHMyy0PUAXlVIref2mYvGE5Z/abQSe0
         TIp1mMw8K6t+UERUDkPFV40tmm+3by/2VSs42WnxlNBSJsm8b3m1Ai+0knou7bUbuzeQ
         hM+CO/+H0s9SGXKhItMWVJvxrzVDSXjQKpgcr3ZuVR2wgBwOAOIGxyo3AlhkS2J8pCRD
         jQSyWdypb6886tgvyWLnoS3AjFJ2RiVOpRJAHBc4ommDAH45nPam6OrZ9HfYNAW0tLnD
         Nv3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eXw1VdsQ;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.182 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708499607; x=1709104407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=/42KGqOPTNvI/ciuoK11J0hGbPdeuebiarG3o8Aau7E=;
        b=IKD4XXloF0TahS1bPRX4qwez4c/NeVFKCTJlQIjyQ2HNvvRdXEbmtuQTOHD6wo39Os
         at5dyK4i6ewszS5t5BwlKoTT1UJ9FKVtiUB1CxA+qqblWv7JEGpl50TwXSjlr3OeBBwo
         iy2ftR1xqubsqjAAvcZkWwvDvBib7UpYY/1WH9BaZJTMXqfmDsetv7ZnE5Xy25ewcwjG
         WSLfIYfoHLTWIrlUkP6/epCHXol9G3ffH3eRpA5JzugyzQz9hQjNpllTVOvg4x8aFoXk
         OWqa7F0MN3LnIf5xBZ407m6z1UO0SfNwSlqExfahduHsG/LmEMPkDaKsNp0zpCPOFUDc
         CXcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708499607; x=1709104407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=/42KGqOPTNvI/ciuoK11J0hGbPdeuebiarG3o8Aau7E=;
        b=ZlGzCPCiS9qP5+LH2jk+peqxeVumnLkGHHPkZkjBVD9t7IcMfwhQY2sebrPBRdL48h
         a0GkvzWcczGnuQhkn5NQqXigOA9u3kjb1uoo0hCbWjuHg2gXoLobrgPvGlQVE62Rui2u
         jIqHqECtdepUZbwiBVP8mUqTcFtbBY8NoKIaIh97/vDpTVFMb8DdhTHyg9R0QjKkyimY
         OjORbxBYcEEyj6b2AkC1GXUDC4j4zyryFxmarccp2NXYgMAC5dO2ivUH300plknJ3aO1
         5B6Q3hck61yyojVuWZGvetAxyfbeKDDRvKK6vGwdPHTjEHg4JIDDgiHlc/lAffgry8TA
         /WHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVegEOJvIRlNwYcjb+ziSW7j7eDrfBIJbZKx29tz4m1LDKsiRn+z7V4lQgWaPNlxk+uLdb5IbCbqDc26DFl4py/eoZQtlxH0w==
X-Gm-Message-State: AOJu0YwWib/78jAOdp1kdOyXbyCi2tU3oLEdJqzJp25+vtiaoE2p9Mj1
	HtXKr8nAzcCof7tNYerKGf5X3gwPsx0WrUT0lh2ARYyQQU59M/nT
X-Google-Smtp-Source: AGHT+IFnhPMINBbCwLdWjTxHMHtzT5QduiB9F71YrFyw4i/9ORqAkP+0LeTiehOg76P/JGJG6bWzAg==
X-Received: by 2002:a2e:9d84:0:b0:2d2:4800:5fe with SMTP id c4-20020a2e9d84000000b002d2480005femr3420796ljj.35.1708499606301;
        Tue, 20 Feb 2024 23:13:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10b1:b0:2d2:3997:45d with SMTP id
 k17-20020a05651c10b100b002d23997045dls926647ljn.1.-pod-prod-01-eu; Tue, 20
 Feb 2024 23:13:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCNJrayPGDHh3jO+9QN2ciu9xbE41KHegGvki7Kny0H6CvhDqc4pSX+gbhsptm29Cv9oKbQTuVwfnW5KdK/HE3woq9TwLzvOCh/Q==
X-Received: by 2002:a05:6512:1321:b0:512:bd65:860a with SMTP id x33-20020a056512132100b00512bd65860amr6298067lfu.5.1708499604148;
        Tue, 20 Feb 2024 23:13:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708499604; cv=none;
        d=google.com; s=arc-20160816;
        b=K7eP1oGV6TO585cA+h7pjzc19LLpIaTsudX4FXxT5EgAJJUf7lWoOxB6SBW7847Ydy
         8A1AXfOmBdIdPJPHn9aQqHFzckkv49lvpxNweMmQYRxscwIEfzGJhPBSPKHJmuIHmWX8
         A3LoeMY1j+6OVNe43bQOW3P+D5dxRNrDwz2zU4xNZMhz7hcj2iu0WTFtANBITlfcRBvI
         v/Wo7igXjVxve2rpyG+qnJ23JSL5P2az4i2zU6M7oZNPgGGILwcXX2cRxbmcEd0a9f6S
         QexBKkUZdYESohrjQI+GtIVok02kVstXTlMl64ydHwEWvDwUdTR3+/fthTSWrJLPYeWS
         cU/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=4lnluPublLsql88cuouFDfLI5nirAwLVTd6p6qVgmKo=;
        fh=psRl9dOmmlv1R0vYTuQ68Rj9XPUleTtuphcDV1SUegg=;
        b=fb5lbQ5s12TcgMvfnyFlwkF3UsPeWOhdkIglRqB8o9hpp410MRxwk2NFHypij/PN+1
         f+Smw0a2exSLnp4Cu6MlQSWbYn+eqepUmw1KTq857wrYd3yZADfBDdPLtehxm/EZmrtK
         GtH+x4UQjXB0C0ASVG7cQD8gmQZfZjKkf5bW3+xgEzk505FEDlkbEvw6q2L7r7aYVhch
         3F8A+842A8wqUGgEZlsKEWtW7H3/LZ/IM+7RxaowUZwBq5feSl9vokF3vosL8Ptuhzzv
         aIocxmJFvkMDNdwHZByQjYUI3wAYvbHzO1xfXrBSR89gNMBAe1Weg9aT3DcXravkwtXX
         f/mw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eXw1VdsQ;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.182 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-182.mta0.migadu.com (out-182.mta0.migadu.com. [91.218.175.182])
        by gmr-mx.google.com with ESMTPS id k21-20020ac24f15000000b00511a71805a8si462124lfr.8.2024.02.20.23.13.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 23:13:24 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.182 as permitted sender) client-ip=91.218.175.182;
Message-ID: <aef16f2d-b20f-4999-b959-b4bf4209b4dc@linux.dev>
Date: Wed, 21 Feb 2024 15:13:06 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>,
 Xiongwei Song <xiongwei.song@windriver.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eXw1VdsQ;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates 91.218.175.182 as
 permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On 2024/2/21 00:58, Vlastimil Babka wrote:
> The values of SLAB_ cache creation flagsare defined by hand, which is
> tedious and error-prone. Use an enum to assign the bit number and a
> __SF_BIT() macro to #define the final flags.
> 
> This renumbers the flag values, which is OK as they are only used
> internally.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>

Thanks!

> ---
>  include/linux/slab.h | 81 ++++++++++++++++++++++++++++++++++++++--------------
>  mm/slub.c            |  6 ++--
>  2 files changed, 63 insertions(+), 24 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 6252f44115c2..f893a132dd5a 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -21,29 +21,68 @@
>  #include <linux/cleanup.h>
>  #include <linux/hash.h>
>  
> +enum _slab_flag_bits {
> +	_SLAB_CONSISTENCY_CHECKS,
> +	_SLAB_RED_ZONE,
> +	_SLAB_POISON,
> +	_SLAB_KMALLOC,
> +	_SLAB_HWCACHE_ALIGN,
> +	_SLAB_CACHE_DMA,
> +	_SLAB_CACHE_DMA32,
> +	_SLAB_STORE_USER,
> +	_SLAB_PANIC,
> +	_SLAB_TYPESAFE_BY_RCU,
> +	_SLAB_TRACE,
> +#ifdef CONFIG_DEBUG_OBJECTS
> +	_SLAB_DEBUG_OBJECTS,
> +#endif
> +	_SLAB_NOLEAKTRACE,
> +	_SLAB_NO_MERGE,
> +#ifdef CONFIG_FAILSLAB
> +	_SLAB_FAILSLAB,
> +#endif
> +#ifdef CONFIG_MEMCG_KMEM
> +	_SLAB_ACCOUNT,
> +#endif
> +#ifdef CONFIG_KASAN_GENERIC
> +	_SLAB_KASAN,
> +#endif
> +	_SLAB_NO_USER_FLAGS,
> +#ifdef CONFIG_KFENCE
> +	_SLAB_SKIP_KFENCE,
> +#endif
> +#ifndef CONFIG_SLUB_TINY
> +	_SLAB_RECLAIM_ACCOUNT,
> +#endif
> +	_SLAB_OBJECT_POISON,
> +	_SLAB_CMPXCHG_DOUBLE,
> +	_SLAB_FLAGS_LAST_BIT
> +};
> +
> +#define __SF_BIT(nr)	((slab_flags_t __force)(1U << (nr)))
>  
>  /*
>   * Flags to pass to kmem_cache_create().
>   * The ones marked DEBUG need CONFIG_SLUB_DEBUG enabled, otherwise are no-op
>   */
>  /* DEBUG: Perform (expensive) checks on alloc/free */
> -#define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
> +#define SLAB_CONSISTENCY_CHECKS	__SF_BIT(_SLAB_CONSISTENCY_CHECKS)
>  /* DEBUG: Red zone objs in a cache */
> -#define SLAB_RED_ZONE		((slab_flags_t __force)0x00000400U)
> +#define SLAB_RED_ZONE		__SF_BIT(_SLAB_RED_ZONE)
>  /* DEBUG: Poison objects */
> -#define SLAB_POISON		((slab_flags_t __force)0x00000800U)
> +#define SLAB_POISON		__SF_BIT(_SLAB_POISON)
>  /* Indicate a kmalloc slab */
> -#define SLAB_KMALLOC		((slab_flags_t __force)0x00001000U)
> +#define SLAB_KMALLOC		__SF_BIT(_SLAB_KMALLOC)
>  /* Align objs on cache lines */
> -#define SLAB_HWCACHE_ALIGN	((slab_flags_t __force)0x00002000U)
> +#define SLAB_HWCACHE_ALIGN	__SF_BIT(_SLAB_HWCACHE_ALIGN)
>  /* Use GFP_DMA memory */
> -#define SLAB_CACHE_DMA		((slab_flags_t __force)0x00004000U)
> +#define SLAB_CACHE_DMA		__SF_BIT(_SLAB_CACHE_DMA)
>  /* Use GFP_DMA32 memory */
> -#define SLAB_CACHE_DMA32	((slab_flags_t __force)0x00008000U)
> +#define SLAB_CACHE_DMA32	__SF_BIT(_SLAB_CACHE_DMA32)
>  /* DEBUG: Store the last owner for bug hunting */
> -#define SLAB_STORE_USER		((slab_flags_t __force)0x00010000U)
> +#define SLAB_STORE_USER		__SF_BIT(_SLAB_STORE_USER)
>  /* Panic if kmem_cache_create() fails */
> -#define SLAB_PANIC		((slab_flags_t __force)0x00040000U)
> +#define SLAB_PANIC		__SF_BIT(_SLAB_PANIC)
>  /*
>   * SLAB_TYPESAFE_BY_RCU - **WARNING** READ THIS!
>   *
> @@ -95,19 +134,19 @@
>   * Note that SLAB_TYPESAFE_BY_RCU was originally named SLAB_DESTROY_BY_RCU.
>   */
>  /* Defer freeing slabs to RCU */
> -#define SLAB_TYPESAFE_BY_RCU	((slab_flags_t __force)0x00080000U)
> +#define SLAB_TYPESAFE_BY_RCU	__SF_BIT(_SLAB_TYPESAFE_BY_RCU)
>  /* Trace allocations and frees */
> -#define SLAB_TRACE		((slab_flags_t __force)0x00200000U)
> +#define SLAB_TRACE		__SF_BIT(_SLAB_TRACE)
>  
>  /* Flag to prevent checks on free */
>  #ifdef CONFIG_DEBUG_OBJECTS
> -# define SLAB_DEBUG_OBJECTS	((slab_flags_t __force)0x00400000U)
> +# define SLAB_DEBUG_OBJECTS	__SF_BIT(_SLAB_DEBUG_OBJECTS)
>  #else
>  # define SLAB_DEBUG_OBJECTS	0
>  #endif
>  
>  /* Avoid kmemleak tracing */
> -#define SLAB_NOLEAKTRACE	((slab_flags_t __force)0x00800000U)
> +#define SLAB_NOLEAKTRACE	__SF_BIT(_SLAB_NOLEAKTRACE)
>  
>  /*
>   * Prevent merging with compatible kmem caches. This flag should be used
> @@ -119,23 +158,23 @@
>   * - performance critical caches, should be very rare and consulted with slab
>   *   maintainers, and not used together with CONFIG_SLUB_TINY
>   */
> -#define SLAB_NO_MERGE		((slab_flags_t __force)0x01000000U)
> +#define SLAB_NO_MERGE		__SF_BIT(_SLAB_NO_MERGE)
>  
>  /* Fault injection mark */
>  #ifdef CONFIG_FAILSLAB
> -# define SLAB_FAILSLAB		((slab_flags_t __force)0x02000000U)
> +# define SLAB_FAILSLAB		__SF_BIT(_SLAB_FAILSLAB)
>  #else
>  # define SLAB_FAILSLAB		0
>  #endif
>  /* Account to memcg */
>  #ifdef CONFIG_MEMCG_KMEM
> -# define SLAB_ACCOUNT		((slab_flags_t __force)0x04000000U)
> +# define SLAB_ACCOUNT		__SF_BIT(_SLAB_ACCOUNT)
>  #else
>  # define SLAB_ACCOUNT		0
>  #endif
>  
>  #ifdef CONFIG_KASAN_GENERIC
> -#define SLAB_KASAN		((slab_flags_t __force)0x08000000U)
> +#define SLAB_KASAN		__SF_BIT(_SLAB_KASAN)
>  #else
>  #define SLAB_KASAN		0
>  #endif
> @@ -145,10 +184,10 @@
>   * Intended for caches created for self-tests so they have only flags
>   * specified in the code and other flags are ignored.
>   */
> -#define SLAB_NO_USER_FLAGS	((slab_flags_t __force)0x10000000U)
> +#define SLAB_NO_USER_FLAGS	__SF_BIT(_SLAB_NO_USER_FLAGS)
>  
>  #ifdef CONFIG_KFENCE
> -#define SLAB_SKIP_KFENCE	((slab_flags_t __force)0x20000000U)
> +#define SLAB_SKIP_KFENCE	__SF_BIT(_SLAB_SKIP_KFENCE)
>  #else
>  #define SLAB_SKIP_KFENCE	0
>  #endif
> @@ -156,9 +195,9 @@
>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #ifndef CONFIG_SLUB_TINY
> -#define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
> +#define SLAB_RECLAIM_ACCOUNT	__SF_BIT(_SLAB_RECLAIM_ACCOUNT)
>  #else
> -#define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0)
> +#define SLAB_RECLAIM_ACCOUNT	0
>  #endif
>  #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
>  
> diff --git a/mm/slub.c b/mm/slub.c
> index 2ef88bbf56a3..a93c5a17cbbb 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -306,13 +306,13 @@ static inline bool kmem_cache_has_cpu_partial(struct kmem_cache *s)
>  
>  /* Internal SLUB flags */
>  /* Poison object */
> -#define __OBJECT_POISON		((slab_flags_t __force)0x80000000U)
> +#define __OBJECT_POISON		__SF_BIT(_SLAB_OBJECT_POISON)
>  /* Use cmpxchg_double */
>  
>  #ifdef system_has_freelist_aba
> -#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0x40000000U)
> +#define __CMPXCHG_DOUBLE	__SF_BIT(_SLAB_CMPXCHG_DOUBLE)
>  #else
> -#define __CMPXCHG_DOUBLE	((slab_flags_t __force)0U)
> +#define __CMPXCHG_DOUBLE	0
>  #endif
>  
>  /*
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/aef16f2d-b20f-4999-b959-b4bf4209b4dc%40linux.dev.
