Return-Path: <kasan-dev+bncBCKLZ4GJSELRBC6G22XAMGQEVJAD6SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E06285D108
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 08:15:25 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-512bf07e9d1sf232070e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 23:15:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708499724; cv=pass;
        d=google.com; s=arc-20160816;
        b=g7VqoMqYHgaSA2N4Oev5fSh+ScYUgx1NwbQa9kWA9ShCsuzJD41QGXbu/6cWK7sV3X
         WdceILEzemCeu1+1t8ILFp6TJJIIOIPua2mFQHkCjF9KvEzCAu5yh4RY+lTSkM/1VOVY
         vVshoJLqjA0tWIdxd2qPQb/ywYQ58gZh4qBJ/3SptT7xJDKwmhrABw6VK8Sf6XzUlxEc
         EoMD7JdMX5DEcHG5GkTO5DTLqWmMIVQvmPkZGgWW71Ici/LBzPttY76s1+KBiRTdmMO5
         ZWtn3k59QmFIS/5rD71OcgMM4JpdOZxmyEFYCsZeAfB9zrFPfhaSd7pm3ZOBVFVyrN01
         z+1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender
         :dkim-signature;
        bh=GHfo3RD6nEwyiXQf8qpjhcYMSTDrOrbJtSm5kCWdxO4=;
        fh=qLisDXbta/grJQYaQ/NWtCV3LuBGftXyjjp8IdV3RxE=;
        b=GhFwPwh9euKvkSLVzD4dTGw8EKHhVR+LwgyTXnkv53itP7gbuvXKM/vugUeFbWu/z3
         MlRgkqs+L0dnodo64UagCVI91DW7wvrhQRvnFHgIj0sACpcbTsQe35rRf4IG8J/f1ezE
         qTcVEWeSDOd6ZrxSFSSeEUuKwfxzJyMPFFwh4o+eO3PHnovGnuF7mzSXBQKGwflBWCnx
         dEaxh3OM4y7/DlvVu+kKQMhtGUcfopeUPEXXHGgNJhZFTTOpmtlmK5oV3lbJzVA4P9+f
         ZrXwQnq52C9pWEGA1C/ALqLs3xfvBW0qea6104+CuDkUBRLwT5MQy4+dh1f49IYV/hzn
         x1pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fm28TUMb;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.188 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708499724; x=1709104524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:message-id:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=GHfo3RD6nEwyiXQf8qpjhcYMSTDrOrbJtSm5kCWdxO4=;
        b=OvthW9cHqIvepJqSKWAXBg0juj6n34wjMdFJeeZ6+izWEHK0Xmf9bUv7S2fl0nwYT/
         MK3+m+g/ikQ4qxAn7QWfF+zhpETaVx85QPsxnOnFvuJtA9aoylIScujA4mhSTkeXenB5
         IFDDX3uV5V5tLWjuDpC/4q3XY3bsPTX5e4LcMFq7XvFI1exFHwIswonnRdAMeSeTGnOt
         +KUeWZMivE6ZD7d9nXKJ2ZUBvdRrFyzmZFrb9TKRHmeVsLMAex7W1EqQHIrGPzXUOXK3
         bqHPmOjWWHOL/Ii01h4PJf+J3nQjh5HlBmA7FPrQRB0X/zeXRXGPrm70iIPNLyXaPB8q
         niTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708499724; x=1709104524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=GHfo3RD6nEwyiXQf8qpjhcYMSTDrOrbJtSm5kCWdxO4=;
        b=lFppJQih8M7hq3IMCC6cTMrdWWf9xRnFYKL+34tkAmS+ONMT+7Jg003g7CRTEn1eJ/
         tkonB0sFjQ/C3BYT67X8SUrNjsjwCLRdwqQsSHrJx8I8RSQqKjsY5DGFuA5bKZxoEo1K
         hKpxnRtcSfaIYr8swdrT6JxYrAlQl1RzWBmhWfpfCG5hTstwXAJrBVeaB2kAqgVrNocY
         O4aymYctLPqZytaAMFlU9T56BORv7ysF3wJ+aqMQJzZEwNhmBbLwYaKJlNI0hTjttNPk
         NRR7+bMSXmj4MpIaoLnJGDTSTYKI0dITkJG5141dyJEKO0Tit+MENADmz4OgqrJTvOs/
         2iFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmJg5MDapikEU0d3UpvKJTrIlvgUgu/0PfCYL5ia4HDcHxIOIiAzUKSW1ydp93IolzrAbPBf3zcQixbzDHWdgio5aedcCPGw==
X-Gm-Message-State: AOJu0YxE9nI2doM+cyCEpnse9bERmNAYHn3+rWqFNjrXDgNrZHAO65w/
	pWcj3R/OH52dRLOq2bNoZJ5tS4jqPrOmeDsWqLVa9vLURgpW8907
X-Google-Smtp-Source: AGHT+IFZ14F0Ysj8aAGaCUKC2D+CTXKSa2j9FE1yOm469uQQITfahbDJyBVXaRVc2ts4/JqgJsniGQ==
X-Received: by 2002:a19:ae1a:0:b0:512:b859:549b with SMTP id f26-20020a19ae1a000000b00512b859549bmr4196932lfc.67.1708499724042;
        Tue, 20 Feb 2024 23:15:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e15:b0:512:ab4d:5240 with SMTP id
 i21-20020a0565123e1500b00512ab4d5240ls96043lfv.1.-pod-prod-06-eu; Tue, 20 Feb
 2024 23:15:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVvy+JaBw0yUCtyiBM0qCVqOZS7vLuradJxj2bg5YzzjJELPZlsNAatJCHPh6t1xUcnA8hxuD7wwa/TDj2V3dEojVOpkLa0+WHNVg==
X-Received: by 2002:ac2:58d4:0:b0:512:bdd3:1539 with SMTP id u20-20020ac258d4000000b00512bdd31539mr3818030lfo.37.1708499721944;
        Tue, 20 Feb 2024 23:15:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708499721; cv=none;
        d=google.com; s=arc-20160816;
        b=FfHqKwCc/AYiufrRq5BbgVjMnyt+SO5ow6stBF8LVnLf0d8rnMTq11/UXcl6XabZ9R
         o5/+iGNRZGnctbm0Oi9//s3S/izdpCSw+Dzq3mwKiB2Kv+kor27P8ezjSPdmYoC082DH
         UJc3e7qd7hV8TvimzhwaU8+4bbowVwEl/0oAlqUmc3BVzlr1Lf1znwLThJcaYX4Ph93L
         thK7jO4TXRH30mncW3sc9p2DtdPiQq0SwHmrArnn6JuN8TSaKlbKV7/3zT515SZty8hE
         LCcgs7wWr0++QFZB4Ubg0CzKlMZwh0R6Pnp/TJXKR+8Khs9L6grSLzg8kvsZmv+frAZV
         Z3Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:mime-version:date:dkim-signature
         :message-id;
        bh=x6jQuMnrBC0WcnisUd1nhZPzN/7+9FC41RDCX5WDq+o=;
        fh=psRl9dOmmlv1R0vYTuQ68Rj9XPUleTtuphcDV1SUegg=;
        b=BsaiK9Ey5Gi6Bjxjpb+FGvKQmo880D/MYaxNz3qnOo8eP0xEQj9BUSsDmP6sDo3V2B
         hMv8KTSmHvIXHiJvXa9ZNUTAFMbRZl+UGvtEdIudFPEGKyYgm81ZaXwpjWVdX3SraaCg
         6qWWk8DKGZHfpV3k0wxLDwBcsxuF05vKjaRy6A47juCZx4CXC0pXfEK5t/N59wAFCKj6
         DqVmsLw3BvI2bz81bTqucj+fWrtRhg/hFo3RVhEAOMMRX02Itf+TMN9szL8n/ZBVX1xl
         tblGefri+gS8qdPySkjAtQBy7mThi4cUrgKuch1xO3coNt8jcqA+0genJ8eRsudt4sYs
         yapQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=fm28TUMb;
       spf=pass (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.188 as permitted sender) smtp.mailfrom=chengming.zhou@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-188.mta1.migadu.com (out-188.mta1.migadu.com. [95.215.58.188])
        by gmr-mx.google.com with ESMTPS id o19-20020a5d58d3000000b0033ce867f703si513857wrf.5.2024.02.20.23.15.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 23:15:21 -0800 (PST)
Received-SPF: pass (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.188 as permitted sender) client-ip=95.215.58.188;
Message-ID: <50522603-85a9-4e4b-ab44-db40ee7bf476@linux.dev>
Date: Wed, 21 Feb 2024 15:14:44 +0800
MIME-Version: 1.0
Subject: Re: [PATCH 3/3] mm, slab, kasan: replace kasan_never_merge() with
 SLAB_NO_MERGE
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
 <20240220-slab-cleanup-flags-v1-3-e657e373944a@suse.cz>
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Chengming Zhou <chengming.zhou@linux.dev>
In-Reply-To: <20240220-slab-cleanup-flags-v1-3-e657e373944a@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: chengming.zhou@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=fm28TUMb;       spf=pass
 (google.com: domain of chengming.zhou@linux.dev designates 95.215.58.188 as
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
> The SLAB_KASAN flag prevents merging of caches in some configurations,
> which is handled in a rather complicated way via kasan_never_merge().
> Since we now have a generic SLAB_NO_MERGE flag, we can instead use it
> for KASAN caches in addition to SLAB_KASAN in those configurations,
> and simplify the SLAB_NEVER_MERGE handling.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Chengming Zhou <chengming.zhou@linux.dev>

Thanks!

> ---
>  include/linux/kasan.h |  6 ------
>  mm/kasan/generic.c    | 16 ++++------------
>  mm/slab_common.c      |  2 +-
>  3 files changed, 5 insertions(+), 19 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dbb06d789e74..70d6a8f6e25d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -429,7 +429,6 @@ struct kasan_cache {
>  };
>  
>  size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
> -slab_flags_t kasan_never_merge(void);
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  			slab_flags_t *flags);
>  
> @@ -446,11 +445,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache,
>  {
>  	return 0;
>  }
> -/* And thus nothing prevents cache merging. */
> -static inline slab_flags_t kasan_never_merge(void)
> -{
> -	return 0;
> -}
>  /* And no cache-related metadata initialization is required. */
>  static inline void kasan_cache_create(struct kmem_cache *cache,
>  				      unsigned int *size,
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index df6627f62402..d8b78d273b9f 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -334,14 +334,6 @@ DEFINE_ASAN_SET_SHADOW(f3);
>  DEFINE_ASAN_SET_SHADOW(f5);
>  DEFINE_ASAN_SET_SHADOW(f8);
>  
> -/* Only allow cache merging when no per-object metadata is present. */
> -slab_flags_t kasan_never_merge(void)
> -{
> -	if (!kasan_requires_meta())
> -		return 0;
> -	return SLAB_KASAN;
> -}
> -
>  /*
>   * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
>   * For larger allocations larger redzones are used.
> @@ -372,13 +364,13 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  	/*
>  	 * SLAB_KASAN is used to mark caches that are sanitized by KASAN
>  	 * and that thus have per-object metadata.
> -	 * Currently this flag is used in two places:
> +	 * Currently this flag is used in one place:
>  	 * 1. In slab_ksize() to account for per-object metadata when
>  	 *    calculating the size of the accessible memory within the object.
> -	 * 2. In slab_common.c via kasan_never_merge() to prevent merging of
> -	 *    caches with per-object metadata.
> +	 * Additionally, we use SLAB_NO_MERGE to prevent merging of caches
> +	 * with per-object metadata.
>  	 */
> -	*flags |= SLAB_KASAN;
> +	*flags |= SLAB_KASAN | SLAB_NO_MERGE;
>  
>  	ok_size = *size;
>  
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 238293b1dbe1..7cfa2f1ce655 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -50,7 +50,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>  		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> -		SLAB_FAILSLAB | SLAB_NO_MERGE | kasan_never_merge())
> +		SLAB_FAILSLAB | SLAB_NO_MERGE)
>  
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>  			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/50522603-85a9-4e4b-ab44-db40ee7bf476%40linux.dev.
