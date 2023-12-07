Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBSF7YSVQMGQEI7LV4XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id D2999807DE5
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 02:28:41 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-42582e5c496sf341291cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 17:28:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701912520; cv=pass;
        d=google.com; s=arc-20160816;
        b=gulh+GO0+Y9P6j2JONPCkc39KR78PQT/Q2wtaFvq2grE+2qLu5TPYYN99m8x/jSbbc
         wC5sKkdUPe88gTHFUJowh70vv5TvXyCur9md1EuOjQUAUdelk+PUoZaoWAdebAx28W0/
         LSePmGpX2uPi77cDre2t8vtGFxNNx166t8vpZ0vTxvCghwW+wAb+zWyAGekt8NArJbEk
         6LPI2OThsnxq3/jiuLOUTAB8GxDT6Fc6j+Jbo4IsO5B4EfL/V6BIXJvyVXPfdLSVYfPs
         Z0PvCaOL5nYre37IShh/+wbzCm8D7eAwyGiZvbZQt6QW/MEVsWf51Kc8lKSS473dyoVY
         TpRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=xMY2PHba8hSUX8MWQk/h8PX+7O9EI9x4evJ8rO4f8kY=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=vz0HKFtm2UK+/IU4hUqcN0kpTQc/2feIey7NFXslF3ygn7remhaUzfRQg1SqN/ht3Y
         5nC1OPD4nRjUYaAWcxD+GWA6QHxS/739zQAmJ10WPhwVqmCzzM1LTbNuLGmGbTdZA1yP
         OvOqVuN1Lisi2/ov7bsqxbqtHy9UMxdZSqLRfPM284qEBbtosvRbPZ1VHQaq6vIOPiht
         Mjv2DVtFUcr/hDZhIRX1nhJhi3i6N29Ax1kCyoxgup5xk+pcRxZMWl2/SjbDRabSLl0E
         2n0RAhqWOpsRpKn80+uoK2nSuCOXondGbMq2CRQA7/CP7k1I+AFIslrFaB6sx5ONe57+
         2OfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FZFq/kUX";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701912520; x=1702517320; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xMY2PHba8hSUX8MWQk/h8PX+7O9EI9x4evJ8rO4f8kY=;
        b=AUoXr80rkh4fmCeBRBrC4DgiDYEHGKUZqPT9X4BZhnGJ4idmSGbHz5ttUDumrusBHc
         c67+gbcJHX0OoR1AsjYgIH41k8FzCe/PbeDTkxfoKBbsBO6XEI/35QCQ7h8Pf1IC6Wgg
         X4xB5U0zvmT1rtPeDw8QvBV3kSnSdPfTVWPGldjQ9CQP0baYKqOpngKRu/wFHw6fBKl+
         nFJDFXgT8GlncIxW5Z6jlLkLHk29ejVx0vDW4Z6+xKxjAlE9H1gg2ymZp8nt8Rs7EAiY
         R5NGBQDYXA3FtExa3N6U2ndLCOvU4mpTxfEv4M9YM51kKSkHQIEGRgP/0fWJt2pfAV4c
         RoIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701912520; x=1702517320; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=xMY2PHba8hSUX8MWQk/h8PX+7O9EI9x4evJ8rO4f8kY=;
        b=PF1qdGkY6PTt4o/35YjXGJ2wxdBXxpqlH5f4v8sADuCukDrZpF6+zeBQSuJnfEvKZ3
         FbJl1WGE469hNGFb/DHRsLMbmfbb+dDY8IsAt7+lS+jMeL+I1yWZTOGvisD77friFcPm
         iQDXkT8BdunRjIS2grTVneTajxZ2n8Nus20I1Sqef5RgGpX7JWzq55MU8BFA/r5lNCI5
         2B7yxI/uDrZ9g1s2DOIOOWq0ASlZjg4rKxNjfjHdzniGcLbmNiPjZllh0VACfh1lF6JC
         Se8n2uQHshcD2qwH8N2P4ASD4iaDP/bf39BD9hbAx7wlLTsx22L22prxcrp9vgLHTUND
         08RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701912520; x=1702517320;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xMY2PHba8hSUX8MWQk/h8PX+7O9EI9x4evJ8rO4f8kY=;
        b=g+GN5G30fn7CG+ai6DBNW4hgfNd3XWOBLugkmRGHrAp/Dc1OnbKKuhLPCY1dvUY93V
         Q+A95Q5I4ipEsdGr8Uzdj6RU9qMgvnVcAuTXT5BU9FA9gbO5DQpHsw/ot2tA9Y/CahvY
         nDybgpjToZ8c0SP0Rba3b5OkhwXsywdw4rSLxvzk5IIgmVFs1MUeOeaDfZ8RMJ0IH4y1
         GBqvL/BrVId/S1AETAxpBKeLPssWrG8aQa8EY8j4bU0Etjc/syjOeyC332lDw8Fe9ayi
         EW2NOa6Orx+6Aah12QxuEQpS8/MRW2bgRtM+GYJyVr66Pu9biUoqFbir2z0wmr4ueM3Z
         6auw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzFbq2tubeCoaSAm+87DQGzX8rOnvzfRg4WxTOxsh1RPKDW4t79
	alyrTfh+RkeOFdDCP8AInzQ=
X-Google-Smtp-Source: AGHT+IHSJyY2HJwXmQmKldCbwAmEU43QZV0fpSP7yd8EIikK+IGLtSgxp09cdf2cDeN3E0xJjhOqig==
X-Received: by 2002:ac8:5891:0:b0:423:e912:52c5 with SMTP id t17-20020ac85891000000b00423e91252c5mr470311qta.25.1701912520699;
        Wed, 06 Dec 2023 17:28:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:102:b0:423:8c6b:503a with SMTP id
 u2-20020a05622a010200b004238c6b503als450438qtw.1.-pod-prod-07-us; Wed, 06 Dec
 2023 17:28:40 -0800 (PST)
X-Received: by 2002:ac8:5712:0:b0:425:8bbf:f6b1 with SMTP id 18-20020ac85712000000b004258bbff6b1mr600565qtw.108.1701912519923;
        Wed, 06 Dec 2023 17:28:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701912519; cv=none;
        d=google.com; s=arc-20160816;
        b=FviPmyNyNFU+t6pJas2fXpMr+C3KjvT4D4oYMnxJE4a8LTHCYMWGFVDecIbKu3hdnE
         hJLVoHsehdJCEKOojaanGUG5pg1zXHzL0dfwpmnquJY1oml150WudGvykqPD4YMYSNSv
         hN4IMvz7BRkVtUFdK8uTh1geiTG2T211hrznK37rYDKUiCHPWIV/tD4CAVTYX6Z5qrNy
         zaemxsxcHcuqdKJZyR9YDLgcPz4Q5cJ9xrLJXx2mVTweHfzYfkmunUw+6vErweaWENHe
         F2x5BjVtrBgga6nJzUNwzL6J02nDTcYHw8TBlfK3JfQv69444J7X+BJyrM1xG5lJ0Ccu
         O/8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3u1soC42kxxszJtJ9Fi1B4cg1LFazMYjfirO31EmOoI=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=sVfvdByd8rELjvYwLO8WYCg35+EEXLxv8MCYg30YgMW+I9WwvE3iDitl0luLfTixAj
         kLDeFg9ysMmSeU1ZVMH9NGVjBzQTc22e8WR0JXcZZSRmgSEBhusVIt/guCuj5PZBXmV5
         SloP3o38VRGn2M56MT+qYGM9dMUfc7K9hXWsN9bC98OXGVMj0S+44TVaisrakVhR3TxS
         nVeCF193BrAqTOQUoVdv0nq6olyFwz/q18WBxzLq/IA/v1Qf2vhTvYIrUBxpCrHPChIf
         UacC+8uc5S/LS5ZOxaaXWLSeYpkXvLVfQVCACpDjbvdtQLLBf/GhNi/mlR8nxEsxPkt0
         JGng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FZFq/kUX";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id u5-20020a05622a17c500b00423e5a4fb24si84978qtk.0.2023.12.06.17.28.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 17:28:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-1d0c4d84bf6so2925955ad.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 17:28:39 -0800 (PST)
X-Received: by 2002:a17:902:6bc5:b0:1d0:bfb7:6709 with SMTP id m5-20020a1709026bc500b001d0bfb76709mr1280230plt.24.1701912518601;
        Wed, 06 Dec 2023 17:28:38 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id p14-20020a170902780e00b001bf8779e051sm89840pll.289.2023.12.06.17.28.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 17:28:37 -0800 (PST)
Date: Thu, 7 Dec 2023 10:28:24 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 17/21] mm/slab: move kmalloc_slab() to mm/slab.h
Message-ID: <ZXEfuHomAtFw3pKI@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-17-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-17-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="FZFq/kUX";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:28PM +0100, Vlastimil Babka wrote:
> In preparation for the next patch, move the kmalloc_slab() function to
> the header, as it will have callers from two files, and make it inline.
> To avoid unnecessary bloat, remove all size checks/warnings from
> kmalloc_slab() as they just duplicate those in callers, especially after
> recent changes to kmalloc_size_roundup(). We just need to adjust handling
> of zero size in __do_kmalloc_node(). Also we can stop handling NULL
> result from kmalloc_slab() there as that now cannot happen (unless
> called too early during boot).
> 
> The size_index array becomes visible so rename it to a more specific
> kmalloc_size_index.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slab.h        | 28 ++++++++++++++++++++++++++--
>  mm/slab_common.c | 43 ++++++++-----------------------------------
>  2 files changed, 34 insertions(+), 37 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 35a55c4a407d..7d7cc7af614e 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -389,8 +389,32 @@ extern const struct kmalloc_info_struct {
>  void setup_kmalloc_cache_index_table(void);
>  void create_kmalloc_caches(slab_flags_t);
>  
> -/* Find the kmalloc slab corresponding for a certain size */
> -struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller);
> +extern u8 kmalloc_size_index[24];
> +
> +static inline unsigned int size_index_elem(unsigned int bytes)
> +{
> +	return (bytes - 1) / 8;
> +}
> +
> +/*
> + * Find the kmem_cache structure that serves a given size of
> + * allocation
> + *
> + * This assumes size is larger than zero and not larger than
> + * KMALLOC_MAX_CACHE_SIZE and the caller must check that.
> + */
> +static inline struct kmem_cache *
> +kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
> +{
> +	unsigned int index;
> +
> +	if (size <= 192)
> +		index = kmalloc_size_index[size_index_elem(size)];
> +	else
> +		index = fls(size - 1);
> +
> +	return kmalloc_caches[kmalloc_type(flags, caller)][index];
> +}
>  
>  void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
>  			      int node, size_t orig_size,
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index f4f275613d2a..31ade17a7ad9 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -665,7 +665,7 @@ EXPORT_SYMBOL(random_kmalloc_seed);
>   * of two cache sizes there. The size of larger slabs can be determined using
>   * fls.
>   */
> -static u8 size_index[24] __ro_after_init = {
> +u8 kmalloc_size_index[24] __ro_after_init = {
>  	3,	/* 8 */
>  	4,	/* 16 */
>  	5,	/* 24 */
> @@ -692,33 +692,6 @@ static u8 size_index[24] __ro_after_init = {
>  	2	/* 192 */
>  };
>  
> -static inline unsigned int size_index_elem(unsigned int bytes)
> -{
> -	return (bytes - 1) / 8;
> -}
> -
> -/*
> - * Find the kmem_cache structure that serves a given size of
> - * allocation
> - */
> -struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
> -{
> -	unsigned int index;
> -
> -	if (size <= 192) {
> -		if (!size)
> -			return ZERO_SIZE_PTR;
> -
> -		index = size_index[size_index_elem(size)];
> -	} else {
> -		if (WARN_ON_ONCE(size > KMALLOC_MAX_CACHE_SIZE))
> -			return NULL;
> -		index = fls(size - 1);
> -	}
> -
> -	return kmalloc_caches[kmalloc_type(flags, caller)][index];
> -}
> -
>  size_t kmalloc_size_roundup(size_t size)
>  {
>  	if (size && size <= KMALLOC_MAX_CACHE_SIZE) {
> @@ -843,9 +816,9 @@ void __init setup_kmalloc_cache_index_table(void)
>  	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
>  		unsigned int elem = size_index_elem(i);
>  
> -		if (elem >= ARRAY_SIZE(size_index))
> +		if (elem >= ARRAY_SIZE(kmalloc_size_index))
>  			break;
> -		size_index[elem] = KMALLOC_SHIFT_LOW;
> +		kmalloc_size_index[elem] = KMALLOC_SHIFT_LOW;
>  	}
>  
>  	if (KMALLOC_MIN_SIZE >= 64) {
> @@ -854,7 +827,7 @@ void __init setup_kmalloc_cache_index_table(void)
>  		 * is 64 byte.
>  		 */
>  		for (i = 64 + 8; i <= 96; i += 8)
> -			size_index[size_index_elem(i)] = 7;
> +			kmalloc_size_index[size_index_elem(i)] = 7;
>  
>  	}
>  
> @@ -865,7 +838,7 @@ void __init setup_kmalloc_cache_index_table(void)
>  		 * instead.
>  		 */
>  		for (i = 128 + 8; i <= 192; i += 8)
> -			size_index[size_index_elem(i)] = 8;
> +			kmalloc_size_index[size_index_elem(i)] = 8;
>  	}
>  }
>  
> @@ -977,10 +950,10 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller
>  		return ret;
>  	}
>  
> -	s = kmalloc_slab(size, flags, caller);
> +	if (unlikely(!size))
> +		return ZERO_SIZE_PTR;
>  
> -	if (unlikely(ZERO_OR_NULL_PTR(s)))
> -		return s;
> +	s = kmalloc_slab(size, flags, caller);
>  
>  	ret = __kmem_cache_alloc_node(s, flags, node, size, caller);
>  	ret = kasan_kmalloc(s, ret, size, flags);
> 
> -- 

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> 2.42.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEfuHomAtFw3pKI%40localhost.localdomain.
