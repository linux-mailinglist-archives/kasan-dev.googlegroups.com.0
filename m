Return-Path: <kasan-dev+bncBAABBUEXRCJAMGQEH3JFG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EACA4E9FC0
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 21:26:09 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id a5-20020adfc445000000b00203dcb13954sf4520057wrg.23
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 12:26:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648495569; cv=pass;
        d=google.com; s=arc-20160816;
        b=GWErqlThs+h6/TAeMB1YdxgGN5fKz9gyMwtGgK4q7MBUhLZkeXmgcvKRDz5/P+b29r
         q/nylZQ0p+fFbp2FVT/rjW86aeV5OEZekcMP/AMTtsCFtykoVkfvFAZe9Fa2IYR51ZcY
         cPdM8GkSONvc/xBeDNk7Mne7/tbSgbk4unRN4y2qFGRQzTL2V82BPal1KTb7XmJwBkKs
         KfuqjnaTVSspghXsvFBT37p//2FAHMTZ1UR65UhD/wsV737cdaE5FBuEfwm51Kkb2wIC
         tFwOny83v9vFOJJooDQ0yuQTNbTFb27CyfTCtkaDRcAhIYQ3tBG93msg60N0ElWxNLj1
         /F4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KBPEf/EuhEgG0oSD53lONGQnYNzj7iY21pWqteSfX5U=;
        b=rIV8DBp8nIS3D9uabCQPnw1XPMRQ1+liZztTAAbpZ3JPOOJcT0wsdOcWBIdmiT+ieU
         k3HVVQbY8bs9xwHTr4HcgH10p1mRwUg7nVFy5GvQSWIbL3V2cEoePVILLO0Wv0Ejdk8x
         NmGOATBhdkhHb/aUNesTkWesa8z6FELuQI4/deHRPtlbZlbmFAUfKI+NcZfv19AWOdJm
         qajT9C4Ss4lDFTKsLDuNj0HVn2rlLg3QfwWt9tzOY7l+MC6AVZ0ntoavm8NKVCJTFOyZ
         YSRPubB13DlLrIvGiv6UKiHLuUf14KGBj+qUp95n1TGMcVdXiRRIBjolhoq9pvtU0tR8
         U2Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jpOSnpVG;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KBPEf/EuhEgG0oSD53lONGQnYNzj7iY21pWqteSfX5U=;
        b=aH/SvN5bomqW50fgqBO9Ikktc7ggCzmJo+yTEatvCPqRciZKqxpfl0yRAzR0MOyQS6
         SYFUDkehxNmB1cPENicI0da/hpt/6US5GbGpY+ON7cGmo/ADu6ssNebF48YWkO8+ir0k
         +r1RtW56EUMpiQjMF2g8ynf+5a0loIZG0d8WpK7/kGqXp+tq7xdrXfJNWq+X/ho0h8wF
         kboO7YDK8WPfYHpLS5hYirMwVT7FM74nMW/7DgxOYKDZ6JtsZ6Ozdk+lZdFzjD8cQDRh
         SwViUOiJKbz5OdOs3j3ywKK6L/4awTs49bH3HiFPO99/3rwZnDqf9jUzhWn5bTxoPGPZ
         wQ9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KBPEf/EuhEgG0oSD53lONGQnYNzj7iY21pWqteSfX5U=;
        b=c60u+MWkYkDWjDOoR9d8YCw4XkYDM/B4gRh5eJZKHgGLmaHXXA3mGvn2rrrjhH1RrY
         v1TUi1lPB3Da40/q25x6GsV8R0V6kQwb+3Tv305k1qcwX6cTdbdNEpZ/ole8Y2CsfOW2
         fOGU0ttVm9Ow+xQ85a/7QPFq+hi8Z+npRxRyy/Pr85Z4Iei/nknMKWwl5IxYU9iDEZXh
         cJV/Q6vyP1n3fJPW0R7piUP6oqils8alnlIAI4MjzPRXIhZtGVeWctYh7tVeOQzwH6M5
         sEtQeXmANTLU3dGfU3/KazAPhx8/IFbHeZn2b8FspSJ+6NSQH80U+cNXVHKtimK8wOO4
         3sRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322ZiD5zdvxFB+0VeaHJkuA8ezEn8RasJnp04zUQmF7elVIG1y6
	MQ5Ylb+Rrmu89Tdq0lFCD5k=
X-Google-Smtp-Source: ABdhPJw+cS8HIpWwB93zxdTTmOVWLIuvt588pllrKrlmKSwENMGu+609Vpr0W/jMKRhVwUmphoiTaA==
X-Received: by 2002:a05:600c:600a:b0:38c:f953:adc0 with SMTP id az10-20020a05600c600a00b0038cf953adc0mr1020528wmb.188.1648495569050;
        Mon, 28 Mar 2022 12:26:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6f11:0:b0:205:92ad:ce90 with SMTP id ay17-20020a5d6f11000000b0020592adce90ls1741758wrb.0.gmail;
 Mon, 28 Mar 2022 12:26:08 -0700 (PDT)
X-Received: by 2002:adf:8296:0:b0:203:e8bc:7337 with SMTP id 22-20020adf8296000000b00203e8bc7337mr25403073wrc.118.1648495568309;
        Mon, 28 Mar 2022 12:26:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648495568; cv=none;
        d=google.com; s=arc-20160816;
        b=G4sbggTK6G445TaSSN5ipHVhaMx0X9j6KkjgmcTgTFtjry39+R7kBhFYYrJbPkk8Ma
         2uecIAnAQIiUODZwQU7KIvMVgIhqC7lr5Gd0GsEvmAOtlhTguM/S5iKvhwMhFZIL8rWO
         HDdVEoXY1geX7Z8pThk5LCJvaA6Wbwug8v1xFkAsfv6lEioJt6KAnScAl8SDRC9DGH9g
         2yu69EuznN6+f6YZvjJojmxBJhfssbpb9YU4vnX8y4cKqmX6Nt1vroaIwxmVYV5NdISD
         QBQ2ZqA1CQ+AuGrxd3r1gsNR0meu5MEWoyJ/2MEw6MaC+Y9h5JMvYh55pBpewIg4yxJm
         YFrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=HI+dsvmjaN/rkGaZbNLF+cKlPT7DGdpfJYFLeEXc0Ts=;
        b=q9a5OONEQaH8IZbELlSjkzoziFI4kCFpnCtAI4h+/BpWVz8gLJB2hUxAhi10C2Q6E4
         jAYTluQEQSLDLiMriMRKaiesPsVcVZlSO/KFremzlW58Km9qGxtBbbI8nEimuD0hErV/
         dZroVKPpNeCO4GqRXHxxNHNkMAWA/EMRMOB/pAQWQnM4AIN23/D+6smUGANdfSm/aqI4
         xeGMtyLJ9jyqC0iX6T5ra5rLpgOvLL4rj6KLp011WuTckKOy1MfAahetY7Ag+R27OB1f
         YtYNPTla7btKLUCvSSeMfDnIkD8q3Aw6ndE8Fjf0I6Ssa6wbkdkWmVnw+Nr7AWuP7o6e
         MHXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jpOSnpVG;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o13-20020a05600002cd00b002041c300239si917864wry.2.2022.03.28.12.26.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 28 Mar 2022 12:26:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
Date: Mon, 28 Mar 2022 12:26:02 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	duanxiongchun@bytedance.com
Subject: Re: [PATCH v2] mm: kfence: fix objcgs vector allocation
Message-ID: <YkILyqc1WIfQLCTI@carbon.dhcp.thefacebook.com>
References: <20220328132843.16624-1-songmuchun@bytedance.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220328132843.16624-1-songmuchun@bytedance.com>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jpOSnpVG;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 2001:41d0:2:267::
 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;       dmarc=pass
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

On Mon, Mar 28, 2022 at 09:28:43PM +0800, Muchun Song wrote:
> If the kfence object is allocated to be used for objects vector, then
> this slot of the pool eventually being occupied permanently since
> the vector is never freed.  The solutions could be 1) freeing vector
> when the kfence object is freed or 2) allocating all vectors statically.
> Since the memory consumption of object vectors is low, it is better to
> chose 2) to fix the issue and it is also can reduce overhead of vectors
> allocating in the future.
> 
> Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> ---
> v2:
>  - Fix compiler error reported by kernel test robot <lkp@intel.com>.

Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>

LGTM, thanks!


> 
>  mm/kfence/core.c   | 11 ++++++++++-
>  mm/kfence/kfence.h |  3 +++
>  2 files changed, 13 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 13128fa13062..d4c7978cd75e 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -555,6 +555,8 @@ static bool __init kfence_init_pool(void)
>  	 * enters __slab_free() slow-path.
>  	 */
>  	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> +		struct slab *slab = page_slab(&pages[i]);
> +
>  		if (!i || (i % 2))
>  			continue;
>  
> @@ -562,7 +564,11 @@ static bool __init kfence_init_pool(void)
>  		if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
>  			goto err;
>  
> -		__SetPageSlab(&pages[i]);
> +		__folio_set_slab(slab_folio(slab));
> +#ifdef CONFIG_MEMCG
> +		slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
> +				   MEMCG_DATA_OBJCGS;
> +#endif

We can probably put CONFIG_MEMCG_KMEM here, but it doesn't matter that much.
In the long run we should get rid of CONFIG_MEMCG_KMEM anyway.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkILyqc1WIfQLCTI%40carbon.dhcp.thefacebook.com.
