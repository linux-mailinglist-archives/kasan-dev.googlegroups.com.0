Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBF5Z2OLQMGQEFBCPUHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 176C758FACC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 12:40:25 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id o69-20020a17090a0a4b00b001f527012a46sf2174936pjo.5
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 03:40:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660214423; cv=pass;
        d=google.com; s=arc-20160816;
        b=KShnGmSQ63UzjzSclrRPTepFFKwa6JnpY02sDoDKOc/37SZabZZu3BdJm1P4LdbtCS
         9R7aXdkGg4AoSL0tj7zrPoGN5KHwklZLN1vEDO9IgEkffZvyeL08k4n1qi8B1l0YWK5m
         GCfUzd09AXhKPBthHXnpieV/+tv1dtJotvV09HGEl90X1qpjLiNw5FyLgQq+wydFd57t
         /sTMsFqKQwJtrworUECLmsso1ffH0BPjorqq9CQKVVWoiLZI7Y2JgtnMWtRee3c9WGns
         TXT09jlUbYCn15ch9FQ1smZyJxndjyyeo2CDVOnwMmFNXTDz329fqePGAIsA62fWk8bw
         AiMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=M7j3/FCOfD4jx+5bqirGhiZOr6jY00NhCz5QH7oEexg=;
        b=Q21aEp7ctYBRGkYRfMgWlI1NW6GhR0zqE9PZcZo6Tbk380jMCzSvU27jbLqDDoD7rR
         ql/ntWWmt5kIM4fQaymvV9QWWUVXndIVkCi1nt+XEsAfYQ9WetxYsb93F1X4njjYahWt
         oi9kITGxQgktQ91bDcN/TbqxRYWii9xfy1XVmclGQIIEG3Stifylv6FzZhUvfjCo0YHZ
         ABIN54+BBBd8/rkb+THN4xyr02ltteXqFV5MvGwkpgZ6tgqEvrazUDUer20FyYnvuGm2
         Qn4VwzRYaYVa2BNTkU/Mpq1kVJyfZKpsmeKeqVxjljvb7oRY00ljjDz8YIHAiNrO66nm
         4Q5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iUXron1L;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=M7j3/FCOfD4jx+5bqirGhiZOr6jY00NhCz5QH7oEexg=;
        b=pfgra/wfD51WJXtm5IHdrFHOSu4nNvaDJv8DFT8fivoLAa91WycNK1oxhbSryJ1BsO
         kOfU4B5+f5a7JhpY790SZMbo80eiQUyNTLZe+5tDff9zt18dHpB5qOFbQDY+E1FiXJc/
         FuC7Pr8RRXLv1miW+rgsn9PzbDIZQ1GbhuHGfz+5WeuZQGUm0gtUEHB+cw3eOWfkekoC
         VcfdDleBjRzIEDYECHaA8F+/VCpxwZ0bXIQOeEpHKVtvaKj0XNgm7fL+Ww+NIMGcMaUC
         w9QhcY/LpE9V70y4h28y5mPoOOEf9xEncyMQ4JDo6T/1rI4/MdobS5yXeGnFpU+9G82O
         Y5Pg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc;
        bh=M7j3/FCOfD4jx+5bqirGhiZOr6jY00NhCz5QH7oEexg=;
        b=JabI4WqYigikRlSzJm6OKm32E47VtqqcSF8Y9bM0IOdQWTU6eBiyHNMKfbGeSK1ux6
         3e/I4MApKs2X1TK12zmlrpbuGtWUld9D2yWAHnzl0Cn8SNULGb11v6JCU+V7F8zjXGml
         /PXcVaD8c8FqM8mDpIVzbMDKrREHCFlpc1pfcqZ5RB4zsb0zUB8qGYjTbIiPjVOwYOBn
         86VXA+VGhgn6tSk70ZRbcPjmMt3vELUw4mFgSudLcVeQLab0nbnCrQ8LnRaFLOVNXjtG
         5umRMDJRE/gp55Vtov58Zn5UJDzkLhSafIzSmuKthCHkNOtwO3m6A4NzfCF98wma87Ul
         J2KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=M7j3/FCOfD4jx+5bqirGhiZOr6jY00NhCz5QH7oEexg=;
        b=JLVef6cLKa/ERZHly7ILM8/9U6YO19CqcTfztFwlvfHfqD//kcpXR69OIXdE05Gviy
         syMwnzF705IL4xZb+dPvV89HA4c2qNDAM5X+5h+GCq4jaFmJo6EwWDGmkN9qCoBsoy7+
         wd5jIb3dunWM1TQPI+9lhI9Y1g9KnapxUzMBg6CCxJKmSdB9loIdMGHOlkz+CqU92pM3
         WFFaSIXZbTeD4K7NNP0dbPz6OV+BLO4qBJP294zvmQC+lWpGE4UJk29O1cI2oGRz76do
         /r+vEfazT6jYXFOrTEflx/VOw4NSofjMQ50FhsCoCFjDfd77hEHs5Ohj9q+Omx7mAXuK
         rx3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo35sKuQlyOpt51DiQqIeoCBLgA8J82o2RcrsLmUgMKpNVBmL+dr
	qMDjcHoFcAFMnUyMFf3CTL0=
X-Google-Smtp-Source: AA6agR7oWXEnLjNGx49zDt6grRRrzBjgQd6NXITdBRaYFOvNtTX2iOljlSZgzPgOcGXhv+eYApGSjA==
X-Received: by 2002:a17:90a:fd06:b0:1f3:29d8:72d8 with SMTP id cv6-20020a17090afd0600b001f329d872d8mr7979243pjb.23.1660214423381;
        Thu, 11 Aug 2022 03:40:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dad0:b0:16d:6f9a:131a with SMTP id
 q16-20020a170902dad000b0016d6f9a131als786521plx.5.-pod-prod-gmail; Thu, 11
 Aug 2022 03:40:22 -0700 (PDT)
X-Received: by 2002:a17:90b:3502:b0:1f3:550:5f6f with SMTP id ls2-20020a17090b350200b001f305505f6fmr8320778pjb.49.1660214422414;
        Thu, 11 Aug 2022 03:40:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660214422; cv=none;
        d=google.com; s=arc-20160816;
        b=KqRd3PRFLpXPSd+kWhrzTX4b2bZnAfPd1vYsyRte63IZAeoD08qrDfvd8oZw5tmje4
         00j51MzxSHAyOQpiAecJZZzrEGpy9q+zKqK49o6MYozb1qBjczFfxZjGlW8SUvD0PBB0
         QRPOEfncGg6sZi5+6dub1oMLYVIH+lldPeCNN5rERjeUc4/zu7oT9mUX6+Ax4yTQHdsW
         EFP+9F9xIpyalo9Gg6zcQtaHs0MJK0uJfvkQ4LuTI9OyqMfAE82srHYv1ImN4QtViJ1v
         laXm3/9cKUH3/2r6/nI5vsESHB2m6bbVkt9xYCJD/kt+2+OyEUSf+36rkYlgupPKzJDD
         i89Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eGbXQsKb8yt2To4bDCbL2Z7QyRG8T1fC5MTNEkBLar0=;
        b=JC04Fw2RCpFEaxoYIYA5osxBLhvo9eWrw7M50Dqd3gJMjz/z+KQ6tCgMkUSPqdaNBZ
         MG8K7dGNtGIJFicHs1JfQXg1Gm5z2OJ1fj6TSKZZYoUVA123nnbjuJZuFzA05ddpcvZO
         XDhVv9tHlDIrTQ71JIb7ElAFm6KGVfLPwCo7DxGD9q2nztk7urPsdmHVBnz7DGj0Sqcw
         zNWQjliam3zDGyZHWHWxwT4kjUVR2/eQm9BbXbahQS0gjVssqv+fvv4CC5h/C+DGa4l4
         sfXprYHvxfi/s52H6Cv8WZTeTBKBH2NhZq17VuPtZc9ni839/LLSFYkw+5BFdEZ2kEVw
         bSaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iUXron1L;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id ne7-20020a17090b374700b001f336b5004dsi134403pjb.3.2022.08.11.03.40.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Aug 2022 03:40:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id p18so16589550plr.8
        for <kasan-dev@googlegroups.com>; Thu, 11 Aug 2022 03:40:22 -0700 (PDT)
X-Received: by 2002:a17:90b:3e8c:b0:1f7:3792:d336 with SMTP id rj12-20020a17090b3e8c00b001f73792d336mr8325711pjb.0.1660214422056;
        Thu, 11 Aug 2022 03:40:22 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id h11-20020a17090aa88b00b001f4fb21c11asm3402986pjq.21.2022.08.11.03.40.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Aug 2022 03:40:21 -0700 (PDT)
Date: Thu, 11 Aug 2022 19:40:15 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Imran Khan <imran.f.khan@oracle.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, vbabka@suse.cz, roman.gushchin@linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
Message-ID: <YvTcj37kS5xmNWCH@hyeyoo>
References: <20220811085938.2506536-1-imran.f.khan@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220811085938.2506536-1-imran.f.khan@oracle.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=iUXron1L;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::635
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

On Thu, Aug 11, 2022 at 06:59:38PM +1000, Imran Khan wrote:
> By default kfence allocation can happen for any slab object, whose size
> is up to PAGE_SIZE, as long as that allocation is the first allocation
> after expiration of kfence sample interval. But in certain debugging
> scenarios we may be interested in debugging corruptions involving
> some specific slub objects like dentry or ext4_* etc. In such cases
> limiting kfence for allocations involving only specific slub objects
> will increase the probablity of catching the issue since kfence pool
> will not be consumed by other slab objects.
> 
> This patch introduces a sysfs interface '/sys/kernel/slab/<name>/skip_kfence'
> to disable kfence for specific slabs. Having the interface work in this
> way does not impact current/default behavior of kfence and allows us to
> use kfence for specific slabs (when needed) as well. The decision to
> skip/use kfence is taken depending on whether kmem_cache.flags has
> (newly introduced) SLAB_SKIP_KFENCE flag set or not.
> 
> Signed-off-by: Imran Khan <imran.f.khan@oracle.com>
> ---
> 
> Changes since v1:
>  - Remove RFC tag
> 
>  include/linux/slab.h |  6 ++++++
>  mm/kfence/core.c     |  7 +++++++
>  mm/slub.c            | 27 +++++++++++++++++++++++++++
>  3 files changed, 40 insertions(+)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 0fefdf528e0d..947d912fd08c 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -119,6 +119,12 @@
>   */
>  #define SLAB_NO_USER_FLAGS	((slab_flags_t __force)0x10000000U)
>  
> +#ifdef CONFIG_KFENCE
> +#define SLAB_SKIP_KFENCE            ((slab_flags_t __force)0x20000000U)
> +#else
> +#define SLAB_SKIP_KFENCE            0
> +#endif
> +
>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c252081b11df..8c08ae2101d7 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -1003,6 +1003,13 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  		return NULL;
>  	}
>  
> +	/*
> +	 * Skip allocations for this slab, if KFENCE has been disabled for
> +	 * this slab.
> +	 */
> +	if (s->flags & SLAB_SKIP_KFENCE)
> +		return NULL;
> +
>  	if (atomic_inc_return(&kfence_allocation_gate) > 1)
>  		return NULL;
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
> diff --git a/mm/slub.c b/mm/slub.c
> index 862dbd9af4f5..ee8b48327536 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5745,6 +5745,30 @@ STAT_ATTR(CPU_PARTIAL_NODE, cpu_partial_node);
>  STAT_ATTR(CPU_PARTIAL_DRAIN, cpu_partial_drain);
>  #endif	/* CONFIG_SLUB_STATS */
>  
> +#ifdef CONFIG_KFENCE
> +static ssize_t skip_kfence_show(struct kmem_cache *s, char *buf)
> +{
> +	return sysfs_emit(buf, "%d\n", !!(s->flags & SLAB_SKIP_KFENCE));
> +}
> +
> +static ssize_t skip_kfence_store(struct kmem_cache *s,
> +			const char *buf, size_t length)
> +{
> +	int ret = length;
> +
> +	if (buf[0] == '0')
> +		s->flags &= ~SLAB_SKIP_KFENCE;
> +	else if (buf[0] == '1')
> +		s->flags |= SLAB_SKIP_KFENCE;
> +	else
> +		ret = -EINVAL;
> +
> +	return ret;
> +}
> +SLAB_ATTR(skip_kfence);
> +
> +#endif
> +
>  static struct attribute *slab_attrs[] = {
>  	&slab_size_attr.attr,
>  	&object_size_attr.attr,
> @@ -5812,6 +5836,9 @@ static struct attribute *slab_attrs[] = {
>  	&failslab_attr.attr,
>  #endif
>  	&usersize_attr.attr,
> +#ifdef CONFIG_KFENCE
> +	&skip_kfence_attr.attr,
> +#endif
>  
>  	NULL
>  };
> 
> base-commit: 40d43a7507e1547dd45cb02af2e40d897c591870
> -- 
> 2.30.2

No strong opinion on its interface, but from view of correctness:

Looks good to me.
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YvTcj37kS5xmNWCH%40hyeyoo.
