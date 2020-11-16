Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VOZL6QKGQE6ZD4J2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 00E1A2B48EC
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 16:15:11 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id nt22sf7729438ejb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:15:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605539710; cv=pass;
        d=google.com; s=arc-20160816;
        b=UKxaTgZZduT5a7dyEPKwA7T42tYdCqUSGAfhZRQriFMtPYLqXJcqhunnptrzNimqHO
         WFm1naVBvJtMLkoqjJ1YIyiA6sNUBaT/DONT5LcyU5I0ygDaE5wrFtQMPd63v/ppjLFJ
         wWDC/4UGWESaqzbU/CKwQ02nrD7UUPg81eX8TmqQSc7sLd/zGALbZfCBzL0vDGjTmqAm
         hq8e/VK1AZgqAzqsuMvSWtTFC2oO8nBWT1S7MxgftPJcecDlKY9/usZJvaHRgSKlkVLT
         +W0K9h2x2/LG/BDp/sQFy0lXhKQzzhRb7cWkhZ43Z0xrqhG8FtdOpxyFZnbFlAV+Imc5
         7gmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=7awRaY9bxLLQ5ER/MrLfdSE2G70trH/a0r7Lc3PZ3DE=;
        b=htCoqPNO+jjSmMlmZshB9yvRKMX8De9dTIO7wudgikWi357YJLlf5AtZZacmm6Zo/B
         JWIBNocJIoAbQDPHIewzdGPyyE4K/V3N3h3lWyaxzXqK9Swz53UdqBEsY4Zssv/Y0Jbc
         FHE6QUyOLtowhJUX1GK8oDv9JlJU/aW+p8lssZ1kj1zoofNlFzyS//gpwf5Dhud28vGc
         3n8uSuJR64J4CeW/LJzPsK14nAlPMS82tLQ44T+6qdQ5d2W75fkPB0pKLVQdEIK5b9eN
         dGQAbmja2a4+H6pCKIWq8iLowp/LMziMbLUAan8qqwdAk49vjBwJ7YYEsV+PkIjuumbL
         IhCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XyBmRmKW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7awRaY9bxLLQ5ER/MrLfdSE2G70trH/a0r7Lc3PZ3DE=;
        b=rvnIk/IP1WfVv3S+U89RYJa0sGsUm/6zCiur1G17txnGhxXp/xxSU0skBueg+cXOMv
         eZQ6IV2wN65NOR6zgJ8wSmqQ/tMcjGeH6DuxA9Q5Cs5VKt8QastZJFhhjUMM4SjVahlL
         v88dCrp2+8XLvMNV3oKj1LhCAaNSM9gk9kRPmitivKY2eqPkQ4cEiW27Q9txqpJxfhAf
         3DQ9Wh+GyONwWEKHwsPulw6+FwIyuzfce97odnHQZpcx/C8OsrolyHgeez7WzLQWyHju
         7W2zLUzhrVfUTuJkq4I+jtRE/XmJ226+/+SQS4UmM3s1psWia1b9wqq/nuXodzMIzENQ
         N9sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7awRaY9bxLLQ5ER/MrLfdSE2G70trH/a0r7Lc3PZ3DE=;
        b=ntfuPN48Oyy0svACJDqf+ETSy3SN9Qjpobr0jO673TsHNY3BWRKSSaVqASMLAEFWa0
         VGWT98C4xSOnRXeQH4v6CZcReTxefLq96kMfn7JN9UGslNPzTBwF01n+pQ/7yF3pL5HZ
         L/h064X2B9gUm8wFD5px2MBq7isQxByKjJWBJcNMPHOe0y8oADL0/kJ4SqCq8vWe1bFp
         MeMWidQGBXN/URIM1Eak2xzlvp7IL6y0JZbk8yAIvVPDgW5LRYkNhiQyhyp/c+aL9y8t
         rp2JcBoVTvtAXvu+cwTB9d+O6gb+i8JTbfGALc4/8m5tTW1UMb9OKmTMWVlZPHj58ZoR
         bfNw==
X-Gm-Message-State: AOAM533RRWbPofTzE1RWLVS/hRkiRS7kM75ED06BONeLPROVzLpoWLRz
	Wwgzm7q6k937qvBreNgSqlY=
X-Google-Smtp-Source: ABdhPJwQDCM/+XvPnbZQ5wJqP65ApR9yHFR24aHa538uHtDUX4e1XXX5SqgvXT9x5+klGpD7rh7lVA==
X-Received: by 2002:a17:906:cc8c:: with SMTP id oq12mr16028628ejb.177.1605539710700;
        Mon, 16 Nov 2020 07:15:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1743:: with SMTP id v3ls4397732edx.2.gmail; Mon, 16
 Nov 2020 07:15:09 -0800 (PST)
X-Received: by 2002:a50:d784:: with SMTP id w4mr16433840edi.201.1605539709611;
        Mon, 16 Nov 2020 07:15:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605539709; cv=none;
        d=google.com; s=arc-20160816;
        b=goW/rBtjM/vdBfrmIv1vpFYy3zdu5gZBzI3Xq8XXXBJ82InfZZ9NzZpoGA6YLi1HOK
         GsWD9B7bCgBJBcUYHy+unv4/So7amDvLi0JrzNnbwRm1MUevrokFCNvYY1dLP12Q/MZX
         PXaYRdDADOzrQFZZc3/3EnMchw142YJRwCQqiwLzUMCZysNdx3ziqOLvRHZvp/x/iI33
         elToti2lZqJOCMXaI8K5OSyMpaZyXpTAKB/4M58zBuPOzuQcIV5F/lnVpkJuRA5PWK+B
         O8pBgxFjqnZ11jzJMqv0fppxhHvGBQuW1UqIb0Pk92MfEH8z8T/DEIr//3qApXq9oh/Y
         Y/QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tZbF54K8tolVCl75FRWFPLUDutXX6oQr5R1sT2PK7H4=;
        b=dAOhWVmIN1Ipy3ci8QX2HRvXKBYfZPCLaEfsaNTZxRvCEwZHPYkxAQZHLr0RtuDzyR
         Hxu21CwzLJlabJRLWUMRIREdu+9JtaBh6oITA+eCXazq9Vq49tpvLpTrC06O2eUN2Z78
         3Wb4fEF4lSy9kGgw2ZOXzKDhNNHsz0T4tJB2DQ+a9qPfwkSa462U/aWqdgwLWiLkRaoC
         GGn/V81ZmyvuwE2Kz3XNW71kQuBRbr1OQa8tr3UvHLLAA8HtQfO6SYet64Hs+BrGqLMi
         cpwFr30CITmaEoKWN7o0xvl1A7Xzc7IHoRSslzL0oKEZhmRbuHwqldVTLLRMoPSHOOT6
         nZfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XyBmRmKW;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id bm8si606362edb.2.2020.11.16.07.15.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 07:15:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id h2so24078879wmm.0
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 07:15:09 -0800 (PST)
X-Received: by 2002:a1c:544c:: with SMTP id p12mr5744356wmi.146.1605539709052;
        Mon, 16 Nov 2020 07:15:09 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id i10sm23358160wrs.22.2020.11.16.07.15.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Nov 2020 07:15:08 -0800 (PST)
Date: Mon, 16 Nov 2020 16:15:01 +0100
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
Subject: Re: [PATCH mm v3 11/19] kasan: add and integrate kasan boot
 parameters
Message-ID: <20201116151501.GC1357314@elver.google.com>
References: <cover.1605305978.git.andreyknvl@google.com>
 <deb1af093f19c8848346682245513af059626412.1605305978.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <deb1af093f19c8848346682245513af059626412.1605305978.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XyBmRmKW;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
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
> Hardware tag-based KASAN mode is intended to eventually be used in
> production as a security mitigation. Therefore there's a need for finer
> control over KASAN features and for an existence of a kill switch.
> 
> This change adds a few boot parameters for hardware tag-based KASAN that
> allow to disable or otherwise control particular KASAN features.
> 
> The features that can be controlled are:
> 
> 1. Whether KASAN is enabled at all.
> 2. Whether KASAN collects and saves alloc/free stacks.
> 3. Whether KASAN panics on a detected bug or not.
> 
> With this change a new boot parameter kasan.mode allows to choose one of
> three main modes:
> 
> - kasan.mode=off - KASAN is disabled, no tag checks are performed
> - kasan.mode=prod - only essential production features are enabled
> - kasan.mode=full - all KASAN features are enabled
> 
> The chosen mode provides default control values for the features mentioned
> above. However it's also possible to override the default values by
> providing:
> 
> - kasan.stacktrace=off/on - enable alloc/free stack collection
>                             (default: on for mode=full, otherwise off)
> - kasan.fault=report/panic - only report tag fault or also panic
>                              (default: report)
> 
> If kasan.mode parameter is not provided, it defaults to full when
> CONFIG_DEBUG_KERNEL is enabled, and to prod otherwise.
> 
> It is essential that switching between these modes doesn't require
> rebuilding the kernel with different configs, as this is required by
> the Android GKI (Generic Kernel Image) initiative [1].
> 
> [1] https://source.android.com/devices/architecture/kernel/generic-kernel-image
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/common.c  |  22 +++++--
>  mm/kasan/hw_tags.c | 151 +++++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h   |  16 +++++
>  mm/kasan/report.c  |  14 ++++-
>  4 files changed, 196 insertions(+), 7 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1ac4f435c679..a11e3e75eb08 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -135,6 +135,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  	unsigned int redzone_size;
>  	int redzone_adjust;
>  
> +	if (!kasan_stack_collection_enabled()) {
> +		*flags |= SLAB_KASAN;
> +		return;
> +	}
> +
>  	/* Add alloc meta. */
>  	cache->kasan_info.alloc_meta_offset = *size;
>  	*size += sizeof(struct kasan_alloc_meta);
> @@ -171,6 +176,8 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  
>  size_t kasan_metadata_size(struct kmem_cache *cache)
>  {
> +	if (!kasan_stack_collection_enabled())
> +		return 0;
>  	return (cache->kasan_info.alloc_meta_offset ?
>  		sizeof(struct kasan_alloc_meta) : 0) +
>  		(cache->kasan_info.free_meta_offset ?
> @@ -263,11 +270,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
>  {
>  	struct kasan_alloc_meta *alloc_meta;
>  
> -	if (!(cache->flags & SLAB_KASAN))
> -		return (void *)object;
> +	if (kasan_stack_collection_enabled()) {
> +		if (!(cache->flags & SLAB_KASAN))
> +			return (void *)object;
>  
> -	alloc_meta = kasan_get_alloc_meta(cache, object);
> -	__memset(alloc_meta, 0, sizeof(*alloc_meta));
> +		alloc_meta = kasan_get_alloc_meta(cache, object);
> +		__memset(alloc_meta, 0, sizeof(*alloc_meta));
> +	}
>  
>  	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>  		object = set_tag(object, assign_tag(cache, object, true, false));
> @@ -307,6 +316,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
>  	poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
>  
> +	if (!kasan_stack_collection_enabled())
> +		return false;
> +
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
>  			unlikely(!(cache->flags & SLAB_KASAN)))
>  		return false;
> @@ -357,7 +369,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	poison_range((void *)redzone_start, redzone_end - redzone_start,
>  		     KASAN_KMALLOC_REDZONE);
>  
> -	if (cache->flags & SLAB_KASAN)
> +	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
>  		set_alloc_info(cache, (void *)object, flags);
>  
>  	return set_tag(object, tag);
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 863fed4edd3f..30ce88935e9d 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -8,18 +8,115 @@
>  
>  #define pr_fmt(fmt) "kasan: " fmt
>  
> +#include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
>  #include <linux/memory.h>
>  #include <linux/mm.h>
> +#include <linux/static_key.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
>  
>  #include "kasan.h"
>  
> +enum kasan_arg_mode {
> +	KASAN_ARG_MODE_DEFAULT,
> +	KASAN_ARG_MODE_OFF,
> +	KASAN_ARG_MODE_PROD,
> +	KASAN_ARG_MODE_FULL,
> +};
> +
> +enum kasan_arg_stacktrace {
> +	KASAN_ARG_STACKTRACE_DEFAULT,
> +	KASAN_ARG_STACKTRACE_OFF,
> +	KASAN_ARG_STACKTRACE_ON,
> +};
> +
> +enum kasan_arg_fault {
> +	KASAN_ARG_FAULT_DEFAULT,
> +	KASAN_ARG_FAULT_REPORT,
> +	KASAN_ARG_FAULT_PANIC,
> +};
> +
> +static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> +static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
> +static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> +
> +/* Whether KASAN is enabled at all. */
> +DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
> +EXPORT_SYMBOL(kasan_flag_enabled);
> +
> +/* Whether to collect alloc/free stack traces. */
> +DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_stacktrace);
> +
> +/* Whether panic or disable tag checking on fault. */
> +bool kasan_flag_panic __ro_after_init;
> +
> +/* kasan.mode=off/prod/full */
> +static int __init early_kasan_mode(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "off"))
> +		kasan_arg_mode = KASAN_ARG_MODE_OFF;
> +	else if (!strcmp(arg, "prod"))
> +		kasan_arg_mode = KASAN_ARG_MODE_PROD;
> +	else if (!strcmp(arg, "full"))
> +		kasan_arg_mode = KASAN_ARG_MODE_FULL;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kasan.mode", early_kasan_mode);
> +
> +/* kasan.stack=off/on */
> +static int __init early_kasan_flag_stacktrace(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "off"))
> +		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
> +	else if (!strcmp(arg, "on"))
> +		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
> +
> +/* kasan.fault=report/panic */
> +static int __init early_kasan_fault(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "report"))
> +		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> +	else if (!strcmp(arg, "panic"))
> +		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kasan.fault", early_kasan_fault);
> +
>  /* kasan_init_hw_tags_cpu() is called for each CPU. */
>  void kasan_init_hw_tags_cpu(void)
>  {
> +	/*
> +	 * There's no need to check that the hardware is MTE-capable here,
> +	 * as this function is only called for MTE-capable hardware.
> +	 */
> +
> +	/* If KASAN is disabled, do nothing. */
> +	if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
> +		return;
> +
>  	hw_init_tags(KASAN_TAG_MAX);
>  	hw_enable_tagging();
>  }
> @@ -27,6 +124,60 @@ void kasan_init_hw_tags_cpu(void)
>  /* kasan_init_hw_tags() is called once on boot CPU. */
>  void __init kasan_init_hw_tags(void)
>  {
> +	/* If hardware doesn't support MTE, do nothing. */
> +	if (!system_supports_mte())
> +		return;
> +
> +	/* Choose KASAN mode if kasan boot parameter is not provided. */
> +	if (kasan_arg_mode == KASAN_ARG_MODE_DEFAULT) {
> +		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> +			kasan_arg_mode = KASAN_ARG_MODE_FULL;
> +		else
> +			kasan_arg_mode = KASAN_ARG_MODE_PROD;
> +	}
> +
> +	/* Preset parameter values based on the mode. */
> +	switch (kasan_arg_mode) {
> +	case KASAN_ARG_MODE_DEFAULT:
> +		/* Shouldn't happen as per the check above. */
> +		WARN_ON(1);
> +		return;
> +	case KASAN_ARG_MODE_OFF:
> +		/* If KASAN is disabled, do nothing. */
> +		return;
> +	case KASAN_ARG_MODE_PROD:
> +		static_branch_enable(&kasan_flag_enabled);
> +		break;
> +	case KASAN_ARG_MODE_FULL:
> +		static_branch_enable(&kasan_flag_enabled);
> +		static_branch_enable(&kasan_flag_stacktrace);
> +		break;
> +	}
> +
> +	/* Now, optionally override the presets. */
> +
> +	switch (kasan_arg_stacktrace) {
> +	case KASAN_ARG_STACKTRACE_DEFAULT:
> +		break;
> +	case KASAN_ARG_STACKTRACE_OFF:
> +		static_branch_disable(&kasan_flag_stacktrace);
> +		break;
> +	case KASAN_ARG_STACKTRACE_ON:
> +		static_branch_enable(&kasan_flag_stacktrace);
> +		break;
> +	}
> +
> +	switch (kasan_arg_fault) {
> +	case KASAN_ARG_FAULT_DEFAULT:
> +		break;
> +	case KASAN_ARG_FAULT_REPORT:
> +		kasan_flag_panic = false;
> +		break;
> +	case KASAN_ARG_FAULT_PANIC:
> +		kasan_flag_panic = true;
> +		break;
> +	}
> +
>  	pr_info("KernelAddressSanitizer initialized\n");
>  }
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8aa83b7ad79e..d01a5ac34f70 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -6,6 +6,22 @@
>  #include <linux/kfence.h>
>  #include <linux/stackdepot.h>
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#include <linux/static_key.h>
> +DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
> +static inline bool kasan_stack_collection_enabled(void)
> +{
> +	return static_branch_unlikely(&kasan_flag_stacktrace);
> +}
> +#else
> +static inline bool kasan_stack_collection_enabled(void)
> +{
> +	return true;
> +}
> +#endif
> +
> +extern bool kasan_flag_panic __ro_after_init;
> +
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
>  #else
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 76a0e3ae2049..ffa6076b1710 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -99,6 +99,10 @@ static void end_report(unsigned long *flags)
>  		panic_on_warn = 0;
>  		panic("panic_on_warn set ...\n");
>  	}
> +#ifdef CONFIG_KASAN_HW_TAGS
> +	if (kasan_flag_panic)
> +		panic("kasan.fault=panic set ...\n");
> +#endif
>  	kasan_enable_current();
>  }
>  
> @@ -161,8 +165,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>  		(void *)(object_addr + cache->object_size));
>  }
>  
> -static void describe_object(struct kmem_cache *cache, void *object,
> -				const void *addr, u8 tag)
> +static void describe_object_stacks(struct kmem_cache *cache, void *object,
> +					const void *addr, u8 tag)
>  {
>  	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
>  
> @@ -190,7 +194,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
>  		}
>  #endif
>  	}
> +}
>  
> +static void describe_object(struct kmem_cache *cache, void *object,
> +				const void *addr, u8 tag)
> +{
> +	if (kasan_stack_collection_enabled())
> +		describe_object_stacks(cache, object, addr, tag);
>  	describe_object_addr(cache, object, addr);
>  }
>  
> -- 
> 2.29.2.299.gdc1121823c-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201116151501.GC1357314%40elver.google.com.
