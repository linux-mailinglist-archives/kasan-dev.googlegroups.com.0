Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE63WD6QKGQERELWPSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 455DD2AF7E8
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:29:40 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id v5sf894034wrr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:29:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605119380; cv=pass;
        d=google.com; s=arc-20160816;
        b=h/fu+pHrY0jexUKdRqV+ljM+5Id1XzzkjbtxO8OzP1IKjmFUsYv4/qyaEmTlsBY7gV
         1DLRrSRCIVPRMESTj6e294JbbdobnUY27yJDIR6LGeNEmWOgLifMjUTn0+yJ51C8W5i0
         8s5ZQbW0OIWi/q/LoxbWnxbX0ukOYq1m4fh8RQs4b0K+n2LCL/MAkQ3u0Fi7kiLIcnNc
         /W16pBQrbOM6BqaqtS6CKmHsUYGnWcy/tXY7s4PG4z/tHnsu3dJD/8Z6Jpas837a3wKO
         dehvFLxLevBjZYP/Hd9lQmZwmpusucfktMs/6Wfuif06u+vAn0z97O47gmValrsLCprf
         dlWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=G22K7VBv/ZsTTPYLylI8JR5B0steS42xXrT4W8r/qsg=;
        b=hh6pNMJQYfsg7RU/sPVbRjeawcnXUicsq1SV9B59d3zbVaAVwyW7eEZ0z0DwSfOddq
         p9jfTmXU6f0ldXrNEsjGbVwaihZOUMJ5BqqCMlstxCnmGMuhI15y75hd4yuo6on4Rtd4
         DDqkwbGQ5v2B+X6kXyoyh9TAC97KR/OZ5g9JaKdvmjB/8ujJ5q+OohbebHRX4hzitDxJ
         QuLdo06Cpca9V8xkWooOD2YcUEB67CvxJ/vKCE5M4pwv+WeAkcDK5MKRnlGuj6TFSq7i
         k6SLq5NMsZ9195IDXT4WWylGEd+E+ORN5s84NEgcsA12DLPmll9LW4Y1zimgVJgtDbnB
         W5Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eUBuV6ws;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=G22K7VBv/ZsTTPYLylI8JR5B0steS42xXrT4W8r/qsg=;
        b=LiHibqFlpjoZGw3RS92MmBROs4m+4znHsZCixDwMKYi5TLFeT1GI7zL98o5wtUmL7O
         WI2BcSLQq1lj5kxGByLweeoI1jkfS98WPG7pQh0unSKh6Dlp0npLI80tGYl/o1yowlzx
         tfE//2PwjEQwmk9kgsvpj2qMdDgNjT/F/7fOSi9HBxF1u6STok3MY2+cB+2TqRrLtRYz
         rmOwYtEr61Mu00YpaZYhEoVFbydNMHZeacizLTVxzlbPbW/VoC6spoRTv0hdWCyq8Bsv
         UkRkNJCW3I/KxgsabC8UvEwFM2bnEMZT4BLHLxKgNNunUewWXnJHZECkGTIYhtLoIoMe
         r9cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G22K7VBv/ZsTTPYLylI8JR5B0steS42xXrT4W8r/qsg=;
        b=BZn0wpr9DMgOMoVGI3rAx4KYLZpaYofOOOZC+b63GQhAABsvy44XfFDjLY87id4/kf
         vOgeN4Hed78DVPOiiKuMD7N4uYXClV9Zbu1Kfo+mtAqBJhlmktvs1JEpkwKC4DHylaXJ
         RCA+aJJ1mf3513Jr9q9/nE1ZCrYuobzAFzMV62ptDd2pSNWkxZ356tel5Cg51f9fFCsC
         2YL/oXEOwE7ReuXCH8Hn+awzbPlfUwJK292dzfFzZLSTvAc6flYYzo9XVAn6w3ZW3Qzv
         fZsM3q2eDZ/7YDJUEBEKqnjZzJgMzBIwBFZCEnFKa4LfWYbahAC7gd6lNbSV6l9gyiaG
         p3lQ==
X-Gm-Message-State: AOAM533tzdP6lNEQ3LWcHebtqxpfdJVgyWPhppnseTOHuY4DAO76klbR
	T5ibgdQPFTT2uQS0WmYKFYc=
X-Google-Smtp-Source: ABdhPJwkEVecrG9WL9sHYaEn7WX2STd4mVZRu4RNnWJ+7rc+C38GxlFOqIlsP/MnW6WON5/6SfKG5A==
X-Received: by 2002:a05:600c:22c5:: with SMTP id 5mr5574193wmg.25.1605119380014;
        Wed, 11 Nov 2020 10:29:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls78769wma.3.gmail; Wed, 11 Nov
 2020 10:29:39 -0800 (PST)
X-Received: by 2002:a7b:c385:: with SMTP id s5mr5390272wmj.155.1605119378951;
        Wed, 11 Nov 2020 10:29:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605119378; cv=none;
        d=google.com; s=arc-20160816;
        b=MpCl9TC7F3rcQjJ3Qkwvmptz+FwrIW/YvNKJaOBPkCaypHuHQPI1PNSmI2XNuBizby
         its05Fu+PjDTpZzn3w/eBHX5afRWh/26XtOvNjXfWrc9Siv0sdPRRusjYxzLVpkKFupe
         eB4tjI2AD/0kLV5DwiGbPtAPkKbLhNxP6u8ym+w17xljRFHgcUEeSnZ5iZqbZMXePq83
         8h1UBA8FGPMYtwRNAmpk9AKhf1pWsD6twDz1cr3GL/JbpPEXAmsIjqJuqZrewgjz5BUj
         U8L/OkAvOedOsi3j6Mi81x0fzY3vb7n7VlSGl+vnRxIbR8pnK3P7vE9gF9qZELmMy7jD
         oHwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=gkKctNxP2ohF55zVwpehmRMz8y0vnC/mVPskztCYL/A=;
        b=gleMGa4EqIsjpOob1ufe8I+ymmtEKpT0M+2lXaUTmaQl5zlN3P6xW1ZJW5pOquZgFU
         ekt+YNLCvbg83gau+Y0oX5ZQMfMO+pg/UkiNfsOdCzKKTGjkFC7VEVmH2gL4wpAb2G5j
         TLVJlPLqAURJ1trlX85ZftbsuM+eLnJrHrb5Lqa39aE0T2ORYUWm0YDZpqmTawUOD5jB
         MRujMpkHDWGx51/k1EfHn7MG/zlw9kGBbRlcNOK/M8LIPQ2dZr3n8oE1TyNbii3t8mxd
         w/TpJ5/HHNsVV/ScpNWiTXI0YUhCEHHoG8q/caJz0nUBdwVs/n+AT2HXdm0FJhI15bTy
         08LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eUBuV6ws;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id v10si91869wrr.3.2020.11.11.10.29.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:29:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id j7so3508217wrp.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:29:38 -0800 (PST)
X-Received: by 2002:a5d:518e:: with SMTP id k14mr34061180wrv.60.1605119378323;
        Wed, 11 Nov 2020 10:29:38 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id v19sm3612388wrf.40.2020.11.11.10.29.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 10:29:37 -0800 (PST)
Date: Wed, 11 Nov 2020 19:29:31 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
Message-ID: <20201111182931.GM517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eUBuV6ws;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, 'Andrey Konovalov' via kasan-dev wrote:
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
> ---
>  mm/kasan/common.c  |  22 +++++--
>  mm/kasan/hw_tags.c | 152 +++++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h   |  16 +++++
>  mm/kasan/report.c  |  14 ++++-
>  4 files changed, 197 insertions(+), 7 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 4598c1364f19..efad5ed6a3bd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -129,6 +129,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
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
> @@ -165,6 +170,8 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  
>  size_t kasan_metadata_size(struct kmem_cache *cache)
>  {
> +	if (!kasan_stack_collection_enabled())
> +		return 0;
>  	return (cache->kasan_info.alloc_meta_offset ?
>  		sizeof(struct kasan_alloc_meta) : 0) +
>  		(cache->kasan_info.free_meta_offset ?
> @@ -267,11 +274,13 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
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
> @@ -308,6 +317,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
>  	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
>  
> +	if (!kasan_stack_collection_enabled())
> +		return false;
> +
>  	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
>  			unlikely(!(cache->flags & SLAB_KASAN)))
>  		return false;
> @@ -355,7 +367,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
>  		KASAN_KMALLOC_REDZONE);
>  
> -	if (cache->flags & SLAB_KASAN)
> +	if (kasan_stack_collection_enabled() && (cache->flags & SLAB_KASAN))
>  		set_alloc_info(cache, (void *)object, flags);
>  
>  	return set_tag(object, tag);
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 838b29e44e32..2f6f0261af8c 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -8,6 +8,8 @@
>  
>  #define pr_fmt(fmt) "kasan: " fmt
>  
> +#include <linux/init.h>
> +#include <linux/jump_label.h>

This should include <linux/static_key.h> -- although the rest of the
kernel seems to also inconsistently use on or the other. Since the name,
as referred to also by macros are "static keys", perhaps the
static_key.h header is more appropriate...

>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
>  #include <linux/memory.h>
> @@ -17,9 +19,104 @@
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

It seems KASAN_ARG_STACKTRACE_DEFAULT is never used explicitly. Could
the switch statements just be changed to not have a 'default' but
instead refer to *DEFAULT where appropriate?

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
> @@ -27,6 +124,61 @@ void kasan_init_hw_tags_cpu(void)
>  /* kasan_init_hw_tags() is called once on boot CPU. */
>  void kasan_init_hw_tags(void)

Is this an __init function, since it sets __ro_after_init vars?

>  {
> +	/* If hardware doesn't support MTE, do nothing. */
> +	if (!system_supports_mte())
> +		return;
> +
> +	/* If KASAN is disabled, do nothing. */
> +	if (kasan_arg_mode == KASAN_ARG_MODE_OFF)
> +		return;

This is checked twice, once here and the in the switch. I think remove
the one here ^^^.

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
> +	case KASAN_ARG_MODE_OFF:
> +		return;
> +	case KASAN_ARG_MODE_PROD:
> +		static_branch_enable(&kasan_flag_enabled);
> +		break;
> +	case KASAN_ARG_MODE_FULL:
> +		static_branch_enable(&kasan_flag_enabled);
> +		static_branch_enable(&kasan_flag_stacktrace);
> +		break;
> +	default:

I'd suggest removing the 'default' cases in all the switches, so that we
get warnings in case we add new options and they aren't handled.

Here, having KASAN_ARG_MODE_DEFAULT is probably redundant, but so is
'default' ;-)

> +		break;
> +	}
> +
> +	/* Now, optionally override the presets. */
> +
> +	switch (kasan_arg_stacktrace) {
> +	case KASAN_ARG_STACKTRACE_OFF:
> +		static_branch_disable(&kasan_flag_stacktrace);
> +		break;
> +	case KASAN_ARG_STACKTRACE_ON:
> +		static_branch_enable(&kasan_flag_stacktrace);
> +		break;
> +	default:
> +		break;
> +	}
> +
> +	switch (kasan_arg_fault) {
> +	case KASAN_ARG_FAULT_REPORT:
> +		kasan_flag_panic = false;
> +		break;
> +	case KASAN_ARG_FAULT_PANIC:
> +		kasan_flag_panic = true;
> +		break;
> +	default:
> +		break;
> +	}
> +

Would be good to get rid of the 'default' cases here.

>  	pr_info("KernelAddressSanitizer initialized\n");
>  }
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 2d3c99125996..5eff3d9f624e 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -5,6 +5,22 @@
>  #include <linux/kasan.h>
>  #include <linux/stackdepot.h>
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#include <linux/jump_label.h>
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
> index 25ca66c99e48..7d86af340148 100644
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111182931.GM517454%40elver.google.com.
