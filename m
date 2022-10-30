Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFGR66NAMGQECUOGNXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id F1CEF6126F8
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Oct 2022 03:59:33 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id s1-20020a197701000000b004a2aebd8b14sf2589361lfc.21
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Oct 2022 19:59:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667098773; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pk7vgPZQyWzyHqywYJY4qg5WjFmMNvO4y+/MAxR1eA0AhOJ9k9ffUiZhOyqEK+kITI
         7uVf0/97hU1oXALzbVy7jocAYfkKIZQufFrW7/YEtEjtnBKmhJWgU/iCowzsOSqswtNn
         OgQuRvszIa2Ym0NOwvIKv5gqoD8Go02Qb0NCMtx6LnwjrjOPHgtmehRzl9iGL52SPLsJ
         VPRfZhXHcd62g3DzfW6twMd+tkBM45F2SwBiX7CQgUq4sktBpUp5xqAVMovaD2hJ+DJo
         plbc3ktvcf7ms1oqyCdUF/55HVI1f34/R1loAeNgweU6p1lKyZmXtgOq3x1FG1cYCe+X
         hxag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=N+vFyjl3xz6t82g5c0MEvpE6Q/UMxbO1NeJBJtc3Pr4=;
        b=XsgRij5cxza4NN8Ev0+OdVVuqP2aq5Zs+pNGa1QMuT304HCqEi/GlS1mExGKDMnUSp
         FB3kgsWk0Hw3VrbPlcd3OV3807e/UfkH2gfAJqeGMohZa0MHrg8ijN18WPYhPnGfY2b0
         0Bep6A92l/Nq7Qt/KPaVpn8cJpE2B6c/LSnFDc7mpn78pjqS2br31R/WrX+2t9hzOXWL
         KAIMeehixKw+H+NTbLEfKavA/R1fWhpvj5vTljGfQK56rAYv9lspo8damzxeM2jK9/is
         URHAqiM7bWUi0iitoL3S9tJuhRC0Z/vqXcf7U3GXZNwwvu58syhW3B8VmseHcww2D8nT
         vX0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qQ6rDtl8;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=N+vFyjl3xz6t82g5c0MEvpE6Q/UMxbO1NeJBJtc3Pr4=;
        b=JiLWcieIsBfQdG/5/7qRoFb3hL8MNL9qIUVq8/iNOrRTcpxrsPsHcKb6p2cMGxNJBQ
         m1vB34Wvt13tVB+28aaIIQdONr31gBt5QLcEwjx2cMEyombgikBrYbKxsoeWTeuMnv8Y
         vl1WMfhfHfdaPMItzW0JlK6OUDJJoUjnluVU7JNUdX2E6vsxMDROBPaRF+GBANVCWFZ0
         RpWOAao7dFRYg7K2s5m9GYebz2K494QzU1KrFzxir72r3e6Pz356osbRjH9DpwQygLK6
         VbjlVHWHz09pE7uU8Chk17rVoSWAJBNYgBSZjIh9SO8Dt+ErYbBc8kblBLbK5uYKFhZi
         dU7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N+vFyjl3xz6t82g5c0MEvpE6Q/UMxbO1NeJBJtc3Pr4=;
        b=FIj0hEeBT9BO+Hxbh6zg0lyMiqegQ+QFrzAjj2NZMF581sD4JkzLB3mBpGIxzBlMXN
         9S65PUhCOyugena1obUlrjx8sQlEL9CzeMlS3tVrokudF+mlBcRwu6NhBrToZKRrcb2I
         9KyG7ZRRP7LEYkXt+4+hTLA0E+osX2bDu6WR7X/uWCRWd3Qj2+zZiY96ktNqAD05vkkj
         Eno1STVX0QgZXMFA9/ovUCZ24CUvu068OBWk2SVIEWqyDIFnGI1ypJGFRiiuArDZMeND
         hpwx3pWuwv/OgW10n7E4LdnuWYOy79QUE8on8XmOsB8vKDxQGhEOcR1TdSOT6jhuCndy
         pdPg==
X-Gm-Message-State: ACrzQf0yMlAmm1hFTiFLk53hb186jvqe3X9Suk06bTM5Ufl5kgei24Cp
	agkokVqXTK0cPayHtz2D0vw=
X-Google-Smtp-Source: AMsMyM7hB8fAsXwIeRMTpN3pR/eRqJi+hFPQ36IjW6w/2dF4naA3kpCNyvc5fcAnxu+lrp+J3et/1w==
X-Received: by 2002:a05:6512:3606:b0:4a2:71df:7938 with SMTP id f6-20020a056512360600b004a271df7938mr2705301lfs.279.1667098773050;
        Sat, 29 Oct 2022 19:59:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c8b:b0:277:22e9:929f with SMTP id
 bz11-20020a05651c0c8b00b0027722e9929fls1012087ljb.5.-pod-prod-gmail; Sat, 29
 Oct 2022 19:59:31 -0700 (PDT)
X-Received: by 2002:a2e:9c0c:0:b0:274:7384:fcd with SMTP id s12-20020a2e9c0c000000b0027473840fcdmr2929618lji.352.1667098771265;
        Sat, 29 Oct 2022 19:59:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667098771; cv=none;
        d=google.com; s=arc-20160816;
        b=ze0Rdtx7w2fMxcC20cMI/ZY4aihG0p90spBTTeI7Q2xXA9Md8HBSm5aCmVw2G2+3Ie
         FAMvnmK/wA+crwp971Zvch+0p85HlNtiqtCQqVhi8rtZJ7Eo1V4TD7mTe/Q9K23sZwjO
         OS1+DxU57fWcrdpRhFKOl144ojZdZbdtlvYQ61PdqQTammxvT6DXyUfaPk/i854Aeizv
         rbDI5mBuG2zjPPSRPfRWe8MaU1jO/Nt8KC+hP7H9YPye+kXwSEXF5KXkpR5bQ7XMnmwt
         6wR75hompPR9HjKrMrvqAb/JF3AzQn7spun0+JcD4SmWERo+Css0laYkwje0+8DpiS2c
         +G4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ViUX7nS+sMEeCyJpGqlawogkGghwNa0jyE1+CkQUpdc=;
        b=FMzokhkshzYwFt4gQ/qjS06WYsHvg638qZ4UnSrlGHIOgSY3ME/+mouzEofVvRcTV+
         chV0q8KzcgZjXYGIOQak6hmFFi7bhb+MrC3o/zLjfbO7Wxir+Tpuc1c4fMYG3Akeq2aF
         Dd+AJcuKgd5BIFsq3xfh+aHVyxkHyzPnPKQugpS8OyURdPg4uen4I9cgebtRbvNhL0e3
         TXaq2qig5o8hHot684jFGq05jl9on3swRyhxEz4dm6MIpXn23Oncyssa0r+4ag+uG8od
         Cfhsv3bhQUXQL2ttXjApeYXdBgFzMw2HW0ZHTCSVqIyFZNYs9d/ASNOZZEfa+/nLorzd
         5jtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qQ6rDtl8;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id s14-20020a056512214e00b004b069b33a43si83105lfr.3.2022.10.29.19.59.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 29 Oct 2022 19:59:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id y16so11407341wrt.12
        for <kasan-dev@googlegroups.com>; Sat, 29 Oct 2022 19:59:31 -0700 (PDT)
X-Received: by 2002:adf:d1c4:0:b0:230:7771:f618 with SMTP id b4-20020adfd1c4000000b002307771f618mr3541746wrd.203.1667098770552;
        Sat, 29 Oct 2022 19:59:30 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:a6f7:9df9:f4cc:97c1])
        by smtp.gmail.com with ESMTPSA id bi22-20020a05600c3d9600b003b31c560a0csm3240628wmb.12.2022.10.29.19.59.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 29 Oct 2022 19:59:29 -0700 (PDT)
Date: Sun, 30 Oct 2022 03:59:22 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH] kasan: allow sampling page_alloc allocations for HW_TAGS
Message-ID: <Y13oij+hiJgQ9BXj@elver.google.com>
References: <c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qQ6rDtl8;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::433 as
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

On Thu, Oct 27, 2022 at 10:10PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a new boot parameter called kasan.page_alloc.sample, which makes
> Hardware Tag-Based KASAN tag only every Nth page_alloc allocation.
> 
> As Hardware Tag-Based KASAN is intended to be used in production, its
> performance impact is crucial. As page_alloc allocations tend to be big,
> tagging and checking all such allocations introduces a significant
> slowdown in some testing scenarios. The new flag allows to alleviate
> that slowdown.
> 
> Enabling page_alloc sampling has a downside: KASAN will miss bad accesses
> to a page_alloc allocation that has not been tagged.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  Documentation/dev-tools/kasan.rst |  4 +++
>  include/linux/kasan.h             |  7 ++---
>  mm/kasan/common.c                 |  9 +++++--
>  mm/kasan/hw_tags.c                | 26 +++++++++++++++++++
>  mm/kasan/kasan.h                  | 15 +++++++++++
>  mm/page_alloc.c                   | 43 +++++++++++++++++++++----------
>  6 files changed, 85 insertions(+), 19 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 5c93ab915049..bd97301845ef 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -140,6 +140,10 @@ disabling KASAN altogether or controlling its features:
>  - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
>    allocations (default: ``on``).
>  
> +- ``kasan.page_alloc.sample=<sampling frequency>`` makes KASAN tag only

Frequency is number of samples per frame (unit time, or if used
non-temporally like here, population size).

[1] https://en.wikipedia.org/wiki/Systematic_sampling

You're using it as an interval, so I'd just replace uses of frequency
with "interval" appropriately here and elsewhere.

> +  every Nth page_alloc allocation, where N is the value of the parameter
> +  (default: ``1``).
> +
>  Error reports
>  ~~~~~~~~~~~~~
>  
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d811b3d7d2a1..d45d45dfd007 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -120,12 +120,13 @@ static __always_inline void kasan_poison_pages(struct page *page,
>  		__kasan_poison_pages(page, order, init);
>  }
>  
> -void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init);
> -static __always_inline void kasan_unpoison_pages(struct page *page,
> +bool __kasan_unpoison_pages(struct page *page, unsigned int order, bool init);
> +static __always_inline bool kasan_unpoison_pages(struct page *page,
>  						 unsigned int order, bool init)
>  {
>  	if (kasan_enabled())
> -		__kasan_unpoison_pages(page, order, init);
> +		return __kasan_unpoison_pages(page, order, init);
> +	return false;
>  }
>  
>  void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 833bf2cfd2a3..1f30080a7a4c 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -95,19 +95,24 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  }
>  #endif /* CONFIG_KASAN_STACK */
>  
> -void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
> +bool __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
>  {
>  	u8 tag;
>  	unsigned long i;
>  
>  	if (unlikely(PageHighMem(page)))
> -		return;
> +		return false;
> +
> +	if (!kasan_sample_page_alloc())
> +		return false;
>  
>  	tag = kasan_random_tag();
>  	kasan_unpoison(set_tag(page_address(page), tag),
>  		       PAGE_SIZE << order, init);
>  	for (i = 0; i < (1 << order); i++)
>  		page_kasan_tag_set(page + i, tag);
> +
> +	return true;
>  }
>  
>  void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index b22c4f461cb0..aa3b5a080297 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -59,6 +59,11 @@ EXPORT_SYMBOL_GPL(kasan_mode);
>  /* Whether to enable vmalloc tagging. */
>  DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
>  
> +/* Frequency of page_alloc allocation poisoning. */
> +unsigned long kasan_page_alloc_sample = 1;
> +
> +DEFINE_PER_CPU(unsigned long, kasan_page_alloc_count);
> +
>  /* kasan=off/on */
>  static int __init early_kasan_flag(char *arg)
>  {
> @@ -122,6 +127,27 @@ static inline const char *kasan_mode_info(void)
>  		return "sync";
>  }
>  
> +/* kasan.page_alloc.sample=<sampling frequency> */
> +static int __init early_kasan_flag_page_alloc_sample(char *arg)
> +{
> +	int rv;
> +
> +	if (!arg)
> +		return -EINVAL;
> +
> +	rv = kstrtoul(arg, 0, &kasan_page_alloc_sample);
> +	if (rv)
> +		return rv;
> +
> +	if (!kasan_page_alloc_sample) {
> +		kasan_page_alloc_sample = 1;
> +		return -EINVAL;
> +	}
> +
> +	return 0;
> +}
> +early_param("kasan.page_alloc.sample", early_kasan_flag_page_alloc_sample);
> +
>  /*
>   * kasan_init_hw_tags_cpu() is called for each CPU.
>   * Not marked as __init as a CPU can be hot-plugged after boot.
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index abbcc1b0eec5..ee67eb35f4a7 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -42,6 +42,9 @@ enum kasan_mode {
>  
>  extern enum kasan_mode kasan_mode __ro_after_init;
>  
> +extern unsigned long kasan_page_alloc_sample;
> +DECLARE_PER_CPU(unsigned long, kasan_page_alloc_count);
> +
>  static inline bool kasan_vmalloc_enabled(void)
>  {
>  	return static_branch_likely(&kasan_flag_vmalloc);
> @@ -57,6 +60,13 @@ static inline bool kasan_sync_fault_possible(void)
>  	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
>  }
>  
> +static inline bool kasan_sample_page_alloc(void)
> +{
> +	unsigned long *count = this_cpu_ptr(&kasan_page_alloc_count);

this_cpu_inc_return()

without it, you need to ensure preemption is disabled around here.

> +
> +	return (*count)++ % kasan_page_alloc_sample == 0;

Doing '%' is a potentially costly operation if called in a fast-path.

We can generate better code with (rename 'count' -> 'skip'):

	long skip_next = this_cpu_dec_return(kasan_page_alloc_skip);

	if (skip_next < 0) {
		this_cpu_write(kasan_page_alloc_skip, kasan_page_alloc_sample - 1);
		return true;
	}

	return false;

Important is also to switch the counter to a 'long', otherwise you'd
have to pre-initialize all of them to something non-zero to avoid wrap.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y13oij%2BhiJgQ9BXj%40elver.google.com.
