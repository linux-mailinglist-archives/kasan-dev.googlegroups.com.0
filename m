Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC5MQ2AAMGQE4X5CEAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 71B842F7C52
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:18:03 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id e12sf4158051wrp.10
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:18:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610716683; cv=pass;
        d=google.com; s=arc-20160816;
        b=XBa2pvzHuDxX5lu3D0zs4EKblmTTdyBROv1Gn4123lqp3oD7miu3chSnnCtcWAOP5N
         48Yw9eU+Dri26mT8V/KpB4sAYTMv8l216H4LK9NO5PpAauV88bhyvn0kkBN7VwCfBTpY
         KU3WaRLljCNoHoNJY1xHHeI6nyIRnSdy+MFFv7t1TlEg15p0h5WIYIEqU6ncfxYWusoF
         AQqiG8hnqyCUOSH8QIHUmgDq5WZAZMMhGcdFIQhkRXcVYXAtEZwkg+4NCpgbO5D+bdWD
         xaz1O/BuCcPFK0EQQF7AP6TgM9I+LUrMVQYmusIKVUYzR30rU3YjPBlpO3NAJPyaoZEg
         0e+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MhWYH4411JLJ7RU4pzrbvIP2b1iYcXpSkMeBeu8LF+8=;
        b=B8XFby9VlAFHw9fFvOH3h8+D78kRrLq0u0asKSq6F95h9HCWKsEqhiVGlxORXTNaVh
         PT7OYjwPM+cE+eHM2heuWFJL9YrfNBE6ItwuzVtUBsYE5Y/67GmxlriDL5mpNXHzDsz/
         PXbsK67F6GhE5bfkhYT3LAiyanNwVhnZxF7Qqt6YX5r3QRicScq+RRmxezKY6ARcb+pg
         E6NYaWG6DwxqRaElhdGjmT3WvvyHFtsl4zAtcDDCG1ksQtP0OnHxnl21XHmB851WWA2y
         yWp7KaObODSFu+Ttjo3blZOj1y0dNors6rUZhwc3jlQvNoVyzHNEgbOfces3Q9PJJojW
         ewNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SNfAj5VC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MhWYH4411JLJ7RU4pzrbvIP2b1iYcXpSkMeBeu8LF+8=;
        b=irl2SifZ/hxeJRAhFyqrQ6vQo/UR6EiRasfZ0Zaq5STVaAhFdenlzk+jnBCA2hgHsU
         bNzJGZDW0/0OP7cywaE6K2Yj4ZuSxwsttdxicvPfITxneTc3qTdVchoF+Dc1iMJDZId2
         Wbups2E/P7dU6zffvrYaBLvWa46RA7TY7Jzn4iFdPSZbmp7nzELPzRpOYs+Z9aghcdBt
         MyULtfM/zPZsjcgQ6gYqj5kqz7tDeP6/njd6ouZB9skG3GMqyw/dG7CCKL9C2zWaNqjP
         XbwKvoJohu/huTWD1SwywlBTrZfJpOiwP6WBHg94zMzPCK4QyQZ23LFCBeGBWrpwxNr4
         K+3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MhWYH4411JLJ7RU4pzrbvIP2b1iYcXpSkMeBeu8LF+8=;
        b=gIkXR99XG+pAemr8FgsnHeY+BZwjnFxWMVL0Zrsme1dA3g9BhCE5mXt6pxZfK8xvC/
         11MHs/nS3HioZm+Nx83yz2fnuZuE27bsFNvp3aDLdEPuJsqbz9aVdYjIUK0RgtTCSpcV
         hSLOKmo5NOnCc2QviBvgFP4+Ytu130ima2sa3+CAWEzrLpF7w2kgjYo7BsqheQTpRJKJ
         1PDBnf/yCevu9tu4k3daCMc1x/IAylHTRr9kPG24decpCztxg44RT5H6W12KveBou5K4
         wLmIdZOK4d25ADd1ETeHDgSVTLFeQT96BPziRHnF6jUpXG9zhFrgQg1vBVrCF5gptAXs
         fzqA==
X-Gm-Message-State: AOAM530D+QfMAjxXVGqPhE86vFmmG6stzi7sPcYfEruTQ89PgejszvKc
	rL+XBeFoL+9hZVDb2qpjzFY=
X-Google-Smtp-Source: ABdhPJxpR2b7qX4NMbRFzKaTUymxw2sgzdXC7adZzOKi0+W+VEfN2Faff1EvsnxFd0C6EnFZbndQGA==
X-Received: by 2002:a5d:4307:: with SMTP id h7mr13357591wrq.353.1610716683266;
        Fri, 15 Jan 2021 05:18:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5543:: with SMTP id g3ls9306840wrw.0.gmail; Fri, 15 Jan
 2021 05:18:02 -0800 (PST)
X-Received: by 2002:adf:f845:: with SMTP id d5mr13001416wrq.182.1610716682283;
        Fri, 15 Jan 2021 05:18:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610716682; cv=none;
        d=google.com; s=arc-20160816;
        b=PyNK5AqvdPueippRbPXnXW4y1dhJXNjGmsvpyuc0b0RXVeqV2i+Y2WsTa5zbnCfvRL
         KLl/izPlaTgw6UNv3YZzbjJYwNjL39yksDDBLq+HBrKnNb77ca6JfgdZHVJvW5a0xKZF
         4GWd+niW5xVDWKm1Kiki4tU6G+IKO6zOHXaXHvPkQvjACy8xXxyJWzRGC0lc5aw9fqRc
         AtIGOXFXmFxl18dwq8/YVZwesYbT/NqVTRor+IsKGewYsIS4+u8RBhBv/Uzj34UcC5Pk
         Trg15cqvvjtGjc9oGxKtQraVAi7xDkOH5aVCzO5kSd/l76XfwQgV5YAAY6Ey6cfGneSi
         6FLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GkDcd3M5BN96zQc3rGkP2PwiXLixN9g52SK2TKwq13E=;
        b=r9+yblOXRyCWHfSriW/BUpO70AdnWKCmlklpSLbuEfSEP8ZQ8i2Wqx2cth4dFMEnzm
         VKhDVopZAkTm2CFWFEcwXGuyGjZZR7z55mDisj9Lvigb748s8DFMqOnHTZxd5Vxjcmu6
         GM/YVO63nfdY7vZvO2UFRsop10u7eV66XTNVhgM3wJs3KMu16IRaYYguHPPqeQEJf6CA
         Sb37l2kVnAos2baVHNRRIz37qJpRzj22wQ+5wQ8dv6EuzzxvU7bMNYZWNYjriyxi2chk
         NmKQWhiaLk4qTh0OPtJRlBJTzunTU7pv6AH090MAOnScc+u+2NuIJaAxTmKWnPaZd53q
         101w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SNfAj5VC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 18si584676wmg.2.2021.01.15.05.18.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:18:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id o10so1879093wmc.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:18:02 -0800 (PST)
X-Received: by 2002:a1c:6402:: with SMTP id y2mr8487765wmb.43.1610716681745;
        Fri, 15 Jan 2021 05:18:01 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id b19sm12075431wmj.37.2021.01.15.05.18.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jan 2021 05:18:00 -0800 (PST)
Date: Fri, 15 Jan 2021 14:17:55 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 12/15] kasan: fix bug detection via ksize for HW_TAGS
 mode
Message-ID: <YAGWA4EWQQd+7e+v@elver.google.com>
References: <cover.1610652890.git.andreyknvl@google.com>
 <bb93ea5b526a57ca328c69173433309837d05b25.1610652890.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bb93ea5b526a57ca328c69173433309837d05b25.1610652890.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SNfAj5VC;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> The currently existing kasan_check_read/write() annotations are intended
> to be used for kernel modules that have KASAN compiler instrumentation
> disabled. Thus, they are only relevant for the software KASAN modes that
> rely on compiler instrumentation.
> 
> However there's another use case for these annotations: ksize() checks
> that the object passed to it is indeed accessible before unpoisoning the
> whole object. This is currently done via __kasan_check_read(), which is
> compiled away for the hardware tag-based mode that doesn't rely on
> compiler instrumentation. This leads to KASAN missing detecting some
> memory corruptions.
> 
> Provide another annotation called kasan_check_byte() that is available
> for all KASAN modes. As the implementation rename and reuse
> kasan_check_invalid_free(). Use this new annotation in ksize().
> To avoid having ksize() as the top frame in the reported stack trace
> pass _RET_IP_ to __kasan_check_byte().
> 
> Also add a new ksize_uaf() test that checks that a use-after-free is
> detected via ksize() itself, and via plain accesses that happen later.
> 
> Link: https://linux-review.googlesource.com/id/Iaabf771881d0f9ce1b969f2a62938e99d3308ec5
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kasan-checks.h |  6 ++++++
>  include/linux/kasan.h        | 17 +++++++++++++++++
>  lib/test_kasan.c             | 20 ++++++++++++++++++++
>  mm/kasan/common.c            | 11 ++++++++++-
>  mm/kasan/generic.c           |  4 ++--
>  mm/kasan/kasan.h             | 10 +++++-----
>  mm/kasan/sw_tags.c           |  6 +++---
>  mm/slab_common.c             | 16 +++++++++-------
>  8 files changed, 72 insertions(+), 18 deletions(-)
> 
> diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
> index ca5e89fb10d3..3d6d22a25bdc 100644
> --- a/include/linux/kasan-checks.h
> +++ b/include/linux/kasan-checks.h
> @@ -4,6 +4,12 @@
>  
>  #include <linux/types.h>
>  
> +/*
> + * The annotations present in this file are only relevant for the software
> + * KASAN modes that rely on compiler instrumentation, and will be optimized
> + * away for the hardware tag-based KASAN mode. Use kasan_check_byte() instead.
> + */
> +
>  /*
>   * __kasan_check_*: Always available when KASAN is enabled. This may be used
>   * even in compilation units that selectively disable KASAN, but must use KASAN
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bba1637827c3..5bedd5ee481f 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -242,6 +242,19 @@ static __always_inline void kasan_kfree_large(void *ptr)
>  		__kasan_kfree_large(ptr, _RET_IP_);
>  }
>  
> +/*
> + * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
> + * the hardware tag-based mode that doesn't rely on compiler instrumentation.
> + */
> +bool __kasan_check_byte(const void *addr, unsigned long ip);
> +static __always_inline bool kasan_check_byte(const void *addr)
> +{
> +	if (kasan_enabled())
> +		return __kasan_check_byte(addr, _RET_IP_);
> +	return true;
> +}
> +
> +
>  bool kasan_save_enable_multi_shot(void);
>  void kasan_restore_multi_shot(bool enabled);
>  
> @@ -297,6 +310,10 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
>  	return (void *)object;
>  }
>  static inline void kasan_kfree_large(void *ptr) {}
> +static inline bool kasan_check_byte(const void *address)
> +{
> +	return true;
> +}
>  
>  #endif /* CONFIG_KASAN */
>  
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index a06e7946f581..566d894ba20b 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -496,6 +496,7 @@ static void kasan_global_oob(struct kunit *test)
>  	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>  
> +/* Check that ksize() makes the whole object accessible. */
>  static void ksize_unpoisons_memory(struct kunit *test)
>  {
>  	char *ptr;
> @@ -514,6 +515,24 @@ static void ksize_unpoisons_memory(struct kunit *test)
>  	kfree(ptr);
>  }
>  
> +/*
> + * Check that a use-after-free is detected by ksize() and via normal accesses
> + * after it.
> + */
> +static void ksize_uaf(struct kunit *test)
> +{
> +	char *ptr;
> +	int size = 128 - KASAN_GRANULE_SIZE;
> +
> +	ptr = kmalloc(size, GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +	kfree(ptr);
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
> +	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *ptr);
> +	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *(ptr + size));
> +}
> +
>  static void kasan_stack_oob(struct kunit *test)
>  {
>  	char stack_array[10];
> @@ -907,6 +926,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kasan_alloca_oob_left),
>  	KUNIT_CASE(kasan_alloca_oob_right),
>  	KUNIT_CASE(ksize_unpoisons_memory),
> +	KUNIT_CASE(ksize_uaf),
>  	KUNIT_CASE(kmem_cache_double_free),
>  	KUNIT_CASE(kmem_cache_invalid_free),
>  	KUNIT_CASE(kasan_memchr),
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index eedc3e0fe365..b18189ef3a92 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -345,7 +345,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
>  		return false;
>  
> -	if (kasan_check_invalid_free(tagged_object)) {
> +	if (!kasan_byte_accessible(tagged_object)) {
>  		kasan_report_invalid_free(tagged_object, ip);
>  		return true;
>  	}
> @@ -490,3 +490,12 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
>  		kasan_report_invalid_free(ptr, ip);
>  	/* The object will be poisoned by kasan_free_pages(). */
>  }
> +
> +bool __kasan_check_byte(const void *address, unsigned long ip)
> +{
> +	if (!kasan_byte_accessible(address)) {
> +		kasan_report((unsigned long)address, 1, false, ip);
> +		return false;
> +	}
> +	return true;
> +}
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index acab8862dc67..3f17a1218055 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -185,11 +185,11 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
>  	return check_region_inline(addr, size, write, ret_ip);
>  }
>  
> -bool kasan_check_invalid_free(void *addr)
> +bool kasan_byte_accessible(const void *addr)
>  {
>  	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
>  
> -	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
> +	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
>  }
>  
>  void kasan_cache_shrink(struct kmem_cache *cache)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 292dfbc37deb..bd4ee6fab648 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -329,20 +329,20 @@ static inline void kasan_unpoison(const void *address, size_t size)
>  			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>  
> -static inline bool kasan_check_invalid_free(void *addr)
> +static inline bool kasan_byte_accessible(const void *addr)
>  {
>  	u8 ptr_tag = get_tag(addr);
> -	u8 mem_tag = hw_get_mem_tag(addr);
> +	u8 mem_tag = hw_get_mem_tag((void *)addr);
>  
> -	return (mem_tag == KASAN_TAG_INVALID) ||
> -		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
> +	return (mem_tag != KASAN_TAG_INVALID) &&
> +		(ptr_tag == KASAN_TAG_KERNEL || ptr_tag == mem_tag);
>  }
>  
>  #else /* CONFIG_KASAN_HW_TAGS */
>  
>  void kasan_poison(const void *address, size_t size, u8 value);
>  void kasan_unpoison(const void *address, size_t size);
> -bool kasan_check_invalid_free(void *addr);
> +bool kasan_byte_accessible(const void *addr);
>  
>  #endif /* CONFIG_KASAN_HW_TAGS */
>  
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index cc271fceb5d5..94c2d33be333 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -118,13 +118,13 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
>  	return true;
>  }
>  
> -bool kasan_check_invalid_free(void *addr)
> +bool kasan_byte_accessible(const void *addr)
>  {
>  	u8 tag = get_tag(addr);
>  	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(kasan_reset_tag(addr)));
>  
> -	return (shadow_byte == KASAN_TAG_INVALID) ||
> -		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
> +	return (shadow_byte != KASAN_TAG_INVALID) &&
> +		(tag == KASAN_TAG_KERNEL || tag == shadow_byte);
>  }
>  
>  #define DEFINE_HWASAN_LOAD_STORE(size)					\
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index e981c80d216c..9c12cf4212ea 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1157,19 +1157,21 @@ size_t ksize(const void *objp)
>  	size_t size;
>  
>  	/*
> -	 * We need to check that the pointed to object is valid, and only then
> -	 * unpoison the shadow memory below. We use __kasan_check_read(), to
> -	 * generate a more useful report at the time ksize() is called (rather
> -	 * than later where behaviour is undefined due to potential
> -	 * use-after-free or double-free).
> +	 * We need to first check that the pointer to the object is valid, and
> +	 * only then unpoison the memory. The report printed from ksize() is
> +	 * more useful, then when it's printed later when the behaviour could
> +	 * be undefined due to a potential use-after-free or double-free.
>  	 *
> -	 * If the pointed to memory is invalid we return 0, to avoid users of
> +	 * We use kasan_check_byte(), which is supported for the hardware
> +	 * tag-based KASAN mode, unlike kasan_check_read/write().
> +	 *
> +	 * If the pointed to memory is invalid, we return 0 to avoid users of
>  	 * ksize() writing to and potentially corrupting the memory region.
>  	 *
>  	 * We want to perform the check before __ksize(), to avoid potentially
>  	 * crashing in __ksize() due to accessing invalid metadata.
>  	 */
> -	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
> +	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
>  		return 0;
>  
>  	size = __ksize(objp);
> -- 
> 2.30.0.284.gd98b1dd5eaa7-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YAGWA4EWQQd%2B7e%2Bv%40elver.google.com.
