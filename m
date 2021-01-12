Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD56637QKGQE34OMSLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D99C2F304B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 14:07:27 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id c2sf834049wme.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 05:07:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610456847; cv=pass;
        d=google.com; s=arc-20160816;
        b=KZuHy9eDWlRcAL96CaDELO90vGHy+ABKs5Gm1yp9B7CZJ0mXd3Bcjb21/U/28pgwev
         OuVB8EBTG61cQDab+WoFq9Tsl9tIWD6W37W7Zjdb6AqIDYQxrYL0OCLWcu0yofvvwby3
         6i++UrYnFmE6WvIjyUKRLWHiIo0u3E9YLfyJv7rRSJqm+HW5TglkBtYik59eUJeqrRTu
         PpbKc+KjByIgqHZMdpWa9Kbpc5rmD4EZvA9/lj330KzvbiLWTbh5SqJDxmFCsl8rPxe5
         hj2Hz13h7HHEdhHen6H146dmsVbRbUyJVdgqVcvNslPKfF2H7V4r3uOwKxCeQFyBVF44
         6H9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Rfya8442Kn6NiWRmJH5G2QLTWnqx1d1m5bpEd+qA8TM=;
        b=YENKeSQF/IsmJNE33yOMwH4exkQBKfjxDswOoEYt/BZabmw6IzAHsrPGHzIR1NlzM4
         0aYAy9l2fga8fCZX7hHV7ICjNkkRrp9f3EUt8o2hB41u1vBLlV0f6GYxVS4Isa854orq
         K7q+PmK+yv2Vx2ZFTBwRM8ZLMqqh7QR+gH34BWR48FLvdAqR+cSrMbKc3Xk5gg4mLSHT
         pp4xaLQcFcVIRJ7UQl2Vw+pfbGLSYnV5u5/feFXJnyjf36isZ3hg0K1hD0E9ybPt0eEI
         eU5+K76KF67fGssiH6PmUpNmk9BI0MXc2T4X9V5Oj8jfdd6CG+6qWnm7/OKq/mpPdej+
         2r7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wv7K70rB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Rfya8442Kn6NiWRmJH5G2QLTWnqx1d1m5bpEd+qA8TM=;
        b=aJIUZztTJKCx+dG1zV4UjMmtJn8OKKC9/6v4k2F3GCID7pMbd2cNg71pmNQ3E/qtOL
         +VIED6TDmUcTx3hje1lf0EXVQRddXHPJTbDORoX0ZHpD3zHoD3bOkqx5dKZhgkliuVxg
         U5iPM8xKOOvgbMrAH/winTH7Q6nemdspJrnxmi40G/O0ERjxDob+bpLNSbSOyOQLvTy3
         PICcwteNVRwMLcjMMUh/k4EvK9UROLPIQBTy7OiykSzApHdbBHf2/XIrXr3mmpUv9XbP
         wM6eyW36Hv4XthFIUGbum3wLYGgZLYq+TDY0MKxCXvz92sKyeLVk6jOVHzVQmEGDo+eZ
         7n5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Rfya8442Kn6NiWRmJH5G2QLTWnqx1d1m5bpEd+qA8TM=;
        b=TeJSY3y0769GJXm7c3li5iKkl3aCPG2BxhyOi6vAF8HQrVE41T09Uy5oQTGBcrB52L
         Qw5bximWalpdC1xXiv8nheU/z7bNPpMIYemXG9o1qo7hfUUybleij20sqq0ETimSN7ye
         NppnR11PiVzhAtoHQzkRNBmv/rKI/MdtEzQtlkd1Q2GRUCcvaNEKmjs5HMqVzNDHZzr9
         jIr83kX/3Jwd2RBCiEoUMOQ/RleSieMso261jxUU3F7inir75hCXrgOvRqXcEwqM7ZfU
         pbGmSKNklC3FYrr9vxs7mJ+huGLVP4ag3PeMLNKwLrIP5InvUGdRZnqRt12WlhbzigOm
         hFFQ==
X-Gm-Message-State: AOAM532xAmEkI9eEGmgm3AHsYnvnEzuHXaGc9F6Wyp4GLGaiCLIkqZcm
	VeiiFAxtE4DTeVAZlO4Y/wM=
X-Google-Smtp-Source: ABdhPJyPJMTv24tMAEayq2tXppsLZ1nUMy/ktS4Bcl50iFXyW8KWeidiuuhyZdDJPNUU0TFLUOB3BQ==
X-Received: by 2002:a05:6000:368:: with SMTP id f8mr4276558wrf.150.1610456847262;
        Tue, 12 Jan 2021 05:07:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbd5:: with SMTP id n21ls1261806wmi.3.gmail; Tue, 12 Jan
 2021 05:07:26 -0800 (PST)
X-Received: by 2002:a05:600c:3510:: with SMTP id h16mr3501560wmq.156.1610456846314;
        Tue, 12 Jan 2021 05:07:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610456846; cv=none;
        d=google.com; s=arc-20160816;
        b=Nns3WtvAEFdR/tjuGOBs1eCaajLELX9ZVajRTI3DFUbzkJxqyiIw2Sp2Ui/no4B2YS
         cs/O5alO97gbtJKTM9dKnRBO/te3i3e1t863gHbMTF6egM/B2CnppzCXuia5vVw84cua
         AHcPfefxlPJaayhidb9d+jWx6uub4+vg7KklehqvRKMil/hHClEmc//cP73o4Vf5yiQO
         /d+miCGQdWJQd9Gf3FO6tislhFApQ0hcwON0eFpNxMuD0AdiwhkOWSY5ZtDZ1i/IisR9
         8uACErZx2uWDFpYeH6XhnNnWO0Oflpy4kBGnvv61EQM3LqNXu9EEBxlv69k9+h+hj9ks
         Xa3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GnsdLE8z7GKqgdEkPWmktkSWY9f1wcAcGK6xh9iY7ow=;
        b=olhmzYDl8FTRcVF/x/1ME/VVz25KoRhE2K2O9zSy0AxRHYcIrC6ZMn2Zgg3P24P77w
         Vd5c+MMBYEjq96UsJdgQgw/JDwkrOjEbGDh6Q/tN0DJoJhWpSbqd7euCLLqGauE6Rew2
         j1S+l5lWp5h4d556wakI5VHy7j8rla7zkP03QcBaPYEwABIzEShrsXcI2Rfy/Idao++c
         ZTFSA+8NHbsXSkOBBafeiTQK64xg1ndcyyR/LqTpIEzivT+B5TBdsCWvr0FL1uf0o3Vo
         3z36RFOvYJbh1V4DN5hgLb8thaivKQcXDK5+BKLtKtho42eOKfggyDmSMl06uX07VWSP
         0HMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wv7K70rB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id x130si93876wmg.2.2021.01.12.05.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 05:07:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id d26so2398212wrb.12
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 05:07:26 -0800 (PST)
X-Received: by 2002:adf:b359:: with SMTP id k25mr4376621wrd.98.1610456845707;
        Tue, 12 Jan 2021 05:07:25 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id b133sm3694353wme.33.2021.01.12.05.07.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Jan 2021 05:07:24 -0800 (PST)
Date: Tue, 12 Jan 2021 14:07:19 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 03/11] kasan: clean up comments in tests
Message-ID: <X/2fB7oPuRN29r7u@elver.google.com>
References: <cover.1609871239.git.andreyknvl@google.com>
 <cb4e610c6584251aa2397b56c46e278da0050a25.1609871239.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cb4e610c6584251aa2397b56c46e278da0050a25.1609871239.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wv7K70rB;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
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

On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> Clarify and update comments and info messages in KASAN tests.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I6c816c51fa1e0eb7aa3dead6bda1f339d2af46c8

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c        | 94 +++++++++++++++++++++++------------------
>  lib/test_kasan_module.c |  5 ++-
>  2 files changed, 55 insertions(+), 44 deletions(-)
> 
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 2947274cc2d3..46e578c8e842 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -28,10 +28,9 @@
>  #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
>  
>  /*
> - * We assign some test results to these globals to make sure the tests
> - * are not eliminated as dead code.
> + * Some tests use these global variables to store return values from function
> + * calls that could otherwise be eliminated by the compiler as dead code.
>   */
> -
>  void *kasan_ptr_result;
>  int kasan_int_result;
>  
> @@ -39,14 +38,13 @@ static struct kunit_resource resource;
>  static struct kunit_kasan_expectation fail_data;
>  static bool multishot;
>  
> +/*
> + * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
> + * first detected bug and panic the kernel if panic_on_warn is enabled.
> + */
>  static int kasan_test_init(struct kunit *test)
>  {
> -	/*
> -	 * Temporarily enable multi-shot mode and set panic_on_warn=0.
> -	 * Otherwise, we'd only get a report for the first case.
> -	 */
>  	multishot = kasan_save_enable_multi_shot();
> -
>  	return 0;
>  }
>  
> @@ -56,12 +54,12 @@ static void kasan_test_exit(struct kunit *test)
>  }
>  
>  /**
> - * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> - * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
> - * Do not use this name for a KUnit resource outside here.
> - *
> + * KUNIT_EXPECT_KASAN_FAIL() - check that the executed expression produces a
> + * KASAN report; causes a test failure otherwise. This relies on a KUnit
> + * resource named "kasan_data". Do not use this name for KUnit resources
> + * outside of KASAN tests.
>   */
> -#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> +#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do { \
>  	fail_data.report_expected = true; \
>  	fail_data.report_found = false; \
>  	kunit_add_named_resource(test, \
> @@ -69,7 +67,7 @@ static void kasan_test_exit(struct kunit *test)
>  				NULL, \
>  				&resource, \
>  				"kasan_data", &fail_data); \
> -	condition; \
> +	expression; \
>  	KUNIT_EXPECT_EQ(test, \
>  			fail_data.report_expected, \
>  			fail_data.report_found); \
> @@ -117,11 +115,12 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>  	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>  
>  	if (!IS_ENABLED(CONFIG_SLUB)) {
> -		kunit_info(test, "CONFIG_SLUB is not enabled.");
> +		kunit_info(test, "skipping, CONFIG_SLUB required");
>  		return;
>  	}
>  
> -	/* Allocate a chunk that does not fit into a SLUB cache to trigger
> +	/*
> +	 * Allocate a chunk that does not fit into a SLUB cache to trigger
>  	 * the page allocator fallback.
>  	 */
>  	ptr = kmalloc(size, GFP_KERNEL);
> @@ -137,7 +136,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
>  	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>  
>  	if (!IS_ENABLED(CONFIG_SLUB)) {
> -		kunit_info(test, "CONFIG_SLUB is not enabled.");
> +		kunit_info(test, "skipping, CONFIG_SLUB required");
>  		return;
>  	}
>  
> @@ -154,7 +153,7 @@ static void kmalloc_pagealloc_invalid_free(struct kunit *test)
>  	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
>  
>  	if (!IS_ENABLED(CONFIG_SLUB)) {
> -		kunit_info(test, "CONFIG_SLUB is not enabled.");
> +		kunit_info(test, "skipping, CONFIG_SLUB required");
>  		return;
>  	}
>  
> @@ -168,7 +167,9 @@ static void kmalloc_large_oob_right(struct kunit *test)
>  {
>  	char *ptr;
>  	size_t size = KMALLOC_MAX_CACHE_SIZE - 256;
> -	/* Allocate a chunk that is large enough, but still fits into a slab
> +
> +	/*
> +	 * Allocate a chunk that is large enough, but still fits into a slab
>  	 * and does not trigger the page allocator fallback in SLUB.
>  	 */
>  	ptr = kmalloc(size, GFP_KERNEL);
> @@ -218,7 +219,7 @@ static void kmalloc_oob_16(struct kunit *test)
>  
>  	/* This test is specifically crafted for the generic mode. */
>  	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
> +		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
>  		return;
>  	}
>  
> @@ -454,7 +455,7 @@ static void kasan_global_oob(struct kunit *test)
>  
>  	/* Only generic mode instruments globals. */
>  	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -		kunit_info(test, "CONFIG_KASAN_GENERIC required");
> +		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
>  		return;
>  	}
>  
> @@ -469,10 +470,13 @@ static void ksize_unpoisons_memory(struct kunit *test)
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>  	real_size = ksize(ptr);
> -	/* This access doesn't trigger an error. */
> +
> +	/* This access shouldn't trigger a KASAN report. */
>  	ptr[size] = 'x';
> -	/* This one does. */
> +
> +	/* This one must. */
>  	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
> +
>  	kfree(ptr);
>  }
>  
> @@ -483,7 +487,7 @@ static void kasan_stack_oob(struct kunit *test)
>  	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
>  
>  	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
> -		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
> +		kunit_info(test, "skipping, CONFIG_KASAN_STACK required");
>  		return;
>  	}
>  
> @@ -498,12 +502,12 @@ static void kasan_alloca_oob_left(struct kunit *test)
>  
>  	/* Only generic mode instruments dynamic allocas. */
>  	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -		kunit_info(test, "CONFIG_KASAN_GENERIC required");
> +		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
>  		return;
>  	}
>  
>  	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
> -		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
> +		kunit_info(test, "skipping, CONFIG_KASAN_STACK required");
>  		return;
>  	}
>  
> @@ -518,12 +522,12 @@ static void kasan_alloca_oob_right(struct kunit *test)
>  
>  	/* Only generic mode instruments dynamic allocas. */
>  	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -		kunit_info(test, "CONFIG_KASAN_GENERIC required");
> +		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
>  		return;
>  	}
>  
>  	if (!IS_ENABLED(CONFIG_KASAN_STACK)) {
> -		kunit_info(test, "CONFIG_KASAN_STACK is not enabled");
> +		kunit_info(test, "skipping, CONFIG_KASAN_STACK required");
>  		return;
>  	}
>  
> @@ -568,7 +572,7 @@ static void kmem_cache_invalid_free(struct kunit *test)
>  		return;
>  	}
>  
> -	/* Trigger invalid free, the object doesn't get freed */
> +	/* Trigger invalid free, the object doesn't get freed. */
>  	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_free(cache, p + 1));
>  
>  	/*
> @@ -585,10 +589,12 @@ static void kasan_memchr(struct kunit *test)
>  	char *ptr;
>  	size_t size = 24;
>  
> -	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
> +	/*
> +	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> +	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
> +	 */
>  	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
> -		kunit_info(test,
> -			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> +		kunit_info(test, "skipping, CONFIG_AMD_MEM_ENCRYPT enabled");
>  		return;
>  	}
>  
> @@ -610,10 +616,12 @@ static void kasan_memcmp(struct kunit *test)
>  	size_t size = 24;
>  	int arr[9];
>  
> -	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
> +	/*
> +	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> +	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
> +	 */
>  	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
> -		kunit_info(test,
> -			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> +		kunit_info(test, "skipping, CONFIG_AMD_MEM_ENCRYPT enabled");
>  		return;
>  	}
>  
> @@ -634,10 +642,12 @@ static void kasan_strings(struct kunit *test)
>  	char *ptr;
>  	size_t size = 24;
>  
> -	/* See https://bugzilla.kernel.org/show_bug.cgi?id=206337 */
> +	/*
> +	 * str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT.
> +	 * See https://bugzilla.kernel.org/show_bug.cgi?id=206337 for details.
> +	 */
>  	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)) {
> -		kunit_info(test,
> -			"str* functions are not instrumented with CONFIG_AMD_MEM_ENCRYPT");
> +		kunit_info(test, "skipping, CONFIG_AMD_MEM_ENCRYPT enabled");
>  		return;
>  	}
>  
> @@ -701,12 +711,12 @@ static void kasan_bitops_generic(struct kunit *test)
>  
>  	/* This test is specifically crafted for the generic mode. */
>  	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -		kunit_info(test, "CONFIG_KASAN_GENERIC required\n");
> +		kunit_info(test, "skipping, CONFIG_KASAN_GENERIC required");
>  		return;
>  	}
>  
>  	/*
> -	 * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> +	 * Allocate 1 more byte, which causes kzalloc to round up to 16 bytes;
>  	 * this way we do not actually corrupt other memory.
>  	 */
>  	bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
> @@ -733,7 +743,7 @@ static void kasan_bitops_tags(struct kunit *test)
>  
>  	/* This test is specifically crafted for the tag-based mode. */
>  	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> -		kunit_info(test, "CONFIG_KASAN_SW_TAGS required\n");
> +		kunit_info(test, "skipping, CONFIG_KASAN_SW_TAGS required");
>  		return;
>  	}
>  
> @@ -765,7 +775,7 @@ static void vmalloc_oob(struct kunit *test)
>  	void *area;
>  
>  	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> -		kunit_info(test, "CONFIG_KASAN_VMALLOC is not enabled.");
> +		kunit_info(test, "skipping, CONFIG_KASAN_VMALLOC required");
>  		return;
>  	}
>  
> diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> index 3b4cc77992d2..eee017ff8980 100644
> --- a/lib/test_kasan_module.c
> +++ b/lib/test_kasan_module.c
> @@ -123,8 +123,9 @@ static noinline void __init kasan_workqueue_uaf(void)
>  static int __init test_kasan_module_init(void)
>  {
>  	/*
> -	 * Temporarily enable multi-shot mode. Otherwise, we'd only get a
> -	 * report for the first case.
> +	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
> +	 * report the first detected bug and panic the kernel if panic_on_warn
> +	 * is enabled.
>  	 */
>  	bool multishot = kasan_save_enable_multi_shot();
>  
> -- 
> 2.29.2.729.g45daf8777d-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/X/2fB7oPuRN29r7u%40elver.google.com.
