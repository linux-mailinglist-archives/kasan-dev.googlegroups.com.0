Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI43WD6QKGQETZJ5GTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 77CA52AF5EC
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 17:13:25 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id g19sf158067ljl.23
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:13:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605111205; cv=pass;
        d=google.com; s=arc-20160816;
        b=y6F8CHEYfxix0k0T+3IMw9Bmj26qof+qvg+M9VeUf2+AppJKtPVMroIfrzgM4f4FVy
         vz7SAaF4aEi1xFDZILyFOTPgt9hGgfj3HLuoyUdP7iNwsxDsYlRu2bVhuvItazkVt2R/
         7Kws6NzWTEfV5rt3hP6ZJFb+VU2RcmP0NspLL6A2oCBYDbkBK0v+RrtJEvt31jKUwW36
         yGBHgwiCTVJKDZCAHLq6dQvO2S6MLuGl+t0YCF9mvsjTO+KZx6AiGHmmZQ1otMmYOVdt
         30yVNbN42BwpuQSsHBPWM20yHk6ZdJKFpQYeX9P1iXPpXRbRvMmXFThhi4197kE9M1Q8
         qIIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rrXt5nkXbv2AE8EWJ9Wc+ee2OBoi5LWUGwaNOkuRydc=;
        b=L4V0bKp9Iu8Q1YTPhA/iUsHkWjy1lBXV81fQszImyDQAQxjKXCHpAH8jW0RNlHmj56
         D34a/aktOi0vT9DHB6qDvYvGYZ8GIMmD6BVsTFUzyzcGFWhjXlLwSSHWs67FnoUK+uSC
         2farb11adqKYIZt0GgMbr+tTVl6S9qgM9dEa5MtPnmqzruGlCUBg+05FABDQHB8Tv7q4
         HnfjrTkExyQqE4ECdOrdU8iR/2I3d6h08iXUCks8VpMzWJ4YI78qXfmWdgHfBDZ2rvj0
         Imdvbcj3q7egoDEdwLYM9HksoQ1PhNQCIMsUpJAJNkPBNSy94zJ8cew5IKE1mFo28dqv
         WG/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=djjmtjGB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rrXt5nkXbv2AE8EWJ9Wc+ee2OBoi5LWUGwaNOkuRydc=;
        b=Dhfz2DnhNQumnuoyRIj6MICyddh9EjWtdk0+/UIziYG7wzmaGSyGzkXKRJLaEwa622
         5Rsd3WnMCOD0fQb3x5HJ0Q6LC3FhPG8fob1JlPU0ljnhcqFsilGp+9e/lLShxt2TsQDY
         PNteFByjZKuD0RPX4xDPKcsLDCAgHUZBqcavnWTft8nw2eidUOHFsHFJ2pv/sBATv2UE
         5hsGtDHfIvMcTb+xTAowyWFRQncRy/Es51TMy42wsC2SwXhsbRpIZnljYhBie7SvUTQt
         lwLxhagRjwZ8ZQn0XuvaBN6prfMUY/dwAsFjTV/b8gDnIz7Uto2fnOQGOn7a5UGoYVH+
         7SDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rrXt5nkXbv2AE8EWJ9Wc+ee2OBoi5LWUGwaNOkuRydc=;
        b=DTeBkcEwp6WeB4Pfa/Wwd8p6mw5s+60ffgMHOc+y6Pe8VaG5Ck8eRzTl5yTBhlm4b8
         /TdR55aZnj9ON2uhuVTyQtsACaSOXMHOgWHjGZ5uwF2M9k0WFKFO8546Iqx+IiqRk5Vi
         wrTp0KY8rBlnBMzdQngSuw4mMMy3Tu77jQDsHmicMO/w+HaPs6ufX6gspvC/wacr9i8n
         QW88WF1k6d2Hc+d9gefKzDXGzgLDMgs0gRKi/RDKhKX8knu1xDeo+5NvlvWLeCNTGgtf
         m1bnnABau23HfaAT59nCQrhiA/muvf3toW3QMqtJEpZXVxltFZZcLdnJTv7dNd2C1+gG
         1Wjg==
X-Gm-Message-State: AOAM532KSrbIo2f8nf+s2qKe1/Ph71nQkEgXR32W4gh5APfTU94ct/gS
	bR5sf+ZP4zZCIhnu6RVDgZU=
X-Google-Smtp-Source: ABdhPJxfaFkpYMFCJv4NfswqcO690b3tRuyCUrimfB+YwubgzWWGKqVjXOt9u/uKKNsSopX5UX2Z5A==
X-Received: by 2002:a05:651c:2cc:: with SMTP id f12mr10463524ljo.179.1605111203542;
        Wed, 11 Nov 2020 08:13:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls12764lfa.1.gmail; Wed, 11 Nov
 2020 08:13:21 -0800 (PST)
X-Received: by 2002:a19:be13:: with SMTP id o19mr6805947lff.445.1605111200908;
        Wed, 11 Nov 2020 08:13:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605111200; cv=none;
        d=google.com; s=arc-20160816;
        b=kWSSudjvXa4py1g0tzLq+MXopeCvR3JvFGbyoO+iDCH6mUuQaUKwG2erg/CBhpDx6L
         dcd9T2Y+s1pZTfDeaUtnlc2F07ZsPCVytQfrBuQSARrCzDtGqDQsjmwqZ9VJwOjWPzHY
         kO8KtPUUfhg/VxcoeWTiCmrxmbtXgwMLn0FDUvnJGDxkMgAsnn1IxUuEt3CTUtznfG3I
         4tejAN9jrdWmxcNt7XyW3rbDV4JLP9KxNo0ciITtpHqMX7PqbkzDWnjDnnBd2cItohKk
         5eATBcPADaLIEocbK/nIYDaWO3lPh0HvjDiUADLN8CY4k4HjKgTEVWMvlNY098eRyxH4
         DNSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WwThXO74wAdZUw9ureBsdbo33+GC/qabfRYu0sfQ7ak=;
        b=DWuQY92KxdI+pqbtthZKngiC3Wm3f6FHEA9gjc05w6baPvdSGPdUZ7Clo1tJKxcD5r
         cdrK+KL3w5ZFc5FJC0b6cvEEVqHw/qgK++p/Y6/WtGxuHZdz/4pqhNvDgsYgQ+JSyNyz
         FikcqsjZx2TuC25e2uritZk6XbmTz1pOW1ln12Dt2IPOB/24Dl5kMTCjgliplM3pEOsb
         +mJwWi8znMVG5lupfQ/0xmG5JIjtWfNitQ+dKOmBhYgFEzIIhVdiqlZJRTxiJlVx/7g6
         LKr+zACrW4zM5CiZQvrdUSq5yLBY9C+3+sKOFcbhX8mb9YpXSmmJokpaFw0fBPA6P8HZ
         /8FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=djjmtjGB;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id v24si93698lfo.5.2020.11.11.08.13.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 08:13:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id j7so3081893wrp.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 08:13:20 -0800 (PST)
X-Received: by 2002:a5d:5446:: with SMTP id w6mr21313985wrv.122.1605111200317;
        Wed, 11 Nov 2020 08:13:20 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id b8sm3334226wrv.57.2020.11.11.08.13.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 08:13:19 -0800 (PST)
Date: Wed, 11 Nov 2020 17:13:13 +0100
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
Subject: Re: [PATCH v2 04/20] kasan, arm64: unpoison stack only with
 CONFIG_KASAN_STACK
Message-ID: <20201111161313.GF517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <7e95d4739f5617b2c1acf52f37e01f1ca83750b5.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7e95d4739f5617b2c1acf52f37e01f1ca83750b5.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=djjmtjGB;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> There's a config option CONFIG_KASAN_STACK that has to be enabled for
> KASAN to use stack instrumentation and perform validity checks for
> stack variables.
> 
> There's no need to unpoison stack when CONFIG_KASAN_STACK is not enabled.
> Only call kasan_unpoison_task_stack[_below]() when CONFIG_KASAN_STACK is
> enabled.
> 
> Note, that CONFIG_KASAN_STACK is an option that is currently always
> defined when CONFIG_KASAN is enabled, and therefore has to be tested
> with #if instead of #ifdef.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If8a891e9fe01ea543e00b576852685afec0887e3
> ---
>  arch/arm64/kernel/sleep.S        |  2 +-
>  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
>  include/linux/kasan.h            | 10 ++++++----
>  mm/kasan/common.c                |  2 ++
>  4 files changed, 10 insertions(+), 6 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> index ba40d57757d6..bdadfa56b40e 100644
> --- a/arch/arm64/kernel/sleep.S
> +++ b/arch/arm64/kernel/sleep.S
> @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
>  	 */
>  	bl	cpu_do_resume
>  
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>  	mov	x0, sp
>  	bl	kasan_unpoison_task_stack_below
>  #endif
> diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> index c8daa92f38dc..5d3a0b8fd379 100644
> --- a/arch/x86/kernel/acpi/wakeup_64.S
> +++ b/arch/x86/kernel/acpi/wakeup_64.S
> @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
>  	movq	pt_regs_r14(%rax), %r14
>  	movq	pt_regs_r15(%rax), %r15
>  
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
>  	/*
>  	 * The suspend path may have poisoned some areas deeper in the stack,
>  	 * which we now need to unpoison.
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index f22bdef82111..b9b9db335d87 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -76,8 +76,6 @@ static inline void kasan_disable_current(void) {}
>  
>  void kasan_unpoison_memory(const void *address, size_t size);
>  
> -void kasan_unpoison_task_stack(struct task_struct *task);
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order);
>  void kasan_free_pages(struct page *page, unsigned int order);
>  
> @@ -122,8 +120,6 @@ void kasan_restore_multi_shot(bool enabled);
>  
>  static inline void kasan_unpoison_memory(const void *address, size_t size) {}
>  
> -static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> -
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>  
> @@ -175,6 +171,12 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>  
>  #endif /* CONFIG_KASAN */
>  
> +#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> +void kasan_unpoison_task_stack(struct task_struct *task);
> +#else
> +static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> +#endif
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  
>  void kasan_cache_shrink(struct kmem_cache *cache);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a880e5a547ed..a3e67d49b893 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -58,6 +58,7 @@ void kasan_disable_current(void)
>  }
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>  
> +#if CONFIG_KASAN_STACK
>  static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
>  {
>  	void *base = task_stack_page(task);
> @@ -84,6 +85,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  
>  	kasan_unpoison_memory(base, watermark - base);
>  }
> +#endif /* CONFIG_KASAN_STACK */
>  
>  void kasan_alloc_pages(struct page *page, unsigned int order)
>  {
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111161313.GF517454%40elver.google.com.
