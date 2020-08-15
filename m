Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDVJ4D4QKGQES7HQMWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4723F245186
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 19:00:00 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id q5sf7721146ion.12
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Aug 2020 10:00:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597510799; cv=pass;
        d=google.com; s=arc-20160816;
        b=DSgxQnEfcR5Oi8zUrZecl5rMhZgp0QJw2IyE9YNb7CJKoer7u7OrhEy8QFtaHw6nvQ
         Rd0/pVQQlX8OF/H645p95qCxrmaac5HT0+CzfnBhzpP2J937+0p6eHEDE1g+dY7olQcu
         8JsM53lWNas9hWjItGE9NYeRb8bHIIzzON3FxZq2U5M1sxplJBsx7AJaV5wo2J1fc3W3
         t90JcTRuBopuayJNx6eFWpbh6mHrgcd7tfjfqvLDCK8t05L95cPkLCL9Mh0Fk8zUoyl1
         Uu/ZYfULeaLPNW1E9fwTy4UXBdNZSuQWGRfYeBRcUnyjNCiR9/BDqJUEKeiRd3Uau7Rg
         JKfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Bo43bOuMZQDIM4sDpIggNnp9SFpreqwkD0ha84N+llA=;
        b=hMD/lDlqW88PwuII0HQVoDxahI0HYhjO4eNfIhR7ykVNSTys44XliOUDMvYr9+23av
         PzYH1yapC4AxKHdOHZX3q/4WPUeheykbfVo4Otru0feDp/q/Bf7WTN0CGwyNDeEsQ6QO
         qmW0jjbRmO88ciPRTXkL/i1LS6Jj36UxtBM//B/r/ai0kyWEWTHoPUwAVB3SGeFAtx6C
         9lZdRA/t+TOUCgmZSiuT7JDAxY48hJgQFEeRxYOilX7idSknqtVFB2ZiHJkyYlwaFx8f
         JTjI61bXA796y4YYXMlFNgFMLQz5rGh5lw4ov13oF/aGVujJ6INamJG5zXsClNvtK35I
         vI2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bp6qJV4D;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Bo43bOuMZQDIM4sDpIggNnp9SFpreqwkD0ha84N+llA=;
        b=AWb6R+CLJNsvit8/WcalZVTy2ROoc5ajGjPrn4Vb3huNLTXkfpqFdSi3YKLo4fNspe
         gtURSs/berHTUGcATTiMSeRxLx4jjchVkbougDhuxTeEjFj2Z4tIM6cOjQvCQOo7iRUm
         +NENPxkVCxyyKRtTJmDfNpujZewtYV/98NBs5/A0ObjQD6taQXXNwoOYQDYM0KQZIXdq
         l0dHMvUnCYaAcydlXZlKvDntMqvIb3oDo6CgZ0TuL+K3cv+GwMIVAAjSMwQQb0fJm7oa
         +JWW/yKapv5PqTzacKed40rPVs+6KpkS6+/6nFZaE9apHqa1kIsz0Xh7afGyg28k1BOR
         UJ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Bo43bOuMZQDIM4sDpIggNnp9SFpreqwkD0ha84N+llA=;
        b=OUkjmyoHDRWIvfMOP3O6GryE66v2gKviyAP0mhHDW8M0qt/1774bHn4sMd8Yya+cTs
         R2erRt7fVyPb8LNuGRIXc2E2XRJ2iasKZz6cCzpw+o1jHkPZB9pR+ZfMGQ+lA60/04lh
         /RlFVIN2Cdb/REddWLyhg4ENUQWIuUQH1TKqEt/JKNrVUCGC2+5pJOp/z9cS1BxH77tj
         GgvwX4Ax+RzhMEnsTITDcRWENOPlN5jQ0aHLt4Im/XXnFNwRFklT/gEM/ciL1PbBS3DD
         9F9ccCSHLCHvXHT9Sr/dHr51CE8HygC9/8HtH1PzZ3uEerP8iIAWAnKnNJNG4FI/A74F
         ALKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333ZsLiteYZvHDBqD0EKJTEIWXJ2lSpY9s/hspQ5tzYgIwb3MKK
	Yg6kfI7ntWuh35mpd3uZQrg=
X-Google-Smtp-Source: ABdhPJwf8TOF0jWW4GCX14Y1jmyvfIaW6h0akSZI2J+Zz+wYld8aQPVWyIm07QluPJSJ4Ad4LRbfMQ==
X-Received: by 2002:a05:6e02:ea3:: with SMTP id u3mr6900361ilj.49.1597510798910;
        Sat, 15 Aug 2020 09:59:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7308:: with SMTP id e8ls2025130ioh.6.gmail; Sat, 15 Aug
 2020 09:59:58 -0700 (PDT)
X-Received: by 2002:a6b:591a:: with SMTP id n26mr6271785iob.122.1597510798623;
        Sat, 15 Aug 2020 09:59:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597510798; cv=none;
        d=google.com; s=arc-20160816;
        b=eqzySmE2GLAQDI6ilRLdPOdK0aIlIoItz/cxcuEMVaDIbsB73vBH/ABxuVY2+9QGCV
         tDghjOF4WW1QDEtc9RAI5kunq6EJ7TJ6ZWff+o1+Ck4Hr5+ZZJueFfHsRj+J1fiNud8i
         Qjhv7UUITtUSVBkti0I3irUJjg9vgB/up4xzPp+wGpWoUwBDF8KJLOdjo4IMM4KIgQcq
         E2OaScwUonhY1rLXJM2u+aRUlaGV7crqUscXyTdwOfa4TFL517ah5lY67BzFZcv28AoH
         xc5OlSqrxqYaH9c+/9kw2FYCXnROzKaEFfMhal96XF4sbz5mJetAaOrhly2cHxf4w7Zc
         8nIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Rb/IMQYAMEFrYCtyEvFVd8k7Hv2cYtIwx71PE3QM1p8=;
        b=0OzcfHUBlAm8PfYp/mhFal2wd5JZICZpmAxrTyhftxDZifkGo2Hx4yLNYrUe/mEFm0
         pjlu/ibQ06VEnoMjuet1t51MJFM2zQqMbWtPFY51LYgWLCCpbvJcnso9NKKhki++LSHC
         JY+a/L+gr+9bR/TU9MzNQXSbMz/PHe+zupkKVfhGDKhCFPVbQKf4w28f/CnEqx3sOB7Z
         znDV6xRbJfGk76t1eAT003O3P/HvoPMGna36l/um9qdizMo0WCH2UUN12q096/EPz9XX
         3MorQ8KvxLOWxU+smM/PNAA6eF+aJwjrjDwOOnqGXiAHm1F2EDj659zNWlqP1aMbaoio
         Z6Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bp6qJV4D;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id z7si615209ilm.3.2020.08.15.09.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 15 Aug 2020 09:59:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id t11so5514138plr.5
        for <kasan-dev@googlegroups.com>; Sat, 15 Aug 2020 09:59:58 -0700 (PDT)
X-Received: by 2002:a17:90a:e986:: with SMTP id v6mr6862878pjy.88.1597510798065;
        Sat, 15 Aug 2020 09:59:58 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id d127sm12507740pfc.175.2020.08.15.09.59.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 15 Aug 2020 09:59:57 -0700 (PDT)
Date: Sat, 15 Aug 2020 09:59:56 -0700
From: Kees Cook <keescook@chromium.org>
To: Alexander Popov <alex.popov@linux.com>
Cc: Jann Horn <jannh@google.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com, linux-kernel@vger.kernel.org,
	notify@kernel.org
Subject: Re: [PATCH RFC 2/2] lkdtm: Add heap spraying test
Message-ID: <202008150952.E81C4A52F@keescook>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-3-alex.popov@linux.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200813151922.1093791-3-alex.popov@linux.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=bp6qJV4D;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Aug 13, 2020 at 06:19:22PM +0300, Alexander Popov wrote:
> Add a simple test for CONFIG_SLAB_QUARANTINE.
> 
> It performs heap spraying that aims to reallocate the recently freed heap
> object. This technique is used for exploiting use-after-free
> vulnerabilities in the kernel code.
> 
> This test shows that CONFIG_SLAB_QUARANTINE breaks heap spraying
> exploitation technique.

Yay tests!

> 
> Signed-off-by: Alexander Popov <alex.popov@linux.com>
> ---
>  drivers/misc/lkdtm/core.c  |  1 +
>  drivers/misc/lkdtm/heap.c  | 40 ++++++++++++++++++++++++++++++++++++++
>  drivers/misc/lkdtm/lkdtm.h |  1 +
>  3 files changed, 42 insertions(+)
> 
> diff --git a/drivers/misc/lkdtm/core.c b/drivers/misc/lkdtm/core.c
> index a5e344df9166..78b7669c35eb 100644
> --- a/drivers/misc/lkdtm/core.c
> +++ b/drivers/misc/lkdtm/core.c
> @@ -126,6 +126,7 @@ static const struct crashtype crashtypes[] = {
>  	CRASHTYPE(SLAB_FREE_DOUBLE),
>  	CRASHTYPE(SLAB_FREE_CROSS),
>  	CRASHTYPE(SLAB_FREE_PAGE),
> +	CRASHTYPE(HEAP_SPRAY),
>  	CRASHTYPE(SOFTLOCKUP),
>  	CRASHTYPE(HARDLOCKUP),
>  	CRASHTYPE(SPINLOCKUP),
> diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
> index 1323bc16f113..a72a241e314a 100644
> --- a/drivers/misc/lkdtm/heap.c
> +++ b/drivers/misc/lkdtm/heap.c
> @@ -205,6 +205,46 @@ static void ctor_a(void *region)
>  static void ctor_b(void *region)
>  { }
>  
> +#define HEAP_SPRAY_SIZE 128
> +
> +void lkdtm_HEAP_SPRAY(void)
> +{
> +	int *addr;
> +	int *spray_addrs[HEAP_SPRAY_SIZE] = { 0 };

(the 0 isn't needed -- and it was left there, it should be NULL)

> +	unsigned long i = 0;
> +
> +	addr = kmem_cache_alloc(a_cache, GFP_KERNEL);

I would prefer this test add its own cache (e.g. spray_cache), to avoid
misbehaviors between tests. (e.g. the a and b caches already run the
risk of getting corrupted weirdly.)

> +	if (!addr) {
> +		pr_info("Unable to allocate memory in lkdtm-heap-a cache\n");
> +		return;
> +	}
> +
> +	*addr = 0x31337;
> +	kmem_cache_free(a_cache, addr);
> +
> +	pr_info("Performing heap spraying...\n");
> +	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
> +		spray_addrs[i] = kmem_cache_alloc(a_cache, GFP_KERNEL);
> +		*spray_addrs[i] = 0x31337;
> +		pr_info("attempt %lu: spray alloc addr %p vs freed addr %p\n",
> +						i, spray_addrs[i], addr);

That's 128 lines spewed into dmesg... I would leave this out.

> +		if (spray_addrs[i] == addr) {
> +			pr_info("freed addr is reallocated!\n");
> +			break;
> +		}
> +	}
> +
> +	if (i < HEAP_SPRAY_SIZE)
> +		pr_info("FAIL! Heap spraying succeed :(\n");

I'd move this into the "if (spray_addrs[i] == addr)" test instead of the
pr_info() that is there.

> +	else
> +		pr_info("OK! Heap spraying hasn't succeed :)\n");

And then make this an "if (i == HEAP_SPRAY_SIZE)" test

> +
> +	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
> +		if (spray_addrs[i])
> +			kmem_cache_free(a_cache, spray_addrs[i]);
> +	}
> +}
> +
>  void __init lkdtm_heap_init(void)
>  {
>  	double_free_cache = kmem_cache_create("lkdtm-heap-double_free",
> diff --git a/drivers/misc/lkdtm/lkdtm.h b/drivers/misc/lkdtm/lkdtm.h
> index 8878538b2c13..dfafb4ae6f3a 100644
> --- a/drivers/misc/lkdtm/lkdtm.h
> +++ b/drivers/misc/lkdtm/lkdtm.h
> @@ -45,6 +45,7 @@ void lkdtm_READ_BUDDY_AFTER_FREE(void);
>  void lkdtm_SLAB_FREE_DOUBLE(void);
>  void lkdtm_SLAB_FREE_CROSS(void);
>  void lkdtm_SLAB_FREE_PAGE(void);
> +void lkdtm_HEAP_SPRAY(void);
>  
>  /* lkdtm_perms.c */
>  void __init lkdtm_perms_init(void);
> -- 
> 2.26.2
> 

I assume enabling the quarantine defense also ends up being seen in the
SLAB_FREE_DOUBLE LKDTM test too, yes?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202008150952.E81C4A52F%40keescook.
