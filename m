Return-Path: <kasan-dev+bncBDJILRGJQEERBH5K3H5AKGQEU3NJLOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D0A1225FD53
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 17:43:27 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id l22sf4262979lji.23
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 08:43:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599493407; cv=pass;
        d=google.com; s=arc-20160816;
        b=dEAiuW6ry5lkisJ0LGnzDUabShAGHFORiGH0q2Nm3zNOiAM9u/N1yUoH7z+2HzoJsk
         TZ7Al8a+rlROAdeAv/8W2rzkzfpPNO/lBIcXXgNncdbZADBayssKO8k6sHbq6gDV3ivL
         DxY7plluiHMOdeviNEygSHUXH6seI7zkAbYyF7lrTQY+gxds9udkQGhfd2OkTSzHcvSa
         CsiUc8gFz+HpmJH3SL4KIdY162ww9Gv9x+5l2F9mgFUTo3Jr+rEc+6LINXt808husdU4
         ul02iR7FxS5naeTroSRvKA34oE6MqcwOsx7ga3/gbvY4/mAr5S30A3PaPP7HMYdrGWuc
         05Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:organization
         :references:in-reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sY3s5++krQOPANCSsA9t4z7hKy+78YHG3x7ruENGmMQ=;
        b=mq5RuitVHfS8sSUpx61Ht/SmZFhTHmJLPJBGTCVGM6ijKKNZr5s0ucUDQ9XXLeolqv
         XvIOhsumrunTvTZe5mBJHbEu7KGmos8coZppv4uNOo2UztQdPjg+cmmXPdhMnGmMg6DA
         /AgVN5xvSVjJnu+rHN6LmNI6mplvh0PQuqaVcdFFxm3R8eoh9KSk2ok3MQxWLj8LyIYJ
         hDSVg24B06yit9AlXn1HlPnaXgYTg9Dg5dguzVwtjDS9U2sja6UhywfLHeF4mJYNxFMa
         Xw8KLrMeDbTLWZkGIU7gJL90b2A18I2qOd7QK4JgmJUUdvZqvXgE9n0VbHgx6ynhUhmp
         xnBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jonathan.cameron@huawei.com designates 185.176.76.210 as permitted sender) smtp.mailfrom=jonathan.cameron@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :organization:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sY3s5++krQOPANCSsA9t4z7hKy+78YHG3x7ruENGmMQ=;
        b=Ez21vyBY+E5gN1Cb6RacjSeqPaIPIcd+rlBbEJdA8Rfxx4gbgRkYaPJYXTvAywbsqZ
         8nax3h5Cs5yo9h0TLniTAG0YuaarYVC2kb7JhfwrwJVXS2JYjWkns2aMJ0ZDPCsqsvYs
         w/bSCQqYGlOL1sVIzGCJgj7MUzAmHViksfA9udiD32Tu1cZK+R6B+tc0cZ5SXlMdGSIv
         rEKFkSYHqg0HPTFGnhBSwP3eHhqQNlWUy+dOsYA3zx84NOTuAVAL+HKJ7TdgZorKm7WX
         1kVHDnV1jUKM7F8uR6tANxjDCyMLAfmAjNTph82s1SKp4XchNxCh59Oteieox+1y2JIL
         vqtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:organization:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sY3s5++krQOPANCSsA9t4z7hKy+78YHG3x7ruENGmMQ=;
        b=A/yr85s58mdY3cv7ljKOEB/Fgo+mj9II0T49WzoFgtjCVjif6yIxDnousknfBNlBVJ
         bXPH+NRk805FwrLHYwpPJtV7RdZLlRqIVUv0UWu5n7TFHuW9iXcbg+VU4P6CQ+5e1rAe
         1ailVDQ7RAsY8LQuILpeSoakN6BSIdhbXBE3tp26Dz+hhCx1m0mBJ52hbVwAdiVEE3ly
         2beScz113Kyb3lbfiGW8mN7xA0Ii1gKOXQmHijU5jSl9BTH9RLn7R++776RSqXBdpEN+
         t8Vr7JB0dhHORQgM1llf2Yzds3cRZcNizD72Rl8XVVniXrYyrfaZTR6uEk9t2Om7Fjsb
         dIxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gJBPeq9xnU9cfEnr6L89wBtxHmljP+bfqJaY024SXBoMwVJ3D
	ynRXCEpvMUcza8e4s4Sih/I=
X-Google-Smtp-Source: ABdhPJyd9XA0eJxTybzz++zqoFnsJgrGzrCCMVmZR1fGmrarHDAGisWtyMDN5KbqCH7Ulh9NV/cExg==
X-Received: by 2002:a2e:9b09:: with SMTP id u9mr11293793lji.194.1599493407224;
        Mon, 07 Sep 2020 08:43:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls1863967lff.0.gmail; Mon, 07
 Sep 2020 08:43:26 -0700 (PDT)
X-Received: by 2002:a19:4356:: with SMTP id m22mr10374156lfj.21.1599493405914;
        Mon, 07 Sep 2020 08:43:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599493405; cv=none;
        d=google.com; s=arc-20160816;
        b=WzZXMKcJKH4kA+Xcri0KfXvGPvceparICYhn+DkJ08TPvxdSIVdEgrq3v+lHQs80XT
         6QtUpkh/i9h1/tiwMqx6wT+ImhTM0IDGXmy8RRCR4EF2Z/avMxmbThyvOKj1OBbQeWL4
         4ee5HgX9KbNMyEDibVZ3aUSoWBV3RbYpw2ovummYhDgwDiBxP4jSAoklhfGLgTjzcD+I
         5iP6uyV4sN/D6Tr06o1QKeAB+H+3HEp+rztGhxICWl9C23smhAENZ2gdS0yX217fV6vS
         ei7mSlxRpG1YErqmPBAOZBgYOktM9GyR0BEQUVEH7juqiXlnSSQenHhM0KE8lcAVKP2Y
         56wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:organization:references
         :in-reply-to:message-id:subject:cc:to:from:date;
        bh=uNitiqLT4S6ZC8ZVtpttpxmLs2NOqdawgWUzJCXSOqg=;
        b=JAOJVlbTc6YcVf6Ni76qv1H+h/kVmNcbbWg3QUir5Hn8taNwaGZtqbuXMeZdcRnm7c
         UQvtsKBLTlQVzJ2ERRUplx2k9HHsU/o33yD3bXDUXAKrj2bPMPkmjk1jJJ8in+OcEnkG
         66J1ccvgFoUkxD9wQPV3Sf3wln7JJIqXE5UqchNtDEgetG7Qg0BM9KqEq3AVp4tvTu3a
         ctZQVviUfuT28/mgI71bgac4w+lG8PYG0ecpWm9qknm68+sGxkSvwtHXselfUDZdUdfO
         RTweV8ZY+w7Unt5YNzHJ09ePuipJ82rx3ADdYjOdgwWsCHPE3d+RSGMsLhtRSgwBxry/
         uMeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jonathan.cameron@huawei.com designates 185.176.76.210 as permitted sender) smtp.mailfrom=jonathan.cameron@huawei.com
Received: from huawei.com (lhrrgout.huawei.com. [185.176.76.210])
        by gmr-mx.google.com with ESMTPS id r6si60571lji.4.2020.09.07.08.43.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Sep 2020 08:43:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jonathan.cameron@huawei.com designates 185.176.76.210 as permitted sender) client-ip=185.176.76.210;
Received: from lhreml710-chm.china.huawei.com (unknown [172.18.7.107])
	by Forcepoint Email with ESMTP id 74F9B4109E8431945181;
	Mon,  7 Sep 2020 16:43:24 +0100 (IST)
Received: from localhost (10.52.124.38) by lhreml710-chm.china.huawei.com
 (10.201.108.61) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id 15.1.1913.5; Mon, 7 Sep 2020
 16:43:23 +0100
Date: Mon, 7 Sep 2020 16:41:48 +0100
From: Jonathan Cameron <Jonathan.Cameron@Huawei.com>
To: Marco Elver <elver@google.com>
CC: <glider@google.com>, <akpm@linux-foundation.org>,
	<catalin.marinas@arm.com>, <cl@linux.com>, <rientjes@google.com>,
	<iamjoonsoo.kim@lge.com>, <mark.rutland@arm.com>, <penberg@kernel.org>,
	<hpa@zytor.com>, <paulmck@kernel.org>, <andreyknvl@google.com>,
	<aryabinin@virtuozzo.com>, <luto@kernel.org>, <bp@alien8.de>,
	<dave.hansen@linux.intel.com>, <dvyukov@google.com>, <edumazet@google.com>,
	<gregkh@linuxfoundation.org>, <mingo@redhat.com>, <jannh@google.com>,
	<corbet@lwn.net>, <keescook@chromium.org>, <peterz@infradead.org>,
	<cai@lca.pw>, <tglx@linutronix.de>, <will@kernel.org>, <x86@kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mm@kvack.org>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20200907164148.00007899@Huawei.com>
In-Reply-To: <20200907134055.2878499-2-elver@google.com>
References: <20200907134055.2878499-1-elver@google.com>
	<20200907134055.2878499-2-elver@google.com>
Organization: Huawei Technologies Research and Development (UK) Ltd.
X-Mailer: Claws Mail 3.17.4 (GTK+ 2.24.32; i686-w64-mingw32)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.52.124.38]
X-ClientProxiedBy: lhreml709-chm.china.huawei.com (10.201.108.58) To
 lhreml710-chm.china.huawei.com (10.201.108.61)
X-CFilter-Loop: Reflected
X-Original-Sender: jonathan.cameron@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jonathan.cameron@huawei.com designates 185.176.76.210
 as permitted sender) smtp.mailfrom=jonathan.cameron@huawei.com
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

On Mon, 7 Sep 2020 15:40:46 +0200
Marco Elver <elver@google.com> wrote:

> From: Alexander Potapenko <glider@google.com>
> 
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.
> 
> KFENCE is designed to be enabled in production kernels, and has near
> zero performance overhead. Compared to KASAN, KFENCE trades performance
> for precision. The main motivation behind KFENCE's design, is that with
> enough total uptime KFENCE will detect bugs in code paths not typically
> exercised by non-production test workloads. One way to quickly achieve a
> large enough total uptime is when the tool is deployed across a large
> fleet of machines.
> 
> KFENCE objects each reside on a dedicated page, at either the left or
> right page boundaries. The pages to the left and right of the object
> page are "guard pages", whose attributes are changed to a protected
> state, and cause page faults on any attempted access to them. Such page
> faults are then intercepted by KFENCE, which handles the fault
> gracefully by reporting a memory access error.
> 
> Guarded allocations are set up based on a sample interval (can be set
> via kfence.sample_interval). After expiration of the sample interval, a
> guarded allocation from the KFENCE object pool is returned to the main
> allocator (SLAB or SLUB). At this point, the timer is reset, and the
> next allocation is set up after the expiration of the interval.
> 
> To enable/disable a KFENCE allocation through the main allocator's
> fast-path without overhead, KFENCE relies on static branches via the
> static keys infrastructure. The static branch is toggled to redirect the
> allocation to KFENCE. To date, we have verified by running synthetic
> benchmarks (sysbench I/O workloads) that a kernel compiled with KFENCE
> is performance-neutral compared to the non-KFENCE baseline.
> 
> For more details, see Documentation/dev-tools/kfence.rst (added later in
> the series).
> 
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Interesting bit of work. A few trivial things inline I spotted whilst having
a first read through.

Thanks,

Jonathan

> +
> +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
> +{
> +	/*
> +	 * Note: for allocations made before RNG initialization, will always
> +	 * return zero. We still benefit from enabling KFENCE as early as
> +	 * possible, even when the RNG is not yet available, as this will allow
> +	 * KFENCE to detect bugs due to earlier allocations. The only downside
> +	 * is that the out-of-bounds accesses detected are deterministic for
> +	 * such allocations.
> +	 */
> +	const bool right = prandom_u32_max(2);
> +	unsigned long flags;
> +	struct kfence_metadata *meta = NULL;
> +	void *addr = NULL;

I think this is set in all paths, so no need to initialize here.

> +
> +	/* Try to obtain a free object. */
> +	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> +	if (!list_empty(&kfence_freelist)) {
> +		meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
> +		list_del_init(&meta->list);
> +	}
> +	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> +	if (!meta)
> +		return NULL;
> +
> +	if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
> +		/*
> +		 * This is extremely unlikely -- we are reporting on a
> +		 * use-after-free, which locked meta->lock, and the reporting
> +		 * code via printk calls kmalloc() which ends up in
> +		 * kfence_alloc() and tries to grab the same object that we're
> +		 * reporting on. While it has never been observed, lockdep does
> +		 * report that there is a possibility of deadlock. Fix it by
> +		 * using trylock and bailing out gracefully.
> +		 */
> +		raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> +		/* Put the object back on the freelist. */
> +		list_add_tail(&meta->list, &kfence_freelist);
> +		raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> +
> +		return NULL;
> +	}
> +
> +	meta->addr = metadata_to_pageaddr(meta);
> +	/* Unprotect if we're reusing this page. */
> +	if (meta->state == KFENCE_OBJECT_FREED)
> +		kfence_unprotect(meta->addr);
> +
> +	/* Calculate address for this allocation. */
> +	if (right)
> +		meta->addr += PAGE_SIZE - size;
> +	meta->addr = ALIGN_DOWN(meta->addr, cache->align);
> +
> +	/* Update remaining metadata. */
> +	metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
> +	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
> +	WRITE_ONCE(meta->cache, cache);
> +	meta->size = right ? -size : size;
> +	for_each_canary(meta, set_canary_byte);
> +	virt_to_page(meta->addr)->slab_cache = cache;
> +
> +	raw_spin_unlock_irqrestore(&meta->lock, flags);
> +
> +	/* Memory initialization. */
> +
> +	/*
> +	 * We check slab_want_init_on_alloc() ourselves, rather than letting
> +	 * SL*B do the initialization, as otherwise we might overwrite KFENCE's
> +	 * redzone.
> +	 */
> +	addr = (void *)meta->addr;
> +	if (unlikely(slab_want_init_on_alloc(gfp, cache)))
> +		memzero_explicit(addr, size);
> +	if (cache->ctor)
> +		cache->ctor(addr);
> +
> +	if (CONFIG_KFENCE_FAULT_INJECTION && !prandom_u32_max(CONFIG_KFENCE_FAULT_INJECTION))
> +		kfence_protect(meta->addr); /* Random "faults" by protecting the object. */
> +
> +	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCATED]);
> +	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCS]);
> +
> +	return addr;
> +}

...

> +
> +size_t kfence_ksize(const void *addr)
> +{
> +	const struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> +
> +	/*
> +	 * Read locklessly -- if there is a race with __kfence_alloc(), this
> +	 * most certainly is either a use-after-free, or invalid access.
> +	 */
> +	return meta ? abs(meta->size) : 0;
> +}
> +
> +void *kfence_object_start(const void *addr)
> +{
> +	const struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> +
> +	/*
> +	 * Read locklessly -- if there is a race with __kfence_alloc(), this
> +	 * most certainly is either a use-after-free, or invalid access.

To my reading using "most certainly" makes this statement less clear

Read locklessly -- if there is a race with __kfence_alloc() this
is either a use-after-free or invalid access.

Same for other cases of that particular "most certainly".

> +	 */
> +	return meta ? (void *)meta->addr : NULL;
> +}
> +
> +void __kfence_free(void *addr)
> +{
> +	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> +
> +	if (unlikely(meta->cache->flags & SLAB_TYPESAFE_BY_RCU))
> +		call_rcu(&meta->rcu_head, rcu_guarded_free);
> +	else
> +		kfence_guarded_free(addr, meta);
> +}
> +
> +bool kfence_handle_page_fault(unsigned long addr)
> +{
> +	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
> +	struct kfence_metadata *to_report = NULL;
> +	enum kfence_error_type error_type;
> +	unsigned long flags;
> +
> +	if (!is_kfence_address((void *)addr))
> +		return false;
> +
> +	if (!READ_ONCE(kfence_enabled)) /* If disabled at runtime ... */
> +		return kfence_unprotect(addr); /* ... unprotect and proceed. */
> +
> +	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
> +
> +	if (page_index % 2) {
> +		/* This is a redzone, report a buffer overflow. */
> +		struct kfence_metadata *meta = NULL;

Not need to set to NULL here as assigned 3 lines down.

> +		int distance = 0;
> +
> +		meta = addr_to_metadata(addr - PAGE_SIZE)

> +		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
> +			to_report = meta;
> +			/* Data race ok; distance calculation approximate. */
> +			distance = addr - data_race(meta->addr + abs(meta->size));
> +		}
> +
> +		meta = addr_to_metadata(addr + PAGE_SIZE);
> +		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
> +			/* Data race ok; distance calculation approximate. */
> +			if (!to_report || distance > data_race(meta->addr) - addr)
> +				to_report = meta;
> +		}
> +
> +		if (!to_report)
> +			goto out;
> +
> +		raw_spin_lock_irqsave(&to_report->lock, flags);
> +		to_report->unprotected_page = addr;
> +		error_type = KFENCE_ERROR_OOB;
> +
> +		/*
> +		 * If the object was freed before we took the look we can still
> +		 * report this as an OOB -- the report will simply show the
> +		 * stacktrace of the free as well.
> +		 */
> +	} else {
> +		to_report = addr_to_metadata(addr);
> +		if (!to_report)
> +			goto out;
> +
> +		raw_spin_lock_irqsave(&to_report->lock, flags);
> +		error_type = KFENCE_ERROR_UAF;
> +		/*
> +		 * We may race with __kfence_alloc(), and it is possible that a
> +		 * freed object may be reallocated. We simply report this as a
> +		 * use-after-free, with the stack trace showing the place where
> +		 * the object was re-allocated.
> +		 */
> +	}
> +
> +out:
> +	if (to_report) {
> +		kfence_report_error(addr, to_report, error_type);
> +		raw_spin_unlock_irqrestore(&to_report->lock, flags);
> +	} else {
> +		/* This may be a UAF or OOB access, but we can't be sure. */
> +		kfence_report_error(addr, NULL, KFENCE_ERROR_INVALID);
> +	}
> +
> +	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
> +}
...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907164148.00007899%40Huawei.com.
