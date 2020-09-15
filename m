Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYMYQP5QKGQE4EBTCJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DB98826A6E3
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 16:14:57 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id g6sf1291513wrv.3
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 07:14:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600179297; cv=pass;
        d=google.com; s=arc-20160816;
        b=sDvhvWx/6vbycsq9kuPaWL0Fk5Zug7gSSaOfkmdeALlEZIWEM8s37euZdaXLWhYNU7
         Ardsx3ZoA/sfIW4FcApORGu8jOSh7o8YPpYqsWukA5SWTzvW+EAx6tq5h50s2kNM8Nt1
         w1RxVvBtYLeKxkUcypV+KiuB/sXxDH0KNystDCfTQ/d4PHoU1flhhVc+vVLbRl+7on1A
         Mz3hHWoqA4TZbOhT9BnKKTGNjTiBFsMEmx2DNo8Qlcdrs9NENrQQv+JELOtUHJ1hkDfY
         jGzZGPBHt8c+sUhTx4WDMmLtnYalekn8aOfx1uYZF0R+8B0QBFmSw6dohP+Oe37RP4aT
         tM+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=kLVO8yR7mmTl1HC8dJYro/f3UJq9cLvOMVbdCRm6nu4=;
        b=VA47TIBximNAD9z1VpPe2w7Xqb6chzC9chdhIilv4TtrZ5/m8QWUldlrSwkquayuuh
         jg0aRUnaFe6w32Tl06aR1digbOGGY+pJWU1wx43VE2ao/s92POZXyP7XRGGa3DvIBiDw
         hKCgg09uZcdn8NsQ4Ey+/rjUH1y3dDY0ESTeNPGyZ4/nUW8lb9cAu5MrTqiuW7CF9CCO
         4MYKemZ8YWvN6kaQjLD/dYLiT+wNfI9GWZf+ZyfM6Y9sKGNLPdJ12641ir/UrXI/T2Oq
         s/YnpEIenpghPRvv+Jk1C85rpeLhcAIREpDpuJ2FXI54gJwMG8Pn67xId4FksKjk+2gW
         lsNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H8nL+xfr;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=kLVO8yR7mmTl1HC8dJYro/f3UJq9cLvOMVbdCRm6nu4=;
        b=sP/ZeeiLK3wYUjTOrzkjPDAulhTnkvHjvLLlT54qbkscTDgeXCJJwRE02d9UOFuIm+
         4fJ9IBQ1SLQuJlwsA4637CDwtnm/fVNgKQBKdFira+iGSsRM3ZfYES5oO2qGBHC9uY8j
         jhftfqel0tmitLNgkL8Ecp+K8E18u2Uc/XGaSpcEewmZxeXfn1Xd/FuuB5HMn4LFsomY
         tur6XUVtKDXJnV3dAi7DcQiPmCFWsD0MjudWAAN2376YqvVMFpl849sP484zViZTQz2i
         ERw5ZopGm3fHj/sN1oLlnkzj+G+HmKVNCyB1e5Tf36IJI905mJEuGH15ODnRquEG5qWQ
         j8Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kLVO8yR7mmTl1HC8dJYro/f3UJq9cLvOMVbdCRm6nu4=;
        b=CQKZ+zyKtqmVjQuObPAhAVWyBx36y3ucyaVqtaFZLQl/K+t/jebKCzKHWvy/Yvutbx
         fBFtZ3Qt6/qf9MIZa0OtHVH9Lh6yrxAR5xqESWEHvAEzLQCjyTcIfZB8FY0GnwF0bLoW
         sL0hXlq0zfc6xVi1vptstLjUZqGskQ2J0gTH4DObXocQpYEiPJypwkjJqOyL+znxBcC8
         PJQ5+Xt/2FhfNLwWk+OgzbQi5ubOlKmbE42H2OqJxdK04WmaNnseEt6OAlApL6P5xOij
         KY8a+jujnEn/YUUmB1zScSywInz8sJ56wxQetLDc3ngV1+sm+y0WsN3QposCLDrO4GWL
         0QvA==
X-Gm-Message-State: AOAM533hrp61iE8XZk1n71Nnn2STS2nWICLcd/5miZpLbpvo+8m1ZaZe
	495onpBnAp65V2AWmTA3+mw=
X-Google-Smtp-Source: ABdhPJxtbNnaDUNWKqQRVPIvrLEBgl3DpkVnf6S71sl3lsK5TOJK68dEJLUBtdG2sR8CTdnjIlj3Ag==
X-Received: by 2002:a7b:c1d9:: with SMTP id a25mr5235668wmj.4.1600179297593;
        Tue, 15 Sep 2020 07:14:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:81d4:: with SMTP id c203ls1592565wmd.1.gmail; Tue, 15
 Sep 2020 07:14:56 -0700 (PDT)
X-Received: by 2002:a1c:1d08:: with SMTP id d8mr5208968wmd.78.1600179296645;
        Tue, 15 Sep 2020 07:14:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600179296; cv=none;
        d=google.com; s=arc-20160816;
        b=BOY8s/dFxnzVv+KKfFGSFeoV73TvPIFqU6liOtJzgVoX7+nPlHvdtt3NvXyj/GivZz
         m+SL0NEt5RZGk+XBYogAOQJH3w/X56AcGKpFG/x1Xj3XhSDUTIiMu6E+Qip+cBL6/ksA
         1kmpVqaHhJXqljudg/xUlkOwa9ok0tWSiGRFyRNqC04GxL8qLJPOuQ0BJFBbkn9/UtuW
         0+JpIFcwJyVJcVWSnRv7gfmVKCQ09NJ6uD8yhD2HyEaqNvnV3PZwuR7ZA/jmNz4dYe8W
         hPNN/z5AgKLWtzMaoPPZhNr7eOF1o8ehilQaIyPPeEGpY7ZHk2PJ/ZXR8I5Z06PuE+dX
         70hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=iCaVZIoES6nQdU1krWtYyw9RTOkMnShVAEcHdPRqonk=;
        b=W8irfI3YNmTKzWHLhIST4oGQYnE0ZgnTAQ13WCnZjXJil8jgEkkS418QeveZS6C3Kv
         67iDn6/SyQQKrM7R+98D4NskrXYOQfHF9ZhfsYQ/8Rn07HTaOgIa/psZnjM4SWfY7Z+B
         hVe5MRQVtQpXSHIXOegEeSZqiEXz9tzryZqFD96JipLJk54l3JyUDo/YJHc2oMlnmID5
         V55/nHbAa2/RIU6rGvM9xtwxZklW0iA1MPojjmiGE/0LbUX2u0bWbAxES7DY/fRnCEWF
         CjKziCRywprzC2Z5aI5aRr4hUQuzfHgHe9GERBK7t8p7mfV4fvaaeFS+kIm0q6FFJwo4
         v65g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H8nL+xfr;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id b1si418114wmj.1.2020.09.15.07.14.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 07:14:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id m6so3554660wrn.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 07:14:56 -0700 (PDT)
X-Received: by 2002:adf:df05:: with SMTP id y5mr23640721wrl.39.1600179295984;
        Tue, 15 Sep 2020 07:14:55 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id k6sm23222807wmi.1.2020.09.15.07.14.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Sep 2020 07:14:55 -0700 (PDT)
Date: Tue, 15 Sep 2020 16:14:49 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: SeongJae Park <sjpark@amazon.com>
Cc: glider@google.com, akpm@linux-foundation.org, catalin.marinas@arm.com,
	cl@linux.com, rientjes@google.com, iamjoonsoo.kim@lge.com,
	mark.rutland@arm.com, penberg@kernel.org, linux-doc@vger.kernel.org,
	peterz@infradead.org, dave.hansen@linux.intel.com,
	linux-mm@kvack.org, edumazet@google.com, hpa@zytor.com,
	will@kernel.org, corbet@lwn.net, x86@kernel.org,
	kasan-dev@googlegroups.com, mingo@redhat.com,
	linux-arm-kernel@lists.infradead.org, aryabinin@virtuozzo.com,
	keescook@chromium.org, paulmck@kernel.org, jannh@google.com,
	andreyknvl@google.com, cai@lca.pw, luto@kernel.org,
	tglx@linutronix.de, dvyukov@google.com, gregkh@linuxfoundation.org,
	linux-kernel@vger.kernel.org, bp@alien8.de
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20200915141449.GA3367763@elver.google.com>
References: <20200907134055.2878499-2-elver@google.com>
 <20200915135754.24329-1-sjpark@amazon.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200915135754.24329-1-sjpark@amazon.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H8nL+xfr;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
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

On Tue, Sep 15, 2020 at 03:57PM +0200, SeongJae Park wrote:
[...]
> 
> So interesting feature!  I left some tirvial comments below.

Thank you!

> [...]
> > diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> > new file mode 100644
> > index 000000000000..7ac91162edb0
> > --- /dev/null
> > +++ b/lib/Kconfig.kfence
> > @@ -0,0 +1,58 @@
> > +# SPDX-License-Identifier: GPL-2.0-only
> > +
> > +config HAVE_ARCH_KFENCE
> > +	bool
> > +
> > +config HAVE_ARCH_KFENCE_STATIC_POOL
> > +	bool
> > +	help
> > +	  If the architecture supports using the static pool.
> > +
> > +menuconfig KFENCE
> > +	bool "KFENCE: low-overhead sampling-based memory safety error detector"
> > +	depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
> > +	depends on JUMP_LABEL # To ensure performance, require jump labels
> > +	select STACKTRACE
> > +	help
> > +	  KFENCE is low-overhead sampling-based detector for heap out-of-bounds
> > +	  access, use-after-free, and invalid-free errors. KFENCE is designed
> > +	  to have negligible cost to permit enabling it in production
> > +	  environments.
> > +
> > +	  See <file:Documentation/dev-tools/kfence.rst> for more details.
> 
> This patch doesn't provide the file yet.  Why don't you add the reference with
> the patch introducing the file?

Sure, will fix for v3.

> > +
> > +	  Note that, KFENCE is not a substitute for explicit testing with tools
> > +	  such as KASAN. KFENCE can detect a subset of bugs that KASAN can
> > +	  detect (therefore enabling KFENCE together with KASAN does not make
> > +	  sense), albeit at very different performance profiles.
> [...]
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > new file mode 100644
> > index 000000000000..e638d1f64a32
> > --- /dev/null
> > +++ b/mm/kfence/core.c
> > @@ -0,0 +1,730 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +
> > +#define pr_fmt(fmt) "kfence: " fmt
> [...]
> > +
> > +static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
> > +{
> > +	long index;
> > +
> > +	/* The checks do not affect performance; only called from slow-paths. */
> > +
> > +	if (!is_kfence_address((void *)addr))
> > +		return NULL;
> > +
> > +	/*
> > +	 * May be an invalid index if called with an address at the edge of
> > +	 * __kfence_pool, in which case we would report an "invalid access"
> > +	 * error.
> > +	 */
> > +	index = ((addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2)) - 1;
> 
> Seems the outermost parentheses unnecessary.

Will fix.

> > +	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
> > +		return NULL;
> > +
> > +	return &kfence_metadata[index];
> > +}
> > +
> > +static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
> > +{
> > +	unsigned long offset = ((meta - kfence_metadata) + 1) * PAGE_SIZE * 2;
> 
> Seems the innermost parentheses unnecessary.

Will fix.

> > +	unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
> > +
> > +	/* The checks do not affect performance; only called from slow-paths. */
> > +
> > +	/* Only call with a pointer into kfence_metadata. */
> > +	if (KFENCE_WARN_ON(meta < kfence_metadata ||
> > +			   meta >= kfence_metadata + ARRAY_SIZE(kfence_metadata)))
> 
> Is there a reason to use ARRAY_SIZE(kfence_metadata) instead of
> CONFIG_KFENCE_NUM_OBJECTS?

They're equivalent. We can switch it. (Although I don't see one being
superior to the other.. maybe we save on compile-time?)

> > +		return 0;
> > +
> > +	/*
> > +	 * This metadata object only ever maps to 1 page; verify the calculation
> > +	 * happens and that the stored address was not corrupted.
> > +	 */
> > +	if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
> > +		return 0;
> > +
> > +	return pageaddr;
> > +}
> [...]
> > +void __init kfence_init(void)
> > +{
> > +	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
> > +	if (!kfence_sample_interval)
> > +		return;
> > +
> > +	if (!kfence_initialize_pool()) {
> > +		pr_err("%s failed\n", __func__);
> > +		return;
> > +	}
> > +
> > +	schedule_delayed_work(&kfence_timer, 0);
> > +	WRITE_ONCE(kfence_enabled, true);
> > +	pr_info("initialized - using %zu bytes for %d objects", KFENCE_POOL_SIZE,
> > +		CONFIG_KFENCE_NUM_OBJECTS);
> > +	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> > +		pr_cont(" at 0x%px-0x%px\n", (void *)__kfence_pool,
> > +			(void *)(__kfence_pool + KFENCE_POOL_SIZE));
> 
> Why don't you use PTR_FMT that defined in 'kfence.h'?

It's unnecessary, since all this is conditional on
IS_ENABLED(CONFIG_DEBUG_KERNEL)) and we can just avoid the indirection
through PTR_FMT.

> > +	else
> > +		pr_cont("\n");
> > +}
> [...]
> > diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> > new file mode 100644
> > index 000000000000..25ce2c0dc092
> > --- /dev/null
> > +++ b/mm/kfence/kfence.h
> > @@ -0,0 +1,104 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +#ifndef MM_KFENCE_KFENCE_H
> > +#define MM_KFENCE_KFENCE_H
> > +
> > +#include <linux/mm.h>
> > +#include <linux/slab.h>
> > +#include <linux/spinlock.h>
> > +#include <linux/types.h>
> > +
> > +#include "../slab.h" /* for struct kmem_cache */
> > +
> > +/* For non-debug builds, avoid leaking kernel pointers into dmesg. */
> > +#ifdef CONFIG_DEBUG_KERNEL
> > +#define PTR_FMT "%px"
> > +#else
> > +#define PTR_FMT "%p"
> > +#endif
> > +
> > +/*
> > + * Get the canary byte pattern for @addr. Use a pattern that varies based on the
> > + * lower 3 bits of the address, to detect memory corruptions with higher
> > + * probability, where similar constants are used.
> > + */
> > +#define KFENCE_CANARY_PATTERN(addr) ((u8)0xaa ^ (u8)((unsigned long)addr & 0x7))
> > +
> > +/* Maximum stack depth for reports. */
> > +#define KFENCE_STACK_DEPTH 64
> > +
> > +/* KFENCE object states. */
> > +enum kfence_object_state {
> > +	KFENCE_OBJECT_UNUSED, /* Object is unused. */
> > +	KFENCE_OBJECT_ALLOCATED, /* Object is currently allocated. */
> > +	KFENCE_OBJECT_FREED, /* Object was allocated, and then freed. */
> 
> Aligning the comments would look better (same to below comments).

Will fix.

> > +};
> [...]
> > diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> > new file mode 100644
> > index 000000000000..8c28200e7433
> > --- /dev/null
> > +++ b/mm/kfence/report.c
> > @@ -0,0 +1,201 @@
> > +// SPDX-License-Identifier: GPL-2.0
> [...]
> > +/* Get the number of stack entries to skip get out of MM internals. */
> > +static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries,
> > +			    enum kfence_error_type type)
> > +{
> > +	char buf[64];
> > +	int skipnr, fallback = 0;
> > +
> > +	for (skipnr = 0; skipnr < num_entries; skipnr++) {
> > +		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
> > +
> > +		/* Depending on error type, find different stack entries. */
> > +		switch (type) {
> > +		case KFENCE_ERROR_UAF:
> > +		case KFENCE_ERROR_OOB:
> > +		case KFENCE_ERROR_INVALID:
> > +			if (!strncmp(buf, KFENCE_SKIP_ARCH_FAULT_HANDLER, len))
> 
> Seems KFENCE_SKIP_ARCH_FAULT_HANDLER not defined yet?

Correct, it'll be defined in <asm/kfence.h> in the x86 and arm64
patches. Leaving this is fine, since no architecture has selected
HAVE_ARCH_KFENCE in this patch yet; as a result, we also can't break the
build even if this is undefined.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915141449.GA3367763%40elver.google.com.
