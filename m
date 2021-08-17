Return-Path: <kasan-dev+bncBCJZRXGY5YJBBRP652EAMGQE64DKWLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D67843EEDC4
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 15:53:10 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id g14-20020a6be60e000000b005b62a0c2a41sf4139217ioh.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 06:53:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629208389; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzJpifGh8/p6srDXgpwmFKZZ5fQTSGcSL+jbpRRrfLEHj6EAZY842X4OLoemuvvwXx
         kTMTisSi2tvzOO/60J3Bxv1/XiUfKHQHrwVXgk17ic7/eddMVnoTGTcNU5FihDwWnFG0
         3tpUawrDG7Js9WYwadUMehHCpC2dz33CARsOqQPmA3DXr1SjdLUH7Szi5bR09dITxbpb
         qd7aBn6wXOD4rlW3K0cbV64vNefw0GP0Xxvm+goNi082FxC30HGTGfTx0/EWkCLnU0uo
         +G37zNnw8064SXGmzMdIcnamdQITQDgaIazlhRFxhYX4PapwBw05d71gQmrkqEfp2pqo
         +nVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=cbliEOVeaLcBxrD+j14FsA+FmehdQ9ZSnHZmB+/oylc=;
        b=C0iP3rZAn3sbU7hB0zcST2YpV19UHJ1OHQYKkPSPBrW0xR+pJmlw3zIOoNGoqiERiP
         eHZnuaEWfhbFnn7g2gmc87BY/ll4hK/aGu2758duNny92n6F5wptZ/76hibjZVUrINsT
         A1PHfaOGwaJxkZkOJWFocVlZEQ0GBbCLxVSPgOa0icuVVnPauDnHxtpND/aMjsVfeK1N
         qUgZKJIY5P69ztX2MCI2v7KNLb2OQIaM5f1xnhhwKaHSVeFk86MIP1Q6OYUCUGSCVBjs
         QEdUZfTIrFK0DLAeQVsvn4cjgtLPP87VrzL+ZYPzjcRNVDOzmhtXYxf9jN/g5dmK1yZ4
         1QEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RgLq2wmV;
       spf=pass (google.com: domain of srs0=54/e=ni=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=54/E=NI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cbliEOVeaLcBxrD+j14FsA+FmehdQ9ZSnHZmB+/oylc=;
        b=gyaCd8MwlIDeRY5Ebzn+T0q+3LZ5RxrOUFimOcwJzpB53kg9AyBg59DIRkt7oxkoKT
         bNJlp+mir9soQORqQzgdBeQOycRd5D4I8P5lP0RghGKacwy2+KF/xZW9d3oOhyxyDvPn
         H/vzJuyIKUfCajjbw14FhHavTLYH7873yQCX6FRsFx5x6g3yZK5Cdbwr2u3JpifDfPG8
         n7S2Kf1Fj+88TbtOWMMlGAvvFcwZHH8NXZuzDZyOsbnwgafcddj49nMC/z3TMqfvGtPa
         7dKm0kDjJogev6W3xUqUa0r4pri6VKej6KbPw6hb+wDqKeNjHNDSQsG+lfScmWKBxl6m
         OM9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cbliEOVeaLcBxrD+j14FsA+FmehdQ9ZSnHZmB+/oylc=;
        b=oIiW69uMoaEuKcPtG3tATAnfIeBR9xfc2bE7JI8ccbGXMqruQbixMF2N27h6ZyEtVd
         y0qH+gsJghDFxfkOhu2q2hYNb3y5E2pSg1gkqXtqhk6/a+rMd+TRxrtOlelCSMth3UQy
         XDHSjcpjPDJaUz7Lts1fUn+PvW/wdRwX6XWM3HgZKOrP9k31CSR+r9N05D0Foi7EEcgE
         URH0/M5aCCAWLgpp/OXYwU8YMcEEzRqVnw5NwkZdEW/YqnQ7SLJed0QPNkTeE6c7aRYF
         3rvfyqfa4nmOCBAcgkX/BEzetO0eyhCPStRImxKxG3uvyP4VDg6d5PVMEHzYIiE/zp7l
         Yq6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gY3NCqGkq2pvjv1rOIPCOHuvkcHWSQ/n7bfO4/AlD4DXN4YTi
	SVEf4hZhU1RK0RPnylUyu9s=
X-Google-Smtp-Source: ABdhPJwZ4zr/cspnJM8KaWs2eq8wDxOO7xx3UxQWl6leFWXWjRptHov6fsX82oGbZ+uUZEHtvK3yPA==
X-Received: by 2002:a92:ad12:: with SMTP id w18mr2449651ilh.3.1629208389498;
        Tue, 17 Aug 2021 06:53:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:81ca:: with SMTP id t10ls348030iol.0.gmail; Tue, 17 Aug
 2021 06:53:09 -0700 (PDT)
X-Received: by 2002:a6b:f111:: with SMTP id e17mr3028165iog.210.1629208389166;
        Tue, 17 Aug 2021 06:53:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629208389; cv=none;
        d=google.com; s=arc-20160816;
        b=PUg/vCoKOo+o3mYaMLnqCC6nLcR+d4zCTWILpoo4WD+m553H5WoW8ydD0pLH7d2SUm
         huWuI8xiXrzhBJRumL4jqQuRI+De9aIng6wfIZYfpnM8nT7X4tzOds8t4dhVzFhNfgGo
         9R7DeXZQm5wxJLOOsGVgpt2sYMq5Vyj3IYF9GkG2tVoIuhIMPWckI496keRarfB2vQm9
         +86NJop5mzptUV7pEFaJBQXs1WxOnFVYPBohtYp6ughBl7k88PJEEt01+q8rwRwHcWHt
         974z/QjLZ8N4t1u1twKsz/hQYWvkR5bfR3dp7YCMr8rk99lkmbYJ+7hDfhlVZewtbWp0
         akKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lwXa7hLga92j3DTdVK260CMxgGblSnsuINtwLzVAD6Q=;
        b=HaH2oOh0LVokWOLB9U3Pk+QbFh72HNWVLYlo3R9ukFKDCLc0EIcjBPeaA0EjZq54oB
         kDhUmVpfUSOHkxhBClbW0alKlo2FuLbW+s5sJ4TKcszcLSltYkP8zwwawBs6TWidThAt
         1prlRMPrU4mEq7XZAEZg21GD+9L6LLTBO+9g2j2pbC1fqZYIPmKeqC0eyzRmXHBQUKXU
         hJBYZhZQNUmne6DceDESQMXmM3jtg5xHc5+Y+E+Xz/UHMqDO6P9RaBJpEaOy3mPM6k7p
         wRcJXc29Pm98pYvwucUiruC1jViIGJbWYlxaeWR1GtL/4mFWW/JTvmvZNDcnNeyIHjKG
         F3CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RgLq2wmV;
       spf=pass (google.com: domain of srs0=54/e=ni=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=54/E=NI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z12si164536iox.0.2021.08.17.06.53.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Aug 2021 06:53:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=54/e=ni=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5145660F58;
	Tue, 17 Aug 2021 13:53:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 20EF05C0F2E; Tue, 17 Aug 2021 06:53:08 -0700 (PDT)
Date: Tue, 17 Aug 2021 06:53:08 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Will Deacon <will@kernel.org>
Cc: Alan Stern <stern@rowland.harvard.edu>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <20210817135308.GO4126399@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com>
 <20210816192109.GC121345@rowland.harvard.edu>
 <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
 <20210817122816.GA12746@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210817122816.GA12746@willie-the-truck>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RgLq2wmV;       spf=pass
 (google.com: domain of srs0=54/e=ni=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=54/E=NI=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Aug 17, 2021 at 01:28:16PM +0100, Will Deacon wrote:
> Just on this bit...
> 
> On Mon, Aug 16, 2021 at 01:50:57PM -0700, Paul E. McKenney wrote:
> > 5.	The dma_mb(), dma_rmb(), and dma_wmb() appear to be specific
> > 	to ARMv8.
> 
> These are useful on other architectures too! IIRC, they were added by x86 in
> the first place. They're designed to be used with dma_alloc_coherent()
> allocations where you're sharing something like a ring buffer with a device
> and they guarantee accesses won't be reordered before they become visible
> to the device. They _also_ provide the same ordering to other CPUs.
> 
> I gave a talk at LPC about some of this, which might help (or might make
> things worse...):
> 
> https://www.youtube.com/watch?v=i6DayghhA8Q

The slides are here, correct?  Nice summary and examples!

https://elinux.org/images/a/a8/Uh-oh-Its-IO-Ordering-Will-Deacon-Arm.pdf

And this is all I see for dma_mb():

arch/arm64/include/asm/barrier.h:#define dma_mb()	dmb(osh)
arch/arm64/include/asm/io.h:#define __iomb()		dma_mb()

And then for __iomb():

arch/arm64/include/asm/io.h:#define __iomb()		dma_mb()
drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.c:	__iomb();

But yes, dma_rmb() and dma_wmb() do look to have a few hundred uses
between them, and not just within ARMv8.  I gave up too soon, so
thank you!

> Ignore the bits about mmiowb() as we got rid of that.

Should the leftovers in current mainline be replaced by wmb()?  Or are
patches to that effect on their way in somewhere?

$ git grep 'mmiowb()'
arch/ia64/include/asm/mmiowb.h:#define mmiowb()	ia64_mfa()
arch/ia64/include/asm/spinlock.h:	mmiowb();
arch/mips/include/asm/mmiowb.h:#define mmiowb()	iobarrier_w()
arch/mips/include/asm/spinlock.h:	mmiowb();
arch/mips/kernel/gpio_txx9.c:	mmiowb();
arch/mips/kernel/gpio_txx9.c:	mmiowb();
arch/mips/kernel/gpio_txx9.c:	mmiowb();
arch/mips/kernel/irq_txx9.c:	mmiowb();
arch/mips/loongson2ef/common/bonito-irq.c:	mmiowb();
arch/mips/loongson2ef/common/bonito-irq.c:	mmiowb();
arch/mips/loongson2ef/common/mem.c:		mmiowb();
arch/mips/loongson2ef/common/pm.c:	mmiowb();
arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
arch/mips/pci/ops-bonito64.c:	mmiowb();
arch/mips/pci/ops-loongson2.c:	mmiowb();
arch/mips/txx9/generic/irq_tx4939.c:	mmiowb();
arch/mips/txx9/generic/setup.c:	mmiowb();
arch/mips/txx9/rbtx4927/irq.c:	mmiowb();
arch/mips/txx9/rbtx4938/irq.c:	mmiowb();
arch/mips/txx9/rbtx4938/irq.c:	mmiowb();
arch/mips/txx9/rbtx4938/setup.c:	mmiowb();
arch/mips/txx9/rbtx4939/irq.c:	mmiowb();
arch/powerpc/include/asm/mmiowb.h:#define mmiowb()		mb()
arch/riscv/include/asm/mmiowb.h:#define mmiowb()	__asm__ __volatile__ ("fence o,w" : : : "memory");
arch/s390/include/asm/io.h:#define mmiowb()	zpci_barrier()
arch/sh/include/asm/mmiowb.h:#define mmiowb()			wmb()
arch/sh/include/asm/spinlock-llsc.h:	mmiowb();
include/asm-generic/mmiowb.h: * Generic implementation of mmiowb() tracking for spinlocks.
include/asm-generic/mmiowb.h: * 	1. Implement mmiowb() (and arch_mmiowb_state() if you're fancy)
include/asm-generic/mmiowb.h:		mmiowb();

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210817135308.GO4126399%40paulmck-ThinkPad-P17-Gen-1.
