Return-Path: <kasan-dev+bncBDAZZCVNSYPBB7XC6OEAMGQEWFXS4PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 494113F02E4
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 13:39:43 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id o11-20020ac85a4b0000b029028acd99a680sf689095qta.19
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 04:39:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629286782; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzdkKbHN86ZFkfAqYXiHWSwS3q4htTNIgfg3/Xr18qnSWPSkk4nM0uNzAaCTQqJIhP
         GqNVRJvrQOVPqXAQ8DG0WMOMRKacCkMlM52X31ABO9c6lJOdhCucDzlTUQMLzcWY+2DI
         q8lfdNtbZrrbt4h455t/hAUwfjZ08QF1lVG5lnb0H6F0AZI4FfulQm4HpVz521ZYvn/7
         wsCIhliOQYkkewxGdeVWd+Vi2S5o8F5aRPYUXwUnhod8P6c+Y1jOvkYPrWXV5cfzEy9t
         s4aYLTJxzuNu+mLcAKK2KFk1+Jk64lUr1Nag+caFSjQTJKH6KJX1vFTHjj0mocmIKYm1
         fLzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=/nQcCIcEXkRXTDiswFb+jX/dYpuolTgChbDOYrdjTms=;
        b=gxF9paB2TP4VyrnlQZtp/P9iX9eLWZxHNrLxPTcz53z+OoRGE1rZoVrqA/FfLlexTL
         rbBCm+DPGgs5Z3qpZ2KopD2AOPhmd2Kq2tBR/GjAxPAMz2utYCGC0XX77b6TXrqAvVgy
         Xxs595YQZKgNGC6NPCM4U543h/NE7T8ViHpFwE3Dm0uHPsEfZNZV88e7tF4DxlJ0GBD4
         39kArPVNHyzuUXkyFng3L9SjJIuFgbfbn2LQQ3y3mzQ8Qog55/suXd1WRTmNE6U830nj
         Rdi8Z6Mt1tFZMWzY08BK9k/XV/bqH2GmGCzD2dic0AFpIO/IMwFNUFW9ArcS4TPebMZO
         9U+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LzYhHK2W;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/nQcCIcEXkRXTDiswFb+jX/dYpuolTgChbDOYrdjTms=;
        b=XbLdGwzCGLDwWXM9zh4IN4/dyI91PP2XcyDhWV4JTdBomesTG+Lf1CQCVHalcokXvL
         VSKPZqPwHcWXoVrB6NDWAfeajiCKFl12PemgFw6t+Eskd2UOgmCBU/c/NJsX0QosCBdv
         1ri5AXh+Fpvmy5PmUqht11NIU4FXpR1K3KL/iZ6wejOZOE1yitsF/vlnljorW56nuMFo
         su1Ov03CUwgEyPfE2hACkT/V65OxW6CjZiX7Gl4ChE0MTKedZJgeca8zhofzGnN6Hlb1
         78dlYVyb84DceVRywFmNKHqFYQy3igHLpFoOzRql8gEEDx3QlLZBsy4r6h+oPDDx5Pjq
         2+Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/nQcCIcEXkRXTDiswFb+jX/dYpuolTgChbDOYrdjTms=;
        b=QicB5Z/hzv7elV82MjnYzZGvHjEvn7DlRYSQuQ/0acRPaOZq2APkCVOzRd2nd9tFgB
         iBNSRb97j7Jk8eKDr3i/kqP9QCN86eYbuCDWScpIGPqsxE92dWnDFzacTVfICtJk5WUi
         NLp5uO1+YlPfe4Sg54i7F7fzNgRmkNhjlsvQ335fD63n91GsiuMPMTB5lWXu+IUMWuD7
         MhiHBEq5uV5LOgck2N9SpIEp+TxOlGmMivLyXKfbIMQW4X5wt1KLpMTeeSNfuDxA4bA7
         NwWRkufqYquykJjE5ITC9GbdwV+7qZnXk5eH2anLi5qeLIIYr1huvPwB/OF2Kr5/2PLJ
         pnVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VPvaIUddCx4cLXh0WPsQmsAHwr7BVl0yRHSzGfTCXSrDFHuw6
	pzt5s5E4IWZVea2hm5C7a+A=
X-Google-Smtp-Source: ABdhPJxMw1yGb7p9ll2z08FvXsKdoY8lbXpJqRkqDCmBpgdmA6J4o/4XB7yPY6TMIetyYtpZBVAmsQ==
X-Received: by 2002:a05:622a:305:: with SMTP id q5mr7368495qtw.154.1629286782223;
        Wed, 18 Aug 2021 04:39:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:190b:: with SMTP id bj11ls1191576qkb.7.gmail; Wed,
 18 Aug 2021 04:39:41 -0700 (PDT)
X-Received: by 2002:a37:678d:: with SMTP id b135mr9067582qkc.176.1629286781791;
        Wed, 18 Aug 2021 04:39:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629286781; cv=none;
        d=google.com; s=arc-20160816;
        b=uYcKiI4b/oOiWEpwe9C+aK1Ns/8sG7ct+Lgh2nRFeBDWOLPgGA+TYd1MJLbW9FmoPU
         3FSxZwyCHIo+SNTmtMxJ6ockykBOUy4Skkdon5JMUvj0vgSDH8q/EQ22o8PgSDS2Ek7F
         2bdf4jDXmoO3NEILVR8OuEJcgZ0MzY96ery/JvbLez2grqYCCO6DmMTcfU8PiB/JNgKu
         s9mc8sYDxLxtluh9UXqW69GF8qwzDxGYaz1YHRBOB5LIrkcWaAIit5C5EoZMaZUoPKxS
         CWcvtI/1RrY7O0SODdssP4zz3rYd3eeSkX+qZX2sNToBjOLSMyTIGq3yjoJJ6BFnhZ2/
         iu1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=g9uQv8HRXBgbetMNkajwBl5uG9sXthypt+1yRwbTc3g=;
        b=MbRuhdX+YvDi6qsGaygscnVCJrqTUoLbwRONSFmwKe7EPZ/Ax6FNTo7OlNPthJXEOe
         uMJHkZ1NFSpmtzE7SxaYcXQOAf3jE3gLIMAcnj3Ws+BJcoXVrJD6uNoMe6Cbvel58iuE
         qqAGZc392Zrruai/VdOHIXt4mewDzM2u6XQorzHTZlDnJTmBHhke9Sx8j7wAuP31R/al
         cI+O3GmeeKVbHD80RJHm9INP/3T+KfZGaQkuXLfupbCTHZRb4WlKV4emNHA+jWTHxZwR
         IXrn6qvKmyBTjg3pZbdg4H5+0+ifAVEC31LDO/TCeb59XrO9s5xQ/8WA+myYR1i68Fbx
         KiHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LzYhHK2W;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s128si344268qkh.6.2021.08.18.04.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Aug 2021 04:39:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3EAF36102A;
	Wed, 18 Aug 2021 11:39:39 +0000 (UTC)
Date: Wed, 18 Aug 2021 12:39:36 +0100
From: Will Deacon <will@kernel.org>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alan Stern <stern@rowland.harvard.edu>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <20210818113935.GA14107@willie-the-truck>
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com>
 <20210816192109.GC121345@rowland.harvard.edu>
 <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
 <20210817122816.GA12746@willie-the-truck>
 <20210817135308.GO4126399@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210817135308.GO4126399@paulmck-ThinkPad-P17-Gen-1>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LzYhHK2W;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Hi Paul.

On Tue, Aug 17, 2021 at 06:53:08AM -0700, Paul E. McKenney wrote:
> On Tue, Aug 17, 2021 at 01:28:16PM +0100, Will Deacon wrote:
> > Just on this bit...
> > 
> > On Mon, Aug 16, 2021 at 01:50:57PM -0700, Paul E. McKenney wrote:
> > > 5.	The dma_mb(), dma_rmb(), and dma_wmb() appear to be specific
> > > 	to ARMv8.
> > 
> > These are useful on other architectures too! IIRC, they were added by x86 in
> > the first place. They're designed to be used with dma_alloc_coherent()
> > allocations where you're sharing something like a ring buffer with a device
> > and they guarantee accesses won't be reordered before they become visible
> > to the device. They _also_ provide the same ordering to other CPUs.
> > 
> > I gave a talk at LPC about some of this, which might help (or might make
> > things worse...):
> > 
> > https://www.youtube.com/watch?v=i6DayghhA8Q
> 
> The slides are here, correct?  Nice summary and examples!
> 
> https://elinux.org/images/a/a8/Uh-oh-Its-IO-Ordering-Will-Deacon-Arm.pdf

Yes, that looks like them. I've also put them up here:

https://mirrors.edge.kernel.org/pub/linux/kernel/people/will/slides/elce-2018.pdf

(turns out it was ELCE not LPC!)

> And this is all I see for dma_mb():
> 
> arch/arm64/include/asm/barrier.h:#define dma_mb()	dmb(osh)
> arch/arm64/include/asm/io.h:#define __iomb()		dma_mb()
> 
> And then for __iomb():
> 
> arch/arm64/include/asm/io.h:#define __iomb()		dma_mb()
> drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.c:	__iomb();
> 
> But yes, dma_rmb() and dma_wmb() do look to have a few hundred uses
> between them, and not just within ARMv8.  I gave up too soon, so
> thank you!

No problem, and yes, dma_mb() is an arm64-internal thing which we should
probably rename.

> > Ignore the bits about mmiowb() as we got rid of that.
> 
> Should the leftovers in current mainline be replaced by wmb()?  Or are
> patches to that effect on their way in somewhere?

I already got rid of the non-arch usage of mmiowb(), but I wasn't bravei
enough to change the arch code as it may well be that they're relying on
some specific instruction semantics.

Despite my earlier comment, mmiowb() still exists, but only as a part of
ARCH_HAS_MMIOWB where it is used to add additional spinlock ordering so
that the rest of the kernel doesn't need to use mmiowb() at all.

So I suppose for these:

> arch/mips/kernel/gpio_txx9.c:	mmiowb();
> arch/mips/kernel/gpio_txx9.c:	mmiowb();
> arch/mips/kernel/gpio_txx9.c:	mmiowb();
> arch/mips/kernel/irq_txx9.c:	mmiowb();
> arch/mips/loongson2ef/common/bonito-irq.c:	mmiowb();
> arch/mips/loongson2ef/common/bonito-irq.c:	mmiowb();
> arch/mips/loongson2ef/common/mem.c:		mmiowb();
> arch/mips/loongson2ef/common/pm.c:	mmiowb();
> arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> arch/mips/loongson2ef/lemote-2f/reset.c:	mmiowb();
> arch/mips/pci/ops-bonito64.c:	mmiowb();
> arch/mips/pci/ops-loongson2.c:	mmiowb();
> arch/mips/txx9/generic/irq_tx4939.c:	mmiowb();
> arch/mips/txx9/generic/setup.c:	mmiowb();
> arch/mips/txx9/rbtx4927/irq.c:	mmiowb();
> arch/mips/txx9/rbtx4938/irq.c:	mmiowb();
> arch/mips/txx9/rbtx4938/irq.c:	mmiowb();
> arch/mips/txx9/rbtx4938/setup.c:	mmiowb();
> arch/mips/txx9/rbtx4939/irq.c:	mmiowb();

we could replace mmiowb() with iobarrier_w().

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210818113935.GA14107%40willie-the-truck.
