Return-Path: <kasan-dev+bncBCJZRXGY5YJBBMU75OEAMGQEMRUEDJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 332733EDEC8
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 22:51:00 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id o3-20020a170902778300b0012d888ce2efsf8003803pll.10
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 13:51:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629147059; cv=pass;
        d=google.com; s=arc-20160816;
        b=BUESkF84xBdD65/p+0norMvWMqDFV03x3QfKRoAgpiR20fwOepN/MZUubS9myw1PZd
         GCDiWlQA68oJInLLbF0qYqDJGjoJQdzyxg8FrKX8WldASwGDJCxhZd61LBi5lwGerAa3
         /R2WIFXqctY9Y7mDb4n0FzKzdgZAlzzcF6TAAOAakU1BKQ0UyHgUc2sWHzgcIsHD7Us3
         Q19FEl71Lmvof0ULmod6UOaTzq1o6yzBrRiKFvYfRfEq0RYAciIITLspxstdobc/qaF6
         90dpqybpfIhlG5M21+nJvp708VrCt59gcx8XMPtFnRJbsOgXmV/uyCQ4qhndjJwqf9Lq
         FvAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=pH/18iRl2oC7R97iN6AmW7B6VD42VM9HZSX+Y+JdAus=;
        b=BW1t5jTyzTFc9YOARicsR7fwqE9chW6tNmJ7KuTyLGpnr3cvNJ+ow4KCpT2RoMjMwN
         DOrvXC6hCPMaIZZrVZNXV99siduJ3YJhhgzzTXF1NduBSBlqbohGHnn5SSjaKRXQ3m7i
         ZXrAqmid0ULme0kHnek5hnKGAvsmPqRtUb/Ix6FHzDLXkzzjV36PFpwWTT37hK4yxUN3
         Fu6vId4dqNKeRd0LJ4xxj/Lx/qBlK49lQ84I8iyDC27XK2xqDd+F+K6HTk1UiKFvu/8h
         TK4GKM83NXH6g6TcUfEX9dMhR+jawvmqdMZOkamh2XI4XoLAJYaaSYxjQMI4iZDqIGUY
         ZUzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vx17vyVN;
       spf=pass (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=PUG/=NH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pH/18iRl2oC7R97iN6AmW7B6VD42VM9HZSX+Y+JdAus=;
        b=D3DdHCydK2DooOKaQGovPEJH9HJJ+EV0ZDrYrNCTZOl854nROptGNosTmLL8RmKE2a
         sHfL9TP622KP3hkpFYwV8uCpPQPFMyGQTiZLk3ujLxZuJjxn856j0IGXMTk5xjdXVsFA
         7ZF3bOQ06H9FDFm9R2RnX7NOvqoqXEZs+d3CI8e17Yne9TQiAxF6EO7t0mlnTfxvXeTB
         j3gaLxPfS4okHI8Ew9Iy5chforkZYcl8GTD+SXFkszeuTo2SrObWDhkZTKmJE2SMrP7v
         d9EkpKxuwiMwcxbSsYY859HuVcbeTYlmXLdzQCNpFEgqnv6QpoPlooohpxh+BcwkSrzF
         1rog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pH/18iRl2oC7R97iN6AmW7B6VD42VM9HZSX+Y+JdAus=;
        b=BPfcfIzznWSVUEpJaLdjeV+ottSQ2Gyt4AQYF8drunBFoZToaNC05diMm/7parkjxL
         OarqdNcivk228JSrI8uDK0Wpk+3n8fdaC3QlLOSTF/YOf5P7kn5USgbP9TXU0CuCSlG6
         SbVi/TcXa+7Stgv3vYdRljfQqU+SuRb7ByVCqoiBUN2N0nYOm/oJs1w8zB0fo1+vUUYz
         VvISUVPjFMo6ik9AvwKcSMe6g11g3K7lvthxvtNyj9WKPf4hMKXJVg3Uk/5tLOIGjKHH
         uyhkokUbvJYffvBOJU5jDnbdqhkNBa7jbDPXVBP0KH821tQo+T8FNqQuXwJYfribDSn8
         2pXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kWgEIxRILLTY0Llkf1ja60wlUXawMQDWMLeql7iLeD4/he8Vf
	IOyNR3IdmGIXEsFEy9PPDrk=
X-Google-Smtp-Source: ABdhPJymu3nnhcT1+fZ424RGVVHzRmLe4vrqaYTBzIU2bZ5n07vkQn6P7FxLAUXsQ4eHHoQT7nVDUw==
X-Received: by 2002:a63:d104:: with SMTP id k4mr643810pgg.196.1629147058788;
        Mon, 16 Aug 2021 13:50:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:656:: with SMTP id 83ls83pgg.9.gmail; Mon, 16 Aug 2021
 13:50:58 -0700 (PDT)
X-Received: by 2002:a62:be04:0:b029:3e0:3fca:2a8f with SMTP id l4-20020a62be040000b02903e03fca2a8fmr68646pff.12.1629147058143;
        Mon, 16 Aug 2021 13:50:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629147058; cv=none;
        d=google.com; s=arc-20160816;
        b=kfvFl1mbdOGx+01m3fFRCEFcXjFiIVGp1SuPsSln2HwobpqFE0fN60ajZjvP5uPRrr
         +s/huPvWJYBJI2g1jTYzhpMK9pOtEOH9o5zwd8WtD63SgtIjqatsn0WmRJpK5/Vz9GIU
         nGVgEJ0RrC94W3aweFB7hGrPQ1Jg2Fxaf3vhmMM1zrP/4yKO8GM04J8YNLxsNzZ/3vFu
         e5yYF0nbGEYLg4bYRJwefvU4pc91MDhu5DmXJmuBLbkB7VHpBGFDcI/dkmVdQuIH6H4e
         gvNPEov0DPHueZW7W5iBVwoHHJcmhDMtsg7IRBSDEm1NaC/LMZA1VLgbRKAMmuTqoR6A
         HxKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WKkuN4t7efUCV4AcsDk7ovIdsCXFPQigQwG4U9wJ8sw=;
        b=dBQPJGwITcNdh1dzrKtIL+vDhXXzvWohu9NIPvlZscDwQougoUQuQ5fl9IfO5BIpnV
         XyLFG7EVcDDXc4iTo+wdRHQ+fLxtqDRCgjITMtUNTrXCJGEbc9l+7nCnyHMhz5pmudGl
         RFjJmhX5cnhGCWyHY9C6vdkN0KPchPr/jY0lVPeH6bgVndflbo4NBiaem4MZRBXrNWpG
         ROYTV6AT//HJ3YQ2oqWa2EUnV75uzv3NGorZYgYbkV8UtUk/suHCWAcAkgjIZl7biAB4
         O7Si4Lma1uJAjgZl5XF0SNiK22LIDxVq8G43EJgcIyerrDkm4GKz/IIrrxvzjA2sSCCS
         +O2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vx17vyVN;
       spf=pass (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=PUG/=NH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bb19si3638pjb.2.2021.08.16.13.50.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Aug 2021 13:50:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D434E604D7;
	Mon, 16 Aug 2021 20:50:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A602F5C098A; Mon, 16 Aug 2021 13:50:57 -0700 (PDT)
Date: Mon, 16 Aug 2021 13:50:57 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Alan Stern <stern@rowland.harvard.edu>
Cc: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com>
 <20210816192109.GC121345@rowland.harvard.edu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210816192109.GC121345@rowland.harvard.edu>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Vx17vyVN;       spf=pass
 (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=PUG/=NH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Aug 16, 2021 at 03:21:09PM -0400, Alan Stern wrote:
> On Mon, Aug 16, 2021 at 07:23:51PM +0200, Marco Elver wrote:
> > On Mon, Aug 16, 2021 at 10:59AM -0400, Alan Stern wrote:
> > [...]
> > > > One caveat is the case I'm trying to understand doesn't involve just 2
> > > > CPUs but also a device. And for now, I'm assuming that dma_wmb() is as
> > > > strong as smp_wmb() also wrt other CPUs (but my guess is this
> > > > assumption is already too strong).
> > > 
> > > I'm not sure that is right.  dma_wmb affects the visibility of writes to 
> > > a DMA buffer from the point of view of the device, not necessarily from 
> > > the point of view of other CPUs.  At least, there doesn't seem to be any 
> > > claim in memory-barriers.txt that it does so.
> > 
> > Thanks, I thought so.
> > 
> > While I could just not instrument dma_*mb() at all, because KCSAN
> > obviously can't instrument what devices do, I wonder if the resulting
> > reports are at all interesting.
> > 
> > For example, if I do not make the assumption that dma_wmb==smp_smb, and
> > don't instrument dma_*mb() at all, I also get racy UAF reordered writes:
> > I could imagine some architecture where dma_wmb() propagates the write
> > to devices from CPU 0; but CPU 1 then does the kfree(), reallocates,
> > reuses the data, but then gets its data overwritten by CPU 0.
> 
> Access ordering of devices is difficult to describe.  How do you tell a 
> memory model (either a theoretical one or one embedded in code like 
> KCSAN) that a particular interrupt handler routine can't be called until 
> after a particular write has enabled the device to generate an IRQ?
> 
> In the case you mention, how do you tell the memory model that the code 
> on CPU 1 can't run until after CPU 0 has executed a particular write, one 
> which is forced by some memory barrier to occur _after_ all the potential 
> overwrites its worried about?

What Alan said on the difficulty!

However, KCSAN has the advantage of not needing to specify the outcomes,
which is much of the complexity.  For LKMM to do a good job of handling
devices, we would need a model of each device(!).

> > What would be more useful?
> > 
> > 1. Let the architecture decide how they want KCSAN to instrument non-smp
> >    barriers, given it's underspecified. This means KCSAN would report
> >    different races on different architectures, but keep the noise down.
> > 
> > 2. Assume the weakest possible model, where non-smp barriers just do
> >    nothing wrt other CPUs.
> 
> I don't think either of those would work out very well.  The problem 
> isn't how you handle the non-smp barriers; the problem is how you 
> describe to the memory model the way devices behave.

There are some architecture-independent ordering guarantees for MMIO
which go something like this:

0.	MMIO readX() and writeX() accesses to the same device are
	implicitly ordered, whether relaxed or not.

1.	Locking partitions non-relaxed MMIO accesses in the manner that
	you would expect.  For example, if CPU 0 does an MMIO write,
	then releases a lock, and later CPU 1 acquires that same lock and
	does an MMIO read, CPU 0's MMIO write is guaranteed to happen
	before CPU 1's MMIO read.  PowerPC has to jump through a few
	hoops to make this happen.

	Relaxed MMIO accesses such as readb_relaxed() can be reordered
	with locking primitives on some architectures.

2.	smp_*() memory barriers are not guaranteed to affect MMIO
	accesses, especially not in kernels built with CONFIG_SMP=n.

3.	The mb() memory barrier is required to order prior MMIO
	accesses against subsequent MMIO accesses.  The wmb() and rmb()
	memory barriers are required to order prior order prior MMIO
	write/reads against later MMIO writes/reads, respectively.
	These memory barriers also order normal memory accesses in
	the same way as their smp_*() counterparts.

4.	The mmiowb() memory barrier can be slightly weaker than wmb(),
	as it is in ia64, but I have lost track of the details.

5.	The dma_mb(), dma_rmb(), and dma_wmb() appear to be specific
	to ARMv8.

6.	Non-relaxed MMIO writeX() accesses force ordering of prior
	normal memory writes before any DMA initiated by the writeX().

7.	Non-relaxed MMIO readX() accesses force ordering of later
	normal memory reads after any DMA whose completion is reported
	by the readX().  These readX() accesses are also ordered before
	any subsequent delay loops.

Some more detail is available in memory-barriers.txt and in this LWN
article:  https://lwn.net/Articles/698014/

I wish I could promise you that these are both fully up to date, but
it is almost certain that updates are needed.

> ...
> 
> > > > In practice, my guess is no compiler and architecture combination would
> > > > allow this today; or is there an arch where it could?
> > > 
> > > Probably not; reordering of reads tends to take place over time 
> > > scales a lot shorter than lengthy I/O operations.
> > 
> > Which might be an argument to make KCSAN's non-smp barrier
> > instrumentation arch-dependent, because some drivers might in fact be
> > written with some target architectures and their properties in mind. At
> > least it would help keep the noise down, and those architecture that
> > want to see such races certainly still could.
> > 
> > Any preferences?
> 
> I'm not a good person to ask; I have never used KCSAN.  However...
> 
> While some drivers are indeed written for particular architectures or 
> systems, I doubt that they rely very heavily on the special properties of 
> their target architectures/systems to avoid races.  Rather, they rely on 
> the hardware to behave correctly, just as non-arch-specific drivers do.
> 
> Furthermore, the kernel tries pretty hard to factor out arch-specific 
> synchronization mechanisms and related concepts into general-purpose 
> abstractions (in the way that smp_mb() is generally available but is 
> defined differently for different architectures, for example).  Drivers 
> tend to rely on these abstractions rather than on the arch-specific 
> properties directly.
> 
> In short, trying to make KCSAN's handling of device I/O into something 
> arch-specific doesn't seem (to me) like a particular advantageous 
> approach.  Other people are likely to have different opinions.

No preconceived notions here, at least not on this topic.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210816205057.GN4126399%40paulmck-ThinkPad-P17-Gen-1.
