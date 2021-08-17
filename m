Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFWQ52EAMGQEO7VUGKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8410E3EEC3F
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 14:14:15 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 192-20020a2e05c90000b02901b91e6a0ebasf3974986ljf.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 05:14:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629202455; cv=pass;
        d=google.com; s=arc-20160816;
        b=LRJaoNI1b+OiBi9woRo774BpQMEPqtL7hN5ZS23H1f6cPLqVYEZqcjKMSSwv7KnxL+
         59vnGS4hL1oPuLxPnDec3d8LR4Q3U5J5CkXsZk1sUJ50yZkgIYd+RUcbxTy4vZEYUx81
         03JEwsKqzNmubLJ7WahrYNh7wbNtfLMqylSco2jPemeqC+Ox8o9sAkOsVR4H5fF15SGg
         0QH8uBCtfs+oRojzyqUlPk/K89KRNIu3G98jyZGv/FDqVjyfCPWI6AKcKVEz+DG5z9I6
         W2G5BkDWROiToDvnZKxRBjQnFUIyLD+KImeGqlV9XpatN5NY+DEeYWrjbUipBYPKlvTW
         vA7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MGJteU6PzZtIkSz0HtWQLBX5DKXSBh2OsNKQ4vv2N5E=;
        b=yYTWNsnZgnJhMbozeEjgT3Yab4NkPA71l5Uej5M/zCqL8009/ZxqMcdi1bXoYvyGnb
         2IpqdpHFLvn6pJ9V8bTqO3pUZQS/3JFMl6rnR4d6ySV/YxuBca6KNEHLSFAcAtuUmrUb
         lJr/MzvpTD7yDPc5/7QfOHTZ3wrNM+oFBiGrVvf4QM33kiAPPOc+hog/cme9ZEem1m0H
         v+rLbTvx0Mwyp+eo61V4ptb0rSnUXguokoF5PHYQQ8eUtxQMu6HpPIuIbW2e9P5zZFHA
         5RQs7fq/IoUh7iGjiBSI+lHxxwTNolINye4WcNlbhLrBIeL1SJH5ShkJ4Y29eR6pasFO
         4JLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k7jDQ3lY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=MGJteU6PzZtIkSz0HtWQLBX5DKXSBh2OsNKQ4vv2N5E=;
        b=Xnm43Y++QxFixwBgzexKUbmbDOQfv66hs1nV2MqoYWUmxWlSvknwRoigy0a7aJxkk9
         o7FPUZ4Yh6uI/Jx1ypiDDtNSXC6vdy6SSAXN7AI76UPFFjTfa6hLwzYbYh7daQEulNDO
         AXJBJ/slI6q9CyaRiWakvTJAn0Py/nN8/ANcXatzwlTKL9pxk7mPXOnnJdL9giOWXFBM
         u8C1vHiyFOXt6Zl7ALY3TAgYqWDK8tWrxKFernJsRqCde2pY1vdL+NtncZHFOxHrcwGk
         EF/T/xI1CAV4EFU6BTvvKt76bcvQOWwsiqooXYvohQTqywhEAkfUWOa7ZygyjLA2qWRU
         nKRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MGJteU6PzZtIkSz0HtWQLBX5DKXSBh2OsNKQ4vv2N5E=;
        b=lF4U6/OdSqa2lbV9cLg+SCzTxORyxUojp8xh3h6DgcGbpg2AcVmXWmtNHzzIASOXrl
         OhtwwgAEoDqrjbun1dShUP2+f9TO3y9rgbT6n1mttdZgquHcqxGeSubAW3U+wbN3UeAX
         tRqhdo6cYv7v1lKrmqoR5UQxy+kEKdM8G1SZjST9Vx5NzlaXs6gxybhBixtA5swaRUkW
         uHNDIaBsWIpJtssgjD0GfNrOolrdQiyp+vlNHSImfVJ0CW/y+bUk+mk/GVlhoK11t4ZW
         3aVYsbXR+e9pf/XM3hXkEPmvpMx3TwN5W5o5aFCGFwNk0H544jQ8E9sCFlViyo/eSi2h
         STmQ==
X-Gm-Message-State: AOAM531NST7fa+ocf3svH79vCSX8REs4i62WpSnNgDkmBjqrrYP5Fo7f
	BaVmu/n08qAo6d7Gt+nvWic=
X-Google-Smtp-Source: ABdhPJyorSffJ2QGfwGUA860lrR2TnJS0MnO315DR2gfJzz8wSZIXB8bhBG6IXylvCcuUlMkJgvVyQ==
X-Received: by 2002:a19:e214:: with SMTP id z20mr2211993lfg.37.1629202455114;
        Tue, 17 Aug 2021 05:14:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls1303480lfi.2.gmail; Tue, 17 Aug
 2021 05:14:14 -0700 (PDT)
X-Received: by 2002:a19:610d:: with SMTP id v13mr2233088lfb.641.1629202453923;
        Tue, 17 Aug 2021 05:14:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629202453; cv=none;
        d=google.com; s=arc-20160816;
        b=YhuB11vQaXGS8s4h5SLfQJz0cVlnHsCSoNvPAgsGdXsUejPmnJGR4lOLEgRjhCK/BX
         3auHKJIwU8VPNDgKR0QTHlKVcXsTEGFMn2jKFi1oBvtQygPs237UzubXiyJ7ENdPECIr
         XlN1W5CrYtEu2/UFibjeHPzFjywRTwPK5XXq6LrMlSxXvIAM1VceqvrlkdFM0isDoutD
         0akfUBRGR3uLOzn6InDA5Xfl83JLJdxRcp9YSsuT1MaxTwOIDSn9SJNJzMO3n43lujSC
         CXbkzFHmN7mBgH/00x9zo4VtF6FyAorYJaVL3bN7d75OMDxlMBNTBL9MSf2+UjMREl1w
         Xefw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ix6jNCDi/nRG6HwuIPNkhPwWUXVhcH/J6lfAEhtZJ30=;
        b=a/kxX85ZiasvNwfDqg2yoULK+2sgJ9QM79+Ldf2XAoZFfuShHhyFeu+8/ub8KIHbp9
         qryQdzp4c6xgtjxWXBQr7F0NXEjs2UuNJxJ2yMGHDR2I2COHj6UpRj3vp2gW9R4ZZzTX
         VQSwfGtUxon+KvTkfALq4zunoUIKNB7MRVy6AXFrulwH+XvaC/VoN2qbhZeCY9/GLOpu
         84YmC/U0aeFn64y3IVV1Ff2aCYzTj1GgyT6PiGqn68numZ4akp6tHvwictu2YKRlTV1Y
         CB10Hu+IefIythxQHx7MgEkxudgq7Yr+CDeUJ2vjK87YepCvHOfrBQ6awN617Y3gntmb
         LfqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k7jDQ3lY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id q8si98417ljb.6.2021.08.17.05.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Aug 2021 05:14:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id q11so28269119wrr.9
        for <kasan-dev@googlegroups.com>; Tue, 17 Aug 2021 05:14:13 -0700 (PDT)
X-Received: by 2002:adf:e94c:: with SMTP id m12mr3744998wrn.235.1629202453271;
        Tue, 17 Aug 2021 05:14:13 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:b13d:94d3:30db:869e])
        by smtp.gmail.com with ESMTPSA id p8sm1868998wme.22.2021.08.17.05.14.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Aug 2021 05:14:12 -0700 (PDT)
Date: Tue, 17 Aug 2021 14:14:06 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alan Stern <stern@rowland.harvard.edu>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <YRuoDhY6gXnx/XEW@elver.google.com>
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com>
 <20210816192109.GC121345@rowland.harvard.edu>
 <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=k7jDQ3lY;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
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

On Mon, Aug 16, 2021 at 01:50PM -0700, Paul E. McKenney wrote:
> On Mon, Aug 16, 2021 at 03:21:09PM -0400, Alan Stern wrote:
[...]
> > Access ordering of devices is difficult to describe.  How do you tell a 
> > memory model (either a theoretical one or one embedded in code like 
> > KCSAN) that a particular interrupt handler routine can't be called until 
> > after a particular write has enabled the device to generate an IRQ?
> > 
> > In the case you mention, how do you tell the memory model that the code 
> > on CPU 1 can't run until after CPU 0 has executed a particular write, one 
> > which is forced by some memory barrier to occur _after_ all the potential 
> > overwrites its worried about?
> 
> What Alan said on the difficulty!
> 
> However, KCSAN has the advantage of not needing to specify the outcomes,
> which is much of the complexity.  For LKMM to do a good job of handling
> devices, we would need a model of each device(!).

For full models, like the formal LKMM, I agree it's extremely difficult!

KCSAN has the advantage that it's a "dynamic analysis" tool, relying on
merely instrumenting real code and running on the real HW. The real HW
is still in charge of generating interrupts, and real devices (like that
E1000 device, though in this case virtualized by QEMU) aren't in any way
abstracted or modeled.

KCSAN's (and any other sanitizer's) primary goals is to just _detect_
certain classes of bugs by making these detectable via instrumentation
but otherwise run real code and HW.

Thus far, for KCSAN this has been trivial because all it does is keep an
eye on reads and writes, and observes if accesses race; and then, per
rules for data races (it needs to know about plain and marked accesses),
it decides if something is a reportable data race.

The real HW is entirely in charge of when and if something executes
concurrently.

One problem with instrumentation, however, is that it adds certain
overheads which make some effects of the hardware very unlikely to
observe. For example, the effects of weak memory. Therefore, I'm
teaching KCSAN a limited set of weak memory effects allowed by the LKMM
by pretending the current CPU reordered an access (currently just
"load/store buffering").

To avoid false positives, however, the tool now has to know about memory
barriers, otherwise it might simulate reordering too aggressively.

Because KCSAN relies on compiler instrumentation, we are simply limited
to analyzing what is happening on CPUs, but devices are invisible, and
just observe what happens as a result on other CPUs if a device is
involved.

The case with E1000 and dma_wmb() came about because KCSAN is now able
to detect races between 2 CPUs because dma_wmb() doesn't seem to say
anything about ordering among CPUs.

The main points are:

1. KCSAN doesn't need a model for devices because it's still running on
   real HW with real devices that are in charge of generating interrupts.

2. In the case with the E1000 driver, a real device causes CPU 1 to run
   the interrupt, which does a free to memory that might still be read/written
   to if CPU 0 reordered its accesses (simulated by KCSAN). That reordering
   can be inhibited by the right barrier, but we haven't found it in the
   code yet. At least the dma_wmb() isn't required to order the writes
   between the 2 CPUs (AFAIK).

> > > What would be more useful?
> > > 
> > > 1. Let the architecture decide how they want KCSAN to instrument non-smp
> > >    barriers, given it's underspecified. This means KCSAN would report
> > >    different races on different architectures, but keep the noise down.
> > > 
> > > 2. Assume the weakest possible model, where non-smp barriers just do
> > >    nothing wrt other CPUs.
> > 
> > I don't think either of those would work out very well.  The problem 
> > isn't how you handle the non-smp barriers; the problem is how you 
> > describe to the memory model the way devices behave.
> 
> There are some architecture-independent ordering guarantees for MMIO
> which go something like this:
> 
> 0.	MMIO readX() and writeX() accesses to the same device are
> 	implicitly ordered, whether relaxed or not.
> 
> 1.	Locking partitions non-relaxed MMIO accesses in the manner that
> 	you would expect.  For example, if CPU 0 does an MMIO write,
> 	then releases a lock, and later CPU 1 acquires that same lock and
> 	does an MMIO read, CPU 0's MMIO write is guaranteed to happen
> 	before CPU 1's MMIO read.  PowerPC has to jump through a few
> 	hoops to make this happen.
> 
> 	Relaxed MMIO accesses such as readb_relaxed() can be reordered
> 	with locking primitives on some architectures.
> 
> 2.	smp_*() memory barriers are not guaranteed to affect MMIO
> 	accesses, especially not in kernels built with CONFIG_SMP=n.
> 
> 3.	The mb() memory barrier is required to order prior MMIO
> 	accesses against subsequent MMIO accesses.  The wmb() and rmb()
> 	memory barriers are required to order prior order prior MMIO
> 	write/reads against later MMIO writes/reads, respectively.
> 	These memory barriers also order normal memory accesses in
> 	the same way as their smp_*() counterparts.
> 
> 4.	The mmiowb() memory barrier can be slightly weaker than wmb(),
> 	as it is in ia64, but I have lost track of the details.
> 
> 5.	The dma_mb(), dma_rmb(), and dma_wmb() appear to be specific
> 	to ARMv8.
> 
> 6.	Non-relaxed MMIO writeX() accesses force ordering of prior
> 	normal memory writes before any DMA initiated by the writeX().
> 
> 7.	Non-relaxed MMIO readX() accesses force ordering of later
> 	normal memory reads after any DMA whose completion is reported
> 	by the readX().  These readX() accesses are also ordered before
> 	any subsequent delay loops.
> 
> Some more detail is available in memory-barriers.txt and in this LWN
> article:  https://lwn.net/Articles/698014/
> 
> I wish I could promise you that these are both fully up to date, but
> it is almost certain that updates are needed.

Thanks, that's useful. What I can tell is that most I/O ops and barriers
have no effect on other CPUs (except for mb() etc.). For KCSAN that's
all that matters.

[...]
> > > Which might be an argument to make KCSAN's non-smp barrier
> > > instrumentation arch-dependent, because some drivers might in fact be
> > > written with some target architectures and their properties in mind. At
> > > least it would help keep the noise down, and those architecture that
> > > want to see such races certainly still could.
> > > 
> > > Any preferences?
> > 
> > I'm not a good person to ask; I have never used KCSAN.  However...
> > 
> > While some drivers are indeed written for particular architectures or 
> > systems, I doubt that they rely very heavily on the special properties of 
> > their target architectures/systems to avoid races.  Rather, they rely on 
> > the hardware to behave correctly, just as non-arch-specific drivers do.
> > 
> > Furthermore, the kernel tries pretty hard to factor out arch-specific 
> > synchronization mechanisms and related concepts into general-purpose 
> > abstractions (in the way that smp_mb() is generally available but is 
> > defined differently for different architectures, for example).  Drivers 
> > tend to rely on these abstractions rather than on the arch-specific 
> > properties directly.
> > 
> > In short, trying to make KCSAN's handling of device I/O into something 
> > arch-specific doesn't seem (to me) like a particular advantageous 
> > approach.  Other people are likely to have different opinions.

As explained above, KCSAN just instruments C code but still runs on real
HW with real devices. All I'm trying to figure out is what I/O ops and
barriers say about making accesses visible to other CPUs to avoid false
positives.

However, it seems by this discussing I'm starting to conclude that the
E1000 race might in fact be something allowed, although very unlikely.

The main question I was trying to answer is "should such cases be
reported or not?", since KCSAN's goal is not to model the system
faithfully, but to detect bugs. Either way is possible, and I don't have
a preference. I'm leaning towards "no assumptions, report everything"
now, because the "access reordering" mode won't be enabled by default.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YRuoDhY6gXnx/XEW%40elver.google.com.
