Return-Path: <kasan-dev+bncBAABB3HX5TYQKGQESS4U5PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D1E98153AA2
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 23:04:29 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id o1sf5563014ywl.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 14:04:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580940268; cv=pass;
        d=google.com; s=arc-20160816;
        b=MKdnR//LzRBzGNGNQj2haujzGhPRiGxIkctnYlrBLpadFWXhhdWzoJ2ypX6iMsgffQ
         blxRuZeFQwjzljFeYeeVgUT3bvoftHJFyA4Zaw+JgHFCHFFvMuM4eYD+17xDCC3Pt1wU
         MeWZa8+MGYbcFDpHP4RS386F+b3tRJ7EvAtDQOnMWGmynpQAgFJh1UhJVsfHq7Qo0Tq2
         eG7n14UTLn3Fw8EK5uGTytTX9zRgVF6eT+mm0eLexXqmAwGfE2p/t879xJflOihH7qmP
         9ruoa9MSX3ZR+kS3ULAqZTeYCxLvK5ee+79xHpV7ocmfYZK67AOoqZcwMI05O1mnRTIy
         gtUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=rJ4lB+yK4MqLMDax3pBcEo+2pw9JpEcy4YUfzQR9FRg=;
        b=SxP7+Vyz5h6TOSBH/+ETkfNgdjcSosWjz7/nmTfIWHk7sXNraC34dQ+sPsSgBduaur
         H83OOnkRQ8tyOXzbZrPmJ1R08Z8ekIVbgrWxFZTnx9/VjehX6/bRxxvQzdfDbSvhauya
         tA62pz+/cxyQxnCtAIFbMylUaZaSLvbb9BhQn0AmCA5DvR5m4B3kWEc3SOWXiWPRGmhB
         X4SLLQLAMVcceeaEeQg83DB31aLvrmzFISvWatZ9BEWMYYN/zdG55L/DCvqDoweEGX1S
         1lWRv6DpXZBXPN4ZT5Nd7Kk40TEzcu2yI1rFrerAvoAg53Mr8x/hQdiKRPBm6hq8vRYi
         7Cuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=s9necmQ2;
       spf=pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rJ4lB+yK4MqLMDax3pBcEo+2pw9JpEcy4YUfzQR9FRg=;
        b=Yfz+LpNaD4Qm+L9ZWL/Jrla1Ry+GsGGB/rDsi9pcwMmZ48/mVa0NJz4pg5wORzrQ+b
         jzWu+e7OPa74beKsEUSHqi+Kk8KW3dBfs5+h+WwMcMyq5STlFBKacGzCaFum8/VfE0us
         EKJbHlI7ZAExFoaim3MK8s82iDGfpn3fA7KqEUBn4FIpYW8vg3wLm1dPDVLCMeK35Q2o
         +yaY3Qu+dDFv2Vbg5rj9iIUnnoUOl4MLsP/hVLJDklL4PLV8hbzP/fH49tU8dGWFBXE9
         hEBCqJpIm8/WFZJTyaabS+sLW8DkQUU6kTaHfcqtZSPckgJUGMiPXY+RMCDTDNaSakry
         mGhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rJ4lB+yK4MqLMDax3pBcEo+2pw9JpEcy4YUfzQR9FRg=;
        b=hmMBHBhzbqpFGJN3oN/j1kMKRFdlwFzqqRrSyc+PPPCidvzulD56Is+XcIQ75yJGwg
         pTvgPywmnVV2FaZ8mkP2dSvimnRyUQQUyU1WAH98/oh168bZYS+akhlGiJk6iAYK8qWS
         eu6PHYPz+cbaA6I7IFZl6XifjZJp0d7VswcLYHT/1uKKx27QTeR6mXNfaIdyEpKS5+sB
         BG9T0sGuwGf+qdQPe1rrfokoaYBSOO6/cu84pI3lSPItyhp+E6vFvOygHj6tAv4ZO5+H
         dc+iadElR839QhREujoj9zzInLSF2XgaizEjtUhpVUdprEd3n7kan9CkpNC1l8EkUJYk
         lT9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVDmyzUp3FZx4QBiwlj5JOM2JcFCu8KLNkSMyxeV5sWFMOdjkZk
	Hq55e+mbrWIL7Oi2iegOJlA=
X-Google-Smtp-Source: APXvYqxHwha98efFZEFZYIEDQCvO7cislwaU0C/WIUjh3CLmESwy4OI3IQqh6VWq4RUIgi0jJgpIfA==
X-Received: by 2002:a81:3754:: with SMTP id e81mr240105ywa.404.1580940268565;
        Wed, 05 Feb 2020 14:04:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c58:: with SMTP id s85ls773697ybs.3.gmail; Wed, 05 Feb
 2020 14:04:28 -0800 (PST)
X-Received: by 2002:a25:cbd1:: with SMTP id b200mr245959ybg.234.1580940268193;
        Wed, 05 Feb 2020 14:04:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580940268; cv=none;
        d=google.com; s=arc-20160816;
        b=GvFVgAnPP+wnJPTCLbikuKNZ7QS70x+gBvGGBbhr/Zph9XE3WzWI+fIvOdX9vSa436
         vXkFbM9ZY8ucbRLI4FXkB3r0oFECHnzPJMWGVMjeoC79jVNYGCz1aasPIPCqzEBRNbHK
         AtloSZRMdzh9cAIlKmqglFC8YmHF+SlTfjIPIiRGxRCbsFoIgvrgJIO/MudLS6x5WCK0
         g1hxamGeAqmAYq/tTDJz4Inyxl90qTxDD+sLXiuFOjYPOSwuZdKxbsxKpTyI1Mo5T8/n
         vM47fr0nHzs2If3hTsDjElPJacqwwk5soV6kR1qctb9X9vLXDEUN97UM5tiZGr4uPRfD
         Tvdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=KhHs0oUeI+iKmeT4AcYJ3U2px8xQdzSSw2MautDsvSY=;
        b=QjAlTJD0pjJtpcjZolnW8J5X/N1WnOZiy3DPPaRldY+FQ8t0Zf6nCfODktoVy9+SWj
         1xlx0WkD2J+1eVcQZ1H2Ur2yPIaMxwjZIR5ZDABLbNvCmAo6rHOxD4Htrn3puACEpIto
         DpV+pRhszBd638k+vRy9M8UA48we3kuR5BOjd1bDWCwsc+2mxdmgFo51jOyLsN0gLzDo
         0ubq5eGqsSGh15sr27ieQZQ9hxmk657IuAxrqqKh9EYxB/RLGX4+e4mz8KvATJJfZ7jH
         gzE6pk7DXI+RwLWsXZUgio0gknKmssJfOPrXyOeUrqVT3ba+uWxeOBAahV1NqIp6be++
         Dh4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=s9necmQ2;
       spf=pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g20si61272ybj.1.2020.02.05.14.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Feb 2020 14:04:28 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2EDBF217BA;
	Wed,  5 Feb 2020 22:04:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 0B6B135227EB; Wed,  5 Feb 2020 14:04:27 -0800 (PST)
Date: Wed, 5 Feb 2020 14:04:27 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 2/3] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
Message-ID: <20200205220427.GC2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200205204333.30953-1-elver@google.com>
 <20200205204333.30953-2-elver@google.com>
 <20200205213302.GA2935@paulmck-ThinkPad-P72>
 <CANpmjNN4vyFVnMY-SmRHHf-Nci_0hAXe1HiN96OvxnTfNjKmjg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN4vyFVnMY-SmRHHf-Nci_0hAXe1HiN96OvxnTfNjKmjg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=s9necmQ2;       spf=pass
 (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Feb 05, 2020 at 10:48:14PM +0100, Marco Elver wrote:
> On Wed, 5 Feb 2020 at 22:33, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Wed, Feb 05, 2020 at 09:43:32PM +0100, Marco Elver wrote:
> > > Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> > > may be used to assert properties of synchronization logic, where
> > > violation cannot be detected as a normal data race.
> > >
> > > Examples of the reports that may be generated:
> > >
> > >     ==================================================================
> > >     BUG: KCSAN: data-race in test_thread / test_thread
> > >
> > >     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
> > >      test_thread+0x8d/0x111
> > >      debugfs_write.cold+0x32/0x44
> > >      ...
> > >
> > >     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > >      test_thread+0xa3/0x111
> > >      debugfs_write.cold+0x32/0x44
> > >      ...
> > >     ==================================================================
> > >
> > >     ==================================================================
> > >     BUG: KCSAN: data-race in test_thread / test_thread
> > >
> > >     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
> > >      test_thread+0xb9/0x111
> > >      debugfs_write.cold+0x32/0x44
> > >      ...
> > >
> > >     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
> > >      test_thread+0x77/0x111
> > >      debugfs_write.cold+0x32/0x44
> > >      ...
> > >     ==================================================================
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> > > ---
> > >
> > > Please let me know if the names make sense, given they do not include a
> > > KCSAN_ prefix.
> >
> > I am OK with this, but there might well be some bikeshedding later on.
> > Which should not be a real problem, irritating though it might be.
> >
> > > The names are unique across the kernel. I wouldn't expect another macro
> > > with the same name but different semantics to pop up any time soon. If
> > > there is a dual use to these macros (e.g. another tool that could hook
> > > into it), we could also move it elsewhere (include/linux/compiler.h?).
> > >
> > > We can also revisit the original suggestion of WRITE_ONCE_EXCLUSIVE(),
> > > if it is something that'd be used very widely. It'd be straightforward
> > > to add with the help of these macros, but would need to be added to
> > > include/linux/compiler.h.
> >
> > A more definite use case for ASSERT_EXCLUSIVE_ACCESS() is a
> > reference-counting algorithm where exclusive access is expected after
> > a successful atomic_dec_and_test().  Any objection to making the
> > docbook header use that example?  I believe that a more familiar
> > example would help people see the point of all this.  ;-)
> 
> Happy to update the example -- I'll send it tomorrow.

Sounds great!

> > I am queueing these as-is for review and testing, but please feel free
> > to send updated versions.  Easy to do the replacement!
> 
> Thank you!
> 
> > And you knew that this was coming...  It looks to me that I can
> > do something like this:
> >
> >         struct foo {
> >                 int a;
> >                 char b;
> >                 long c;
> >                 atomic_t refctr;
> >         };
> >
> >         void do_a_foo(struct foo *fp)
> >         {
> >                 if (atomic_dec_and_test(&fp->refctr)) {
> >                         ASSERT_EXCLUSIVE_ACCESS(*fp);
> >                         safely_dispose_of(fp);
> >                 }
> >         }
> >
> > Does that work, or is it necessary to assert for each field separately?
> 
> That works just fine, and will check for races on the whole struct.

Nice!!!

							Thanx, Paul

> Thanks,
> -- Marco
> 
> >                                                         Thanx, Paul
> >
> > > ---
> > >  include/linux/kcsan-checks.h | 34 ++++++++++++++++++++++++++++++++++
> > >  1 file changed, 34 insertions(+)
> > >
> > > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > > index 21b1d1f214ad5..1a7b51e516335 100644
> > > --- a/include/linux/kcsan-checks.h
> > > +++ b/include/linux/kcsan-checks.h
> > > @@ -96,4 +96,38 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> > >       kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
> > >  #endif
> > >
> > > +/**
> > > + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> > > + *
> > > + * Assert that there are no other threads writing @var; other readers are
> > > + * allowed. This assertion can be used to specify properties of synchronization
> > > + * logic, where violation cannot be detected as a normal data race.
> > > + *
> > > + * For example, if a per-CPU variable is only meant to be written by a single
> > > + * CPU, but may be read from other CPUs; in this case, reads and writes must be
> > > + * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
> > > + * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
> > > + * race condition. Using this macro allows specifying this property in the code
> > > + * and catch such bugs.
> > > + *
> > > + * @var variable to assert on
> > > + */
> > > +#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
> > > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> > > +
> > > +/**
> > > + * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> > > + *
> > > + * Assert that no other thread is accessing @var (no readers nor writers). This
> > > + * assertion can be used to specify properties of synchronization logic, where
> > > + * violation cannot be detected as a normal data race.
> > > + *
> > > + * For example, if a variable is not read nor written by the current thread, nor
> > > + * should it be touched by any other threads during the current execution phase.
> > > + *
> > > + * @var variable to assert on
> > > + */
> > > +#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> > > +     __kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> > > +
> > >  #endif /* _LINUX_KCSAN_CHECKS_H */
> > > --
> > > 2.25.0.341.g760bfbb309-goog
> > >
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205213302.GA2935%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205220427.GC2935%40paulmck-ThinkPad-P72.
