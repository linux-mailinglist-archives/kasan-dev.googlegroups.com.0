Return-Path: <kasan-dev+bncBCJZRXGY5YJBB34QUKFQMGQEO4OHEYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BCA342E221
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 21:43:44 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id x16-20020a25b910000000b005b6b7f2f91csf8438860ybj.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 12:43:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634240623; cv=pass;
        d=google.com; s=arc-20160816;
        b=JAB+3GgGH0Aa7Jg1KbgOmt/tbOCkThpUWlGGJH742tjbkbrCks6JlP+Pc5RXkGWGz0
         gpogPWdmFOGGm0U3dPmIZUI+7BhEHmFeGzfjzeeE+owH4L/vYzEojldST36+0WsiW0UX
         io/I0deY2TJ/xdQjNGVeua6AhMtosS+KbE84FHUNetZVoUXpnsGPNdavOqloiX6BW3HZ
         sEWDX0AiGpQ2ti0VLoK+2HTMrKr5BS9JPIRV9YwHyEijeTb1McPXGbDFsNnxNuhZ0ls7
         sef55Kbw6Dg+Tw4JSqIAvW8uRM9A7j4P7jfl8FxUyzqorU9/0/oBmlvSA2mxFlEtH+Nh
         zfnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=2T8/pHddyf3nKDLdJkNi2DGltmDd+0bNWONgBjTzC9Q=;
        b=HFSv6YNx8TdYxUeVGVnU9raidgGAN+jMdECvFoQtDdFvrAsTufWRB4ZDK6sSucRWqW
         E0hJUz5FFEcK+kBLK+YdroKSwEsm8sN9sPZdYJI5NBlTkQRybxtBbaVhyjhCeFzg5ya0
         9flbRqwfLHL1s38X5mH2lWHzbv2w85HjfK9SghwhS+T243UaiuNJaVCG0P+ERUY59b1U
         U+BUCYGCDOcKFjHSUPMMmP2V1wJ577N/+jzGAAwY3wNZz+1fBOEIpsevBdxohmbOrTg1
         6aqnDbaNY1S4QhbMMaG+GFo2G0g4NG3kE8zsx3U74bKqq/TXQFNxiIe3JIKyrmY0kG0d
         eXnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Thc/c7L+";
       spf=pass (google.com: domain of srs0=+wtw=pc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+Wtw=PC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2T8/pHddyf3nKDLdJkNi2DGltmDd+0bNWONgBjTzC9Q=;
        b=kS4+6OhUhM1rmJ57/Wx6/y6/y3Japvka4Ezyqhye0T5kuFNee1vhx34qFBoGh9IGg4
         kWhlNcwUMU0zboledRc4aOnjnFYCyPe88nChlC1Q4IMI7O3T6+/j9okDvRZEeWQmqjPi
         sFQiTm5yvgDc7TEuLM3vsCQtlioHZNcGclrYZGZ5ftRABWq9U0weXxj4eZqmlwfHv06G
         F/4E9v80ofBZNZ5tS9Wu3jTts8rvqV0+8yoJQ3BqDCdop4VqcRIL20xD2sZ+f4n76tV+
         5sRrlzrXijKymPgaPlqvQKC2QPJkwnaiuoTzbKsgr/2jpUu4tCfGwBlNdaCFaHYGGt6u
         Xc7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2T8/pHddyf3nKDLdJkNi2DGltmDd+0bNWONgBjTzC9Q=;
        b=i/p+erhQ/wMM0fCCW1D6wV4YIv9VDY9cye1GfNziotxYzSiUE5Q9FA1FgJLgw/1oeT
         NedcglIV1crr/LEmz4hTmDvEQhmuH1hAPNld0Tst+U9VmHcdcAzpAYx2VjktAjM/fgVO
         IjXxX0Twa6HxVOVbjxK8r5d0KYwzznd3j8Jf6OKcHDvJOpUBRiD5rzPdMyvaBJcysJL/
         6x707pHhS4GxfCJWc9FVEoWnk8UscO9JH1VpaI26eb5tHZamsspfoaVdk0u1YI4JdwlW
         +Dkzqu1VkWky2RQtQfb5993o7LvZzK54vFyoe5CSVe3kWWGSm4UGTSdKv6eb+svOHZdE
         bhUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300E6DNldbv4qe9DRDeDVPwRdItU59AcKPtgX7dpq/CzmoZp82Y
	kr+ZG/xTYRPg0LCw0eWdIV8=
X-Google-Smtp-Source: ABdhPJxPtWXRQNrzy8rao2mSSZWz58ts9CyG2CHI/0w3SHEQgGBDSwCVCKiNtVV5lIUyLScevmtwMw==
X-Received: by 2002:a25:c0c1:: with SMTP id c184mr8596912ybf.382.1634240623411;
        Thu, 14 Oct 2021 12:43:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b185:: with SMTP id h5ls808785ybj.11.gmail; Thu, 14 Oct
 2021 12:43:42 -0700 (PDT)
X-Received: by 2002:a25:502:: with SMTP id 2mr8773200ybf.40.1634240622846;
        Thu, 14 Oct 2021 12:43:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634240622; cv=none;
        d=google.com; s=arc-20160816;
        b=BStwoS0SptoBNzqrymjOip8qtAVCbr7+akHizCB/+qQhMWipp1lvql0gw6SUVuUoWv
         RPRHOPbUBQ0tQ9RwtZvxPFnoOLPp2HAblYaHGeHtsJuQu7UanSRrhpoBT+zmsY/K7CPO
         esD/TSVIGsxXAX6kLWgzD9gHu5s2qcQPt3IuYu7hkVa4WkEk8CTixzUKSL3aQOvweDOz
         ID3wbvWVI8h3Dy8ci9n+Nhi4ms2zIG7rTH0YFEtX87Ar2Wgi5fhrshTSsOW4OPq2ktqT
         IOBU9iB3QupfNeJpCYZTi2Y0chM9UeyC7eJVkzerCL3n8kHa3GO5h1rQh21+1R8bo2Qv
         NxrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WHPmK1+Wul9NETu4W6upaWpam+R/Y8Sq/iEGr02O9tQ=;
        b=hyWdkWVfiVaoVbscZEcW5L/awmDZ6k/QVpbv5M8zJRZDLCLqI6bBuDTauIPwkqVCp9
         fHdmOVdlT5iA3kSFzkilzcJR5FfSvJ1/QMfDyyFXkfmGxsBE+nsr3vbDtNky0oFUrUkb
         wtoRgGoLrv4K74zjfGspD9QYDJgtlRhf1V8VEs2oBvGQIMddZsg5rNHaYLFMsOkT4cZH
         ssLvcPb8DJwTg/9TCOCQC18ouidliPnz0z2oByH+RDoEYl8h15TKUNezKiGWiaXj3rE1
         zT/cjV6ptP/t3ET4QORQREmsTE78dwjKiaR+p68VusT5mEcelLc56ClXa9uWGfkpILqt
         u9xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Thc/c7L+";
       spf=pass (google.com: domain of srs0=+wtw=pc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+Wtw=PC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t13si254947ybu.2.2021.10.14.12.43.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Oct 2021 12:43:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=+wtw=pc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CEA9361037;
	Thu, 14 Oct 2021 19:43:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9D7D45C0A6E; Thu, 14 Oct 2021 12:43:41 -0700 (PDT)
Date: Thu, 14 Oct 2021 12:43:41 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Wedson Almeida Filho <wedsonaf@google.com>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211014194341.GH880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
 <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mj9x7a4mfzJo+pY8HOXAshqfhyEJMjs7F+qS-rJaaCeA@mail.gmail.com>
 <20211011190104.GI880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72ny0RCnO1+E_wBgx0C6NCaMfv82rvkLVuwmW8Y+7Kii0Q@mail.gmail.com>
 <20211013160707.GR880162@paulmck-ThinkPad-P17-Gen-1>
 <YWccYPLUOH7t9JtB@google.com>
 <20211014033557.GZ880162@paulmck-ThinkPad-P17-Gen-1>
 <YWfkXjHtVhZpg2+P@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YWfkXjHtVhZpg2+P@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Thc/c7L+";       spf=pass
 (google.com: domain of srs0=+wtw=pc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+Wtw=PC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Oct 14, 2021 at 09:03:42AM +0100, Wedson Almeida Filho wrote:
> On Wed, Oct 13, 2021 at 08:35:57PM -0700, Paul E. McKenney wrote:
> > On Wed, Oct 13, 2021 at 06:50:24PM +0100, Wedson Almeida Filho wrote:
> > > On Wed, Oct 13, 2021 at 09:07:07AM -0700, Paul E. McKenney wrote:
> > > > On Wed, Oct 13, 2021 at 01:48:13PM +0200, Miguel Ojeda wrote:
> > > > > On Mon, Oct 11, 2021 at 9:01 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > >
> > > > > > The main issue I was calling out was not justifying Rust, but rather
> > > > > > making sure that the exact same build could be reproduced a decade later.
> > > > > 
> > > > > Yes, but that is quite trivial compared to other issues I was
> > > > > mentioning like adapting and requalifying a testing tool. For
> > > > > instance, if you already had a team maintaining the configuration
> > > > > management (i.e. the versions etc.), adding one more tool is not a big
> > > > > deal.
> > > > 
> > > > OK, close enough to fair enough.  ;-)
> > > > 
> > > > > > There are things that concurrent software would like to do that are
> > > > > > made quite inconvenient due to large numbers of existing optimizations
> > > > > > in the various compiler backends.  Yes, we have workarounds.  But I
> > > > > > do not see how Rust is going to help with these inconveniences.
> > > > > 
> > > > > Sure, but C UB is unrelated to Rust UB. Thus, if you think it would be
> > > > > valuable to be able to express particular algorithms in unsafe Rust,
> > > > > then I would contact the Rust teams to let them know your needs --
> > > > > perhaps we end up with something way better than C for that use case!
> > > > 
> > > > Sequence locks and RCU do seem to be posing some challenges.  I suppose
> > > > this should not be too much of a surprise, given that there are people who
> > > > have been in the Rust community for a long time who do understand both.
> > > > If it were easy, they would have already come up with a solution.
> > > 
> > > (Hey Paul, I tried posting on your blog series, but I'm having difficulty so I
> > > thought I'd reply here given that we mention seqlocks and RCU here.)
> > 
> > It should be straightforward to post a comment, but some report that
> > their employers block livejournal.com.  :-/
> 
> I tried to use my google account while posting and then after I posted it took
> me through some workflow to confirm my account, perhaps the comment was lost
> during this workflow. Let me try again.

Please let me know how it goes.

> > Oh, and I have updated heavily recently, including adding a bunch of
> > Linux-kernel use cases for both sequence locking and RCU.
> 
> I'll check it out, thanks!
>  
> > > I spent a bit of time thinking about sequence locks and I think I have something
> > > that is workable. (I remind you that we use the C implementation for the
> > > synchronisation primitives). Suppose we had some struct like so:
> > > 
> > > struct X {
> > >     a: AtomicU32,
> > >     b: AtomicU32,
> > > }
> > > 
> > > And suppose we have it protected by a sequence lock. If we wanted to return the
> > > sum of the two fields, the code would look like this:
> > > 
> > >     let v = y.access(|x| {
> > >         let a = x.a.load(Ordering::Relaxed);
> > > 	let b = x.b.load(Ordering::Relaxed);
> > > 	a + b
> > >     });
> > > 
> > > It would be expanded to the following machine code in aarch64 (when LTO is
> > > enabled):
> > > 
> > >   403fd4:       14000002        b       403fdc
> > >   403fd8:       d503203f        yield
> > >   403fdc:       b9400808        ldr     w8, [x0, #8]
> > >   403fe0:       3707ffc8        tbnz    w8, #0, 403fd8
> > >   403fe4:       d50339bf        dmb     ishld
> > >   403fe8:       b9400c09        ldr     w9, [x0, #12]
> > >   403fec:       b940100a        ldr     w10, [x0, #16]
> > >   403ff0:       d50339bf        dmb     ishld
> > >   403ff4:       b940080b        ldr     w11, [x0, #8]
> > >   403ff8:       6b08017f        cmp     w11, w8
> > >   403ffc:       54ffff01        b.ne    403fdc
> > >   404000:       0b090148        add     w8, w10, w9
> > > 
> > > It is as efficient as the C version, though not as ergonomic. The
> > > .load(Ordering::Relaxed) can of course be improved to something shorter like
> > > .load_relaxed() or even new atomic types  with .load() being relaxed and
> > > .load_ordered(Ordering) for other ordering.
> > 
> > Nice!
> > 
> > Is this a native Rust sequence-lock implementation or a wrapper around
> > the C-language Linux-kernel implementation?
> 
> It's a wrapper around the C-language Linux kernel implementation. (To get the
> generated code with LTO inlining, I compiled the code in userspace because
> LTO with cross-language inlining isn't enabled/working in the kernel yet).

Good on the wrapper, and agreed, I also tend to prototype in userspace.

> > > I also have guard- and iterator-based methods for the read path that would look
> > > like this (these can all co-exist if we so choose):
> > > 
> > >     let v = loop {
> > >         let guard = y.read();
> > >         let a = guard.a.load(Ordering::Relaxed);
> > >         let b = guard.b.load(Ordering::Relaxed);
> > >         if !guard.need_retry() {
> > >             break a + b;
> > >         }
> > >     };
> > > 
> > > and
> > > 
> > >     let mut v = 0;
> > >     for x in y {
> > >         let a = x.a.load(Ordering::Relaxed);
> > > 	let b = x.b.load(Ordering::Relaxed);
> > > 	v = a + b;
> > >     }
> > > 
> > > The former generates the exact same machine code as above though the latter
> > > generates slightly worse code (it has instructions sequences like "mov w10,
> > > #0x1; tbnz w10, #0, 403ffc" and , "mov w10, wzr; tbnz w10, #0, 403ffc", which
> > > could be optimised but for some reason isn't).
> > 
> > The C++ bindings for RCU provide a similar guard approach, leveraging
> > C++ BasicLock.  Explicit lock and unlock can be obtained using
> > move-assignments.
> 
> I haven't seen these bindings, perhaps I should :) But one relevant point about
> guards is that Rust has an affine type system that allows it to catch misuse of
> guards at compile time. For example, if one wants to explicitly unlock, the
> unlock method 'consumes' (move-assigns) the guard, rendering it unusable:
> attempting to use such a guard is a compile-time error (even if it's in scope).
> In C++, this wouldn't be caught at compile time as moved variables remain
> accessible while in scope.

OK, but there are cases where seqlock entry/exit is buried in helper
functions, for example in follow_dotdot_rcu() function in fs/namei.c.
(See recent changes to https://paulmck.livejournal.com/63957.html.)
This sort of thing is often necessary to support iterators.

So how is that use case handled?

Plus we could easily get an RAII-like effect in C code for RCU as follows:

	#define rcu_read_lock_scoped rcu_read_lock(); {
	#define rcu_read_unlock_scoped } rcu_read_unlock();

	rcu_read_lock_scoped();
		struct foo *p = rcu_dereference(global_p);

		do_some_rcu_stuff_with(p);
	rcu_read_unlock_scoped();

But we don't.  One reason is that we often need to do things like
this:

	rcu_read_lock();
	p = rcu_dereference(global_p);
	if (ask_rcu_question(p)) {
		do_some_other_rcu_thing(p);
		rcu_read_unlock();
		do_something_that_sleeps();
	} else {
		do_yet_some_other_rcu_thing(p);
		rcu_read_unlock();
		do_something_else_that_sleeps();
	}

Sure, you could write that like this:

	bool q;

	rcu_read_lock_scoped();
	struct foo *p = rcu_dereference(global_p);
		q = ask_rcu_question(p);
		if (q)
			do_some_other_rcu_thing(p);
		else
			do_yet_some_other_rcu_thing(p);
	rcu_read_unlock_scoped();
	if (q)
		do_something_that_sleeps();
	else
		do_something_else_that_sleeps();

And I know any number of C++ guys who would sing the benefits of the
latter over the former, but I personally think they are drunk on RAII
Koolaid.  As would any number of people in the Linux kernel community. ;-)

It turns out that there are about 3400 uses of rcu_read_lock() and
about 4200 uses of rcu_read_unlock().  So this sort of thing is common.
Yes, it is possible that use of RAII would get rid of some of them,
but definitely not all of them.

Plus there are situations where an iterator momentarily drops out of
an RCU read-side critical section in order to keep from impeding RCU
grace periods.  These tend to be buried deep down the function-call stack.

Don't get me wrong, RAII has its benefits.  But also its drawbacks.

> > > Anyway, on to the write path. We need another primitive to ensure that only one
> > > writer at a time attempts to acquire the sequence lock in write mode. We do this
> > > by taking a guard for this other lock, for example, suppose we want to increment
> > > each of the fields:
> > > 
> > >     let other_guard = other_lock.lock();
> > >     let guard = y.write(&other_guard);
> > 
> > The first acquires the lock in an RAII (scoped) fashion and the second
> > enters the sequence-lock write-side critical section, correct?
> 
> Yes, exactly.

But wouldn't it be more ergonomic and thus less error-prone to be able
to combine those into a single statement?

> Additionally, the ownership rules guarantee that the outer lock cannot be
> unlocked while in the sequence-lock write-side critical section (because the
> inner guard borrows the outer one, so it can be only be consumed after this
> borrow goes away). An attempt to do so would result in a compile-time error.

OK, let's talk about the Rusty Scale of easy of use...

This was introduced by Rusty Russell in his 2003 Ottawa Linux Symposium
keynote: https://ozlabs.org/~rusty/ols-2003-keynote/ols-keynote-2003.html.
The relevant portion is in slides 39-57.

An API that doesn't let you get it wrong (combined lock/count acquisition)
is better than one where the compiler complains if you get it wrong.  ;-)

> > >     guard.a.store(guard.a.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
> > >     guard.b.store(guard.b.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
> > > 
> > > The part the relates to the sequence lock is compiled to the following:
> > > 
> > >   404058:       f9400009        ldr     x9, [x0]
> > >   40405c:       eb08013f        cmp     x9, x8
> > >   404060:       54000281        b.ne    4040b0
> > > 
> > >   404064:       b9400808        ldr     w8, [x0, #8]
> > >   404068:       11000508        add     w8, w8, #0x1
> > >   40406c:       b9000808        str     w8, [x0, #8]
> > >   404070:       d5033abf        dmb     ishst
> > >   404074:       b9400c08        ldr     w8, [x0, #12]
> > >   404078:       11000508        add     w8, w8, #0x1
> > >   40407c:       b9000c08        str     w8, [x0, #12]
> > >   404080:       b9401008        ldr     w8, [x0, #16]
> > >   404084:       11000508        add     w8, w8, #0x1
> > >   404088:       b9001008        str     w8, [x0, #16]
> > >   40408c:       d5033abf        dmb     ishst
> > >   404090:       b9400808        ldr     w8, [x0, #8]
> > >   404094:       11000508        add     w8, w8, #0x1
> > >   404098:       b9000808        str     w8, [x0, #8]
> > > 
> > > If we ignore the first three instructions momentarily, the rest is as efficient
> > > as C. The reason we need the first three instructions is to ensure that guard
> > > that was passed into the `write` function is a guard to the correct lock. The
> > > lock type already eliminates the vast majority of issues, but a developer could
> > > accidentally lock the wrong lock and use it in the sequence lock, which would be
> > > problematic. So we need this check in Rust that we don't need in C (although the
> > > same mistake could happen in C).
> > > 
> > > We can provide an 'unsafe' version that doesn't perform this check, then the
> > > onus is on the callers to convince themselves that they have acquired the
> > > correct lock (and they'd be required to use an unsafe block). Then the
> > > performance would be the same as the C version.
> > 
> > The Linux-kernel C-language sequence counter (as opposed to the various
> > flavors of sequence lock) assume that the caller has provided any needed
> > mutual exclusion.
> 
> Yes, this actually uses sequence counters.
> 
> I suppose if we embed the locks ourselves like sequence locks do, we can wrap
> such 'unsafe' blocks as part of the implementation and only expose safe
> interfaces as efficient as C.
> 
> Do you happen to know the usage ratio between sequence counters vs sequence
> locks (all flavours combined)? If the latter are used in the vast majority of
> cases, I think it makes sense to do something similar in Rust.

Let's count the initializations:

o	Sequence counters:

	 8	SEQCNT_ZERO
	15	seqcount_init

	23	Total

o	Sequence locks:

	3	SEQCNT_RAW_SPINLOCK_ZERO
	3	SEQCNT_SPINLOCK_ZERO
	0	SEQCNT_RWLOCK_ZERO
	0	SEQCNT_MUTEX_ZERO
	0	SEQCNT_WW_MUTEX_ZERO
	1	seqcount_raw_spinlock_init
	13	seqcount_spinlock_init
	1	seqcount_rwlock_init
	1	seqcount_mutex_init
	1	seqcount_ww_mutex_init

	23	Total

Exactly even!  When does -that- ever happen?  ;-)

> > > Now that I've presented how my proposal looks like from the PoV of a user,
> > > here's its rationale: given that we only want one copy of the data and that
> > > mutable references are always unique in the safe fragment of Rust, we can't (and
> > > don't) return a mutable reference to what's protected by the sequence lock, we
> > > always only allow shared access, even when the sequence lock is acquired in
> > > write mode.
> > > 
> > > Then how does one change the fields? Interior mutability. In the examples above,
> > > the fields are all atomic, so they can be changed with the `store` method. Any
> > > type that provides interior mutability is suitable here.
> > 
> > OK, so following the approach of "marked accesses".
> 
> Yes.
>  
> > > If we need to use types with interior mutability, what's the point of the
> > > sequence lock? The point is to allow a consistent view of the fields. In our
> > > example, even though `a` and `b` are atomic, the sequence lock guarantees that
> > > readers will get a consistent view of the values even though writers modify one
> > > at a time.
> > 
> > Yes.
> > 
> > I suppose that the KCSAN ASSERT_EXCLUSIVE_WRITER() could be used on
> > the sequence-lock update side to check for unwanted concurrency.
> 
> Yes, definitely!

Could anything be done to check for values leaking out of failed seqlock
read-side critical sections?

> > > Lastly, the fact we use a generic `Guard` as proof that a lock is held (for the
> > > write path) means that we don't need to manually implement this for each
> > > different lock we care about; any that implements the `Lock` trait can be used.
> > > This is unlike the C code that uses fragile macros to generate code for
> > > different types of locks (though the scenario is slightly different in that the
> > > C code embeds a lock, which is also something we could do in Rust) -- the Rust
> > > version uses generics, so it is type-checked by the compiler.
> > 
> > OK, so this is a standalone implementation of sequence locks in Rust,
> > rather than something that could interoperate with the C-language
> > sequence locks?
> 
> It's an implementation of sequence locks using C-language sequence counters.
> Instead of embedding a lock for writer mutual exclusion, we require evidence
> that some lock is in use. The idea was to be "flexible" and share locks, but if
> most usage just embeds a lock, we may as well do something similar in Rust.

Whew!

I don't know if such a case exists, but there is the possibility of
non-lock mutual exclusion.  For example, the last guy to remove a
reference to something is allowed to do a sequence-counter update.

How would such a case be handled?

> > Is "fragile macros" just the usual Rust denigration of the C preprocessor,
> > or is there some specific vulnerability that you see in those macros?
> 
> I don't see any specific vulnerability. By fragile I meant that it's more error
> prone to write "generic" code with macros than with compiler-supported generics.

Fair enough, but rest assured that those who love the C preprocessor
have their own "interesting" descriptions of Rust macros.  ;-)

Plus I am old enough to remember people extolling the simplicity of
C-preprocessor macros compared to, among other things, LISP macros.
And they were correct to do so, at least for simple use cases.

I suggest just calling them CPP macros or similar when talking with
Linux-kernel community members.  Me, I have seen enough software artifacts
come and go that I don't much care what you call them, but others just
might be a bit more touchy about such things.

> > Of course, those macros could be used to automatically generate the
> > wrappers.  Extract the macro invocations from the C source, and transform
> > them to wrappers, perhaps using Rust macros somewhere along the way.
> 
> Sure, we could do something like that.
> 
> But given that we already wrap the C locks in Rust abstractions that implement a
> common trait (interface), we can use Rust generics to leverage all locks without
> the need for macros.

If you have a particular sequence lock that is shared between Rust and C
code, it would be good to be able to easily to find the Rust uses given
the C uses and vice versa!

I am not claiming that generics won't work, but instead that we still need
to be able to debug the Linux kernel, and that requires us to be able to
quickly and easily find all the places where a given object is used.

> > > RCU pointers can be implemented with a similar technique in that read access is
> > > protected by a 'global' RCU reader lock (and evidence of it being locked is
> > > required to get read access), and writers require another lock to be held. The
> > > only piece that I haven't thought through yet is how to ensure that pointers
> > > that were exposed with RCU 'protection' cannot be freed before the grace period
> > > has elapsed. But this is a discussion for another time.
> > 
> > Please note that it is quite important for Rust to use the RCU provided
> > by the C-language part of the kernel.  Probably also for sequence locks,
> > but splitting RCU reduces the effectiveness of its batching optimizations.
> 
> Agreed. We actually use the C implementation for all synchronisation primitives
> (including ref-counting, which isn't technically a synchronisation primitive but
> has subtle usage of barriers). What I mean by "implemented in Rust" is just the
> abstractions leveraging Rust concepts to catch misuses earlier where possible.

Might I suggest that you instead say "wrappered for Rust"?

I am not the only one to whom "implemented in Rust" means just what
it says, that Rust has its own variant written completely in Rust.
Continuing to use "implemented in Rust" will continue to mislead
Linux-kernel developers into believing that you created a from-scratch
Rust variant of the code at hand, and believe me, that won't go well.

> > For at least some of the Linux kernel's RCU use cases, something like
> > interior mutability may be required.  Whether those use cases show up
> > in any Rust-language drivers I cannot say.  Other use cases would work
> > well with RCU readers having read ownership of the non-pointer fields
> > in each RCU-protected object.
> > 
> > Again, I did add rough descriptions of a few Linux-kernel RCU use cases.
> > 
> > > I'll send out the patches for what I describe above in the next couple of days.
> > > 
> > > Does any of the above help answer the questions you have about seqlocks in Rust?
> > 
> > Possibly at least some of them.  I suspect that there is still much to
> > be learned on all sides, including learning about additional questions
> > that need to be asked.
> 
> Fair point. We don't know quite yet if we've asked all the questions.

My main immediate additional question is "what are the bugs and what
can be done to better locate them".  That question of course applies
regardless of the language and tools used for a given piece of code.

> > Either way, thank you for your work on this!
> 
> Thanks for engaging with us, this is much appreciated.
> 
> Cheers,
> -Wedson
> 
> > 
> > 							Thanx, Paul
> > 
> > > Thanks,
> > > -Wedson
> > > 
> > > > So the trick is to stage things so as to allow people time to work on
> > > > these sorts of issues.
> > > > 
> > > > > In any case, Rust does not necessarily need to help there. What is
> > > > > important is whether Rust helps writing the majority of the kernel
> > > > > code. If we need to call into C or use inline assembly for certain
> > > > > bits -- so be it.
> > > > > 
> > > > > > But to be fair, much again depends on exactly where Rust is to be applied
> > > > > > in the kernel.  If a given Linux-kernel feature is not used where Rust
> > > > > > needs to be applied, then there is no need to solve the corresponding
> > > > > > issues.
> > > > > 
> > > > > Exactly.
> > > > 
> > > > Thank you for bearing with me.
> > > > 
> > > > I will respond to your other email later,.  but the focus on memory
> > > > safety in particular instead of undefined behavior in general does help
> > > > me quite a bit.
> > > > 
> > > > My next step is to create a "TL;DR: Memory-Model Recommendations" post
> > > > that is more specific, with both short-term ("do what is easy") and
> > > > long-term suggestions.
> > > > 
> > > > 							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211014194341.GH880162%40paulmck-ThinkPad-P17-Gen-1.
