Return-Path: <kasan-dev+bncBCV5TUXXRUIBBAW76H4AKGQECLIDCBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BDC222D908
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 19:44:36 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id i3sf8778620qkf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 10:44:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595699075; cv=pass;
        d=google.com; s=arc-20160816;
        b=ls/x7PM0SuaivZyRZ9lwfxKpZC0ZHmFabqfRUXt/CLhdC4jYByPP/BdZujnpA6haQ/
         Cv2RSope5pu0R7nzp7oC6dFtKFMrxXUH30cTtbXPgFUgoml/GUlmbxawTMF+0FOvtOlm
         DXYiAkMTWZ/qdvlB4SOduEKDKwSCmwiBz/Pyh2phvwGR8Tu3xpp4YXnYKd0HoUDGwRgp
         yxRH4aMMzPT9I3vv2JoZd9YAkG36tNP40RmleS7tFDmpuVyfhyyPu9oeutWisgcGjQJw
         qu9HKON5jFBGQPH+3reYpLTSdejHvDVOIEB4qW+gcmXEqdlRs2W8e26Vm567fDCvr2oA
         3AZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fYbLOr0WG2Sy4iT+G8/KJ54A3cjQsUO1jF8Uo/pO9vw=;
        b=Cmo06MSzY9U4ml0oobLlNmVGxM4okYNm7z0T5YXzqnCF3XrjaRd3P0QkgHOGA3983/
         lPbCiMxBwdPPxspbFZXYbieCTwXyeCNi7ztKI5Vz03t+XrxnRpMXnlCk4KfcxA6VFzZc
         XUvyv71L20lrvRSHf9U8dd+pHPstJ+VzmBP2jpCZiDQYyncGuBGlDyX3Wi1zfHP8kRS1
         z86LU+FpCFqb/wNtJwnxNZtSCkBCCS2xpGxShafTJI5BdMOp8vd79wUoB8JBzEGwdNMz
         IOwKBHL+mmbh5FNszBL3WwKBXWE2rYdxr9D99rsy/ePw0JFzCHH05e0bRSj9P9WBI36A
         Bk8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=2UQhjcBh;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fYbLOr0WG2Sy4iT+G8/KJ54A3cjQsUO1jF8Uo/pO9vw=;
        b=I66SuE/t8XjlakUKGXb40j2jcld1atRpqk3CTr1mBdiKQtwau3oAulm2ghc3XSyIiN
         /wyTEU8aivQtpX3wR6wPvjJVDBQjQSMlxSi+8InXuVMzaf2wOqeWd9u+QlQTsWtHh80A
         Aa4qzlZi04px0lREYewHHSjYd6R+kwcW8H/BdKN69rKYw+fOOIMTDp6zaKrQ2NI5/nBa
         t3gmEbf4GE6a2WQkGxk3lCtrYE3ZP/8lEuEpjd3QPh8UNzVDIR1h2HD5vhqfvm+EN4kw
         BGLZDNmNHNsRZPK8wiSoPfaSg0JEOGP5K1j/5Fg+xcrgMH2FO+phvq/BQAz1LPxTi6bt
         /3/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fYbLOr0WG2Sy4iT+G8/KJ54A3cjQsUO1jF8Uo/pO9vw=;
        b=MzlbRmchzF6czkhpDSH+YGFMslgyiI12qBdolLefKxu5Lvf4kwvk9UPif82L6qPmq+
         cNUW+1PSSesyv/wfWxWulJ9JwShlgk5ifTsVM0Fr6rEMsi6G16wFXQ5bEc/Y3v4ta0J0
         X+JFweJpKXGGqz2Rqw2tLdk2GI4BBoY8B43SIUOH7wYt4KYVme3Fml/JGzl6JzpNrdCw
         7+/IYuA4B6cfkgIAGtRP0oQKgcOE4ukHsiM3Ep3yndzw+SWYZtzP3VcWBOs0NfRYkDXX
         FcALks6xjmfZdLZSJkG5vV7xh1uRkmGaHYmMAH+GpkN3JEYSP5G7a0fSq+pPBTGij/Wd
         1asg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vVubFi3ob+DYyDs5rSqAwhq6jfkLltX3ehxXkmWuVXhzsrxOC
	4XWZWgMY0/WdK/+aJjGJqQc=
X-Google-Smtp-Source: ABdhPJyI0lzhr+rBZMAsEJV+bE9TTMEkUfzSqHGbRQy9m82iwIXAs9lXgqCmyhupIhgs1B5On/NZMA==
X-Received: by 2002:a05:620a:12cf:: with SMTP id e15mr12317276qkl.459.1595699074959;
        Sat, 25 Jul 2020 10:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2a2:: with SMTP id m2ls2862319qvv.11.gmail; Sat, 25
 Jul 2020 10:44:34 -0700 (PDT)
X-Received: by 2002:a05:6214:140d:: with SMTP id n13mr3634388qvx.69.1595699074566;
        Sat, 25 Jul 2020 10:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595699074; cv=none;
        d=google.com; s=arc-20160816;
        b=GHgZF+b3jCNdoOzkTe7wfhn2fC3/4y30DUz8Em93aMmatNM+WYh8J74GKHIo5N6sjG
         TUHJ4Il5pQx+axJ+38gz96xSxr0LnlNT0jTM9Ds9xtI+KZ6OJDBvEph29vNw9YANSd6V
         tdeB2dvrsPLCYUje7hox1f1GEQ8sUVx5O4vluZW4NnvgbLag+1ceYtqjbfl9fot3Mv16
         fSHMOkL5KdXAi/Oy0MONVfEMkteSEGoC/2cCemFT85xZpfUTHnxBY+dTFSCyVnLmfj6r
         PJIYvmTYxa96sFqgVR9M6z1nxTNnlNAve7KT3YBA9xqrfPX8XCe6X46W4sKj7K6sOdZ3
         MWCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IzlB8C4ebbWL5U23JeDEz95EVKPJZOd57Pw+Ihb9yS4=;
        b=FRP3UdlZ/WQDwZFd+AdVkOOdUo3OBjW+kRsuoqTbkpaKpZ4Set3l+8ST77tYX+p0fn
         wY6NbttPQsL3qTYU+vBzIdjA/v7TBZtxwFiscjS+t7AzOjwB6wIitRKBwTQlMFlmxZMB
         ELN18iPAEnB97MN52GZrPVB/MoV9YleiqFozJlXZD0QOpLFUTgXxQ/ByiDbmYN3F53Yj
         KAYkEjD7Dz8nm62XpByONtdvjOTXQrc2/MO7U13sLiQvrr8yU34eqRYPJRWXVuZFF+96
         THoPlynzNozhmBmQ1M5dI1j3YLKqmmnLJyFgDrZq3G7xradGuHMbUHvibw4PIW9Vc3rO
         MRnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=2UQhjcBh;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id w5si681133qki.1.2020.07.25.10.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 25 Jul 2020 10:44:34 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jzODo-0008IH-Qa; Sat, 25 Jul 2020 17:44:33 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 1283E301179;
	Sat, 25 Jul 2020 19:44:31 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id EC37120104627; Sat, 25 Jul 2020 19:44:30 +0200 (CEST)
Date: Sat, 25 Jul 2020 19:44:30 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200725174430.GH10769@hirez.programming.kicks-ass.net>
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=2UQhjcBh;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Sat, Jul 25, 2020 at 05:17:43PM +0200, Marco Elver wrote:
> On Sat, 25 Jul 2020 at 16:56, Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Thu, Feb 20, 2020 at 10:33:17PM +0100, Marco Elver wrote:
> > > On Thu, 20 Feb 2020, Paul E. McKenney wrote:
> > > > On Thu, Feb 20, 2020 at 03:15:51PM +0100, Marco Elver wrote:
> > > > > Add option to allow interrupts while a watchpoint is set up. This can be
> > > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > > > > parameter 'kcsan.interrupt_watcher=1'.
> [...]
> > > > > As an example, the first data race that this found:
> > > > >
> > > > > write to 0xffff88806b3324b8 of 4 bytes by interrupt on cpu 0:
> > > > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]
> > > > >  __rcu_read_lock+0x3c/0x50 kernel/rcu/tree_plugin.h:373
> [...]
> > > > > read to 0xffff88806b3324b8 of 4 bytes by task 6131 on cpu 0:       |
> > > > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  ----+
> [...]
> > > > >
> > > > > The writer is doing 'current->rcu_read_lock_nesting++'. The read is as
> > > > > vulnerable to compiler optimizations and would therefore conclude this
> > > > > is a valid data race.
> > > >
> > > > Heh!  That one is a fun one!  It is on a very hot fastpath.  READ_ONCE()
> > > > and WRITE_ONCE() are likely to be measurable at the system level.
> > > >
> > > > Thoughts on other options?

> > > diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
> > > index c6ea81cd41890..e0595abd50c0f 100644
> > > --- a/kernel/rcu/tree_plugin.h
> > > +++ b/kernel/rcu/tree_plugin.h
> > > @@ -350,17 +350,17 @@ static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
> > >
> > >  static void rcu_preempt_read_enter(void)
> > >  {
> > > -     current->rcu_read_lock_nesting++;
> > > +     local_inc(&current->rcu_read_lock_nesting);
> > >  }
> > >
> > >  static void rcu_preempt_read_exit(void)
> > >  {
> > > -     current->rcu_read_lock_nesting--;
> > > +     local_dec(&current->rcu_read_lock_nesting);
> > >  }
> > >
> > >  static void rcu_preempt_depth_set(int val)
> > >  {
> > > -     current->rcu_read_lock_nesting = val;
> > > +     local_set(&current->rcu_read_lock_nesting, val);
> 
> > I agree that this removes the data races, and that the code for x86 is
> > quite nice, but aren't rcu_read_lock() and rcu_read_unlock() going to
> > have heavyweight atomic operations on many CPUs?
> >
> > Maybe I am stuck with arch-specific code in rcu_read_lock() and
> > rcu_preempt_read_exit().  I suppose worse things could happen.
> 
> Peter also mentioned to me that while local_t on x86 generates
> reasonable code, on other architectures it's terrible. So I think
> something else is needed, and feel free to discard the above idea.
> With sufficient enough reasoning, how bad would a 'data_race(..)' be?

Right, so local_t it atrocious on many architectures, they fall back to
atomic_t.

Even architectures that have optimized variants (eg. Power), they're
quite a lot more expensive than what we actually need here.

Only architectures like x86 that have single instruction memops can
generate anywhere near the code that we'd want here.

So the thing is, since RCU count is 0 per context (an IRQ must have an
equal amount of rcu_read_unlock() as it has rcu_read_lock()), interrupts
are not in fact a problem, even on load-store (RISC) architectures
(preempt_count has the same thing).

So the addition/subtraction in rcu_preempt_read_{enter,exit}() doesn't
need to be atomic vs interrupts. The only thing we really do need is
them being single-copy-atomic.

The problem with READ/WRITE_ONCE is that if we were to use it, we'd end
up with a load-store, even on x86, which is sub-optimal.

I suppose the 'correct' code here would be something like:

	*((volatile int *)&current->rcu_read_lock_nesting)++;

then the compiler can either do a single memop (x86 and the like) or a
load-store that is free from tearing.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200725174430.GH10769%40hirez.programming.kicks-ass.net.
