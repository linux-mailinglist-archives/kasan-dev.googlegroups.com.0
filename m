Return-Path: <kasan-dev+bncBC7OBJGL2MHBBANY576QKGQE6KI43VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D6FB2C0F74
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 16:57:54 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id d3sf6784652eds.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 07:57:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606147074; cv=pass;
        d=google.com; s=arc-20160816;
        b=0S6aRocUjNqPSmEErYd2Fo1ehJurWLdpto+1g0pxmEdRByF+/KrEtcy05EQsPrzzpn
         GiHgHHVd/vseggQifjsMR73VNhL+XWZ3A4F3rZZr10myt1Rs/eo3kcKWZsMjmuNwI/xe
         fdWW5wmdD9ZpTSCwVCbscbPL2OPGjsAQD++L39mN2TO1aGohqd/TwbZ2Pm+iPEHipJWd
         rvjsc8MXQ7+NBIe6/wSyHWvz1Rh/Mfk8PXE6qkRa9cp1K+aMk6ij/0QnmHnt52dlfJBD
         cBxz48L7WF+LXcIR3k9tSRvaKPdlVcfu6QzhUR/0gNNgobo4NgBRHDZ6lKnGMTuUTsCJ
         IIFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QFsjiALQ9QIVkZ7jcYLhUrtDHIZ9MfZ6SE2++ehmNhE=;
        b=HhtgBQ9gXmqfODCo/a+W3zW7rjlPSo1m0UPw/r9X5LhX/1eIN3irW47olNK92Cbd++
         BZi52Rvexr80yU5WIoQiJqcIUly6f6/FRPHlHmH7dzNd0g9IfeHI/rpXox4IFvYIWQt4
         8LccpbcYK0bx1XlyqBRdHTgmgrusRV/27ybCpmKg9z3SgVWahyKayP7NkIPqy5I0hZdF
         hvsy/6hWpFxucPe7TyXvOLYmDX8L/65q5D2mmeAl9zVFKmfj/ZNt0XKEta+Nx8nyDF3L
         qTe/X2wLKliBsDTLTCtQ09S6S4ojJO0QbBwxu45ADSwV7FuA5/qXqVbhdnF3Qdibz+Th
         DljQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YdEjW3Mq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QFsjiALQ9QIVkZ7jcYLhUrtDHIZ9MfZ6SE2++ehmNhE=;
        b=kkfc1S23GlfubWJAbSZfT6VNfzzJvgxLp9TKYF7BQkP8XZC1Hv6xnbMwDTqSGQwves
         ZEOTnkutmy+LD3bRdifGcvxpwcGeMxkJdhEFqLC25dRMudX6NVZNWkm7Qw4TTE8FLFUw
         VZScwz2v4EGnPn6OK7DAr7XQDe56jdqP/Ee+41KGFjSW66FCyH4OBNKfy/ZPcvNaH6Mz
         qyxg3mtD0pqLPCNyNb/gNk1bsTddP+x+yOvxem4cIOvrxvJIqXLnzjpBLn0tSkhXOod6
         Maiu9YGezka9Zn6HnmvEQFyTZWTUJh3Aqoui7BF9gIWgU2C4ydeJrDMbKV68PMPLezYn
         JjIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QFsjiALQ9QIVkZ7jcYLhUrtDHIZ9MfZ6SE2++ehmNhE=;
        b=Oi1G+v3viWmqaBLenjvD86amqj2MZNbRdldzhcA8MVqGUA4xZGXZAJGlprCMaTFfVO
         Tq0RAV4+hGB7fL7fg1ZoQFEwlfSL3Bnoa9TPF0/u8wVrMjxNpYhOnVq5TBxC9D9qPt7I
         QsTpOb2L+tkB4knbQgkC3/gpBRFauHEdgsb9OehFuyV0kp1Sxhyb4KEBxAAzSYQFzbCU
         wJVRg5PPK87dK0czlDrv0qKUfsfXj/6pXsqxK+qBDVs7Y2yETh6ULNg+OYNqqB4r7ATj
         vV7gPRJZv8zGpshYNHUjPTMYo9Pj8tSbyyUhSvkzfokbBnrnJ690P7d/2gzlTYActGW8
         eOZQ==
X-Gm-Message-State: AOAM530AbFMq8gyQjeCnV5nBaYWE/r/ChToPIy2PSxf099x0JE3u/YWF
	v5QB1DnDyJ+nwZ24PrNnwF8=
X-Google-Smtp-Source: ABdhPJwdSBQkNphoKuGGP5eHc7PhLapTbp/fRh5OISqorTEATVTbWxZXyAqfZFuJxgcibFBL7eSoQg==
X-Received: by 2002:a05:6402:32c:: with SMTP id q12mr9222357edw.85.1606147073949;
        Mon, 23 Nov 2020 07:57:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5591:: with SMTP id y17ls6261949ejp.5.gmail; Mon, 23
 Nov 2020 07:57:52 -0800 (PST)
X-Received: by 2002:a17:906:26c6:: with SMTP id u6mr214694ejc.349.1606147072866;
        Mon, 23 Nov 2020 07:57:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606147072; cv=none;
        d=google.com; s=arc-20160816;
        b=hqPR3+E9hw7uKyxBLn8dmzSe6hbLNTpdmLdvSHzICM6SHqF+QEADIE9B3gxoWr+oGr
         pw9xhCoVfMhqdebNWKpV4QlbD1WZa0kUHFPqyieY2gXTnCCf7H9zHbZZ8ZNBEf0Z4G1T
         VAcg8iOUAFQOpR/7iCg8Zc6h9ZCGqyP2vBlqpNNGdx3Z1ZG54SPEY2T5Sn4+C7c6Hm8x
         FjTRoCwQV2pfZ3a9jrblG16wa5n6LGpFhXkp9tFaexLtYv3mfb0ZAnehxcOb3rSlA2MS
         gfpT19dGVbuV8G9edr9Nlh2UmpQ1Ga9ysfwCwg93I6tCWJOiJbE4hOHvnqHhzvlhiZlx
         P75g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=k+kniU7gxDfT8jCCuCcVQlgGKYH8uUnra1Ilt/IrXFs=;
        b=Eg9ns7XTA3QK2ixTchRMrd6rAv0nHS5Y9M5yTPz1KmnIRy/5F33qs+07BLLAfFjbHW
         I5dJMOK0QUaT7rvs4j9UVzFLox6dWRkBYPS5F5bUAXw5ODqW/5XznkNrjW9KfBL3Xq5c
         0ZlPKOu5Z14Cxr0yUEcmcttsVA1YzU2zBlvCJx6OZAR5kMOncm3WG4d6sOARZbjlIBkF
         0ZpcCThGs/p3CaFPamotvXlWEPQis81Qjd3d4+vTUnjMOxjxRRhk+N96nLeBiw1ocCR/
         aZDbZIg6StWJUM8ZT9LG/5cm9durGet4mte12ICWJNHzCelu7GfQFamL3IdVIMuOb43y
         FSbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YdEjW3Mq;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id c11si336330edn.0.2020.11.23.07.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 07:57:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id 23so19058073wrc.8
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 07:57:52 -0800 (PST)
X-Received: by 2002:adf:de85:: with SMTP id w5mr360547wrl.90.1606147072382;
        Mon, 23 Nov 2020 07:57:52 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id u23sm17844378wmc.32.2020.11.23.07.57.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Nov 2020 07:57:51 -0800 (PST)
Date: Mon, 23 Nov 2020 16:57:46 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Will Deacon <will@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v2] kcsan: Avoid scheduler recursion by using
 non-instrumented preempt_{disable,enable}()
Message-ID: <20201123155746.GA2203226@elver.google.com>
References: <20201123132300.1759342-1-elver@google.com>
 <20201123135512.GM3021@hirez.programming.kicks-ass.net>
 <CANpmjNPwuq8Hph3oOyJCVgWQ_d-gOTPEOT3BpbR2pnm5LBeJbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPwuq8Hph3oOyJCVgWQ_d-gOTPEOT3BpbR2pnm5LBeJbw@mail.gmail.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YdEjW3Mq;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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

On Mon, Nov 23, 2020 at 04:17PM +0100, Marco Elver wrote:
> On Mon, 23 Nov 2020 at 14:55, Peter Zijlstra <peterz@infradead.org> wrote:
> > On Mon, Nov 23, 2020 at 02:23:00PM +0100, Marco Elver wrote:
> > > When enabling KCSAN for kernel/sched (remove KCSAN_SANITIZE := n from
> > > kernel/sched/Makefile), with CONFIG_DEBUG_PREEMPT=y, we can observe
> > > recursion due to:
> > >
> > >       check_access() [via instrumentation]
> > >         kcsan_setup_watchpoint()
> > >           reset_kcsan_skip()
> > >             kcsan_prandom_u32_max()
> > >               get_cpu_var()
> > >                 preempt_disable()
> > >                   preempt_count_add() [in kernel/sched/core.c]
> > >                     check_access() [via instrumentation]
> > >
> > > Avoid this by rewriting kcsan_prandom_u32_max() to only use safe
> > > versions of preempt_disable() and preempt_enable() that do not call into
> > > scheduler code.
> > >
> > > Note, while this currently does not affect an unmodified kernel, it'd be
> > > good to keep a KCSAN kernel working when KCSAN_SANITIZE := n is removed
> > > from kernel/sched/Makefile to permit testing scheduler code with KCSAN
> > > if desired.
> > >
> > > Fixes: cd290ec24633 ("kcsan: Use tracing-safe version of prandom")
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > v2:
> > > * Update comment to also point out preempt_enable().
> > > ---
> > >  kernel/kcsan/core.c | 15 ++++++++++++---
> > >  1 file changed, 12 insertions(+), 3 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > > index 3994a217bde7..10513f3e2349 100644
> > > --- a/kernel/kcsan/core.c
> > > +++ b/kernel/kcsan/core.c
> > > @@ -284,10 +284,19 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
> > >   */
> > >  static u32 kcsan_prandom_u32_max(u32 ep_ro)
> > >  {
> > > -     struct rnd_state *state = &get_cpu_var(kcsan_rand_state);
> > > -     const u32 res = prandom_u32_state(state);
> > > +     struct rnd_state *state;
> > > +     u32 res;
> > > +
> > > +     /*
> > > +      * Avoid recursion with scheduler by using non-tracing versions of
> > > +      * preempt_disable() and preempt_enable() that do not call into
> > > +      * scheduler code.
> > > +      */
> > > +     preempt_disable_notrace();
> > > +     state = raw_cpu_ptr(&kcsan_rand_state);
> > > +     res = prandom_u32_state(state);
> > > +     preempt_enable_no_resched_notrace();
> >
> > This is a preemption bug. Does preempt_enable_notrace() not work?
> 
> No it didn't, because we end up calling preempt_schedule_notrace(),
> which again might end in recursion.
> 
> Normally we could surround this by
> kcsan_disable_current/kcsan_enable_current(), but that doesn't work
> because we have this sequence:
> 
>      reset_kcsan_skip();
>      if (!kcsan_is_enabled())
>          ...
> 
> to avoid underflowing the skip counter if KCSAN is disabled. That
> could be solved by writing to the skip-counter twice: once with a
> non-random value, and if KCSAN is enabled with a random value. Would
> that be better?

See below for concrete alternative that works.

> And I'd like to avoid adding __no_kcsan to scheduler functions.
> 
> Any recommendation?

Let me know what you prefer.

Thanks,
-- Marco

------ >8 ------

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 10513f3e2349..c8eadef3f42a 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -266,8 +266,8 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
 		return false;
 
 	/*
-	 * NOTE: If we get here, kcsan_skip must always be reset in slow path
-	 * via reset_kcsan_skip() to avoid underflow.
+	 * Note: If we get here, kcsan_skip must always be reset in slow path to
+	 * avoid underflow.
 	 */
 
 	/* this operation should be watched */
@@ -288,27 +288,19 @@ static u32 kcsan_prandom_u32_max(u32 ep_ro)
 	u32 res;
 
 	/*
-	 * Avoid recursion with scheduler by using non-tracing versions of
-	 * preempt_disable() and preempt_enable() that do not call into
-	 * scheduler code.
+	 * Avoid recursion with scheduler by disabling KCSAN because
+	 * preempt_enable_notrace() will still call into scheduler code.
 	 */
+	kcsan_disable_current();
 	preempt_disable_notrace();
 	state = raw_cpu_ptr(&kcsan_rand_state);
 	res = prandom_u32_state(state);
-	preempt_enable_no_resched_notrace();
+	preempt_enable_notrace();
+	kcsan_enable_current_nowarn();
 
 	return (u32)(((u64) res * ep_ro) >> 32);
 }
 
-static inline void reset_kcsan_skip(void)
-{
-	long skip_count = kcsan_skip_watch -
-			  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
-				   kcsan_prandom_u32_max(kcsan_skip_watch) :
-				   0);
-	this_cpu_write(kcsan_skip, skip_count);
-}
-
 static __always_inline bool kcsan_is_enabled(void)
 {
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
@@ -430,10 +422,16 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
 	 * should_watch().
 	 */
-	reset_kcsan_skip();
-
-	if (!kcsan_is_enabled())
+	if (likely(kcsan_is_enabled())) {
+		long skip_count = kcsan_skip_watch -
+				  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
+					   kcsan_prandom_u32_max(kcsan_skip_watch) :
+					   0);
+		this_cpu_write(kcsan_skip, skip_count);
+	} else {
+		this_cpu_write(kcsan_skip, kcsan_skip_watch);
 		goto out;
+	}
 
 	/*
 	 * Special atomic rules: unlikely to be true, so we check them here in
diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index 5fc9c9b70862..21fb5a5662b5 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -7,12 +7,6 @@ endif
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
 
-# There are numerous data races here, however, most of them are due to plain accesses.
-# This would make it even harder for syzbot to find reproducers, because these
-# bugs trigger without specific input. Disable by default, but should re-enable
-# eventually.
-KCSAN_SANITIZE := n
-
 ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
 # According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
 # needed for x86 only.  Why this used to be enabled for all architectures is beyond

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123155746.GA2203226%40elver.google.com.
