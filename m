Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FA376QKGQEM6AYS6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A76A12BABBD
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 15:19:36 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id g5sf3444945wrp.5
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 06:19:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605881976; cv=pass;
        d=google.com; s=arc-20160816;
        b=AnlNdszjODI97BwVyivQdip4wk9a/KH2Za88CPaHnh19mI2/09S9TpzUThCkgfNOaw
         98lPP5cdOC3KL6+pMMcGCbxSb4Pjq/F5HwAa7XqyPv8UC+TyXBeK8MCitPjqMbqRakKl
         AvzTr9AYSKos4iFDO2FWUjdE6LwPHBiJ+7ItR619JIlIcE3jUi+esgIvvOyLKtpjXjMA
         TvFVrpd5EZc3NqIyXz0trrvEoSN4pfUmPobp6E0f4uHloccjSvQihMaagmvGrg/N3SQ/
         9tzNHfX40IgqgDn2zV5JXQe850vSjNZuVHFBr3XgNRKSXSzYNxwAq0NT/jAgay1zessg
         LRtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xFOphBLiVc/Oaelp8u+6V7c3WygZdHG9ps8w929ygM0=;
        b=ZRnlomKDr72GCxhPikhL593eqzOpVCMbKHM2wVqRNdUJ3GukYBL6FEHpav5y9Q51MK
         y/5du6DRGK3L9PE428VEB3IPhZmU/UMVb8plqe7oi1hXmQm7yJMZwi4r5xVZJoWGNJAj
         GCY4Pngjf4OF8qTUeGMHmC4iOtxn7ItRldPcGCgbC8TTeWvie3tfnVQww1yh8SdWfQ8K
         ng7KgWL+Y5W+0NRNursXJyqXvYc4gUi10sQuoczkUuUvFB7tKIhBdVcPdfAk/uSuuV6/
         S154akmsNGeN3wy0sTDJ5jbYgq7QgJT5fZnUYa8UIp2kbyh2jrj2errMRhOLJdkQHv9C
         GBKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f6nWmbpF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xFOphBLiVc/Oaelp8u+6V7c3WygZdHG9ps8w929ygM0=;
        b=FwK+uxD3clt5eiBkB6Gql7KG9Zi+wnNXttkr88EqGfoIZUiuyc10fnmxGhj8h++jDp
         RZE2TOjpWC/wm8eXAPMAycKQ1zitMuWT3EtN7S5Gr8SJwNFgNQ9f4v1GTQlsFkyxSOH/
         8FpAFlTCxJMTo6NHwNgUIuSBAsjVndfcKMFqpFjS0vdo63/neYbmmBNieviiyRX2yQjg
         3AwObqOh9rVx0qvumbnoDRH8UanKpdWb53LY/VQiOfm+/fmGBiwrz1/bVFVQ+6xGiktk
         7nZXwWJEYVIneLfrAYyx6vp7LDmZj7XpQBVi8njgSaR71nE9czHk+0GwY7pTuH8pwbTo
         WHOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xFOphBLiVc/Oaelp8u+6V7c3WygZdHG9ps8w929ygM0=;
        b=Q4VbrbLsMJ8opz7jPJVNdjeVet4pFq0ePduf0mXIoeDH38+ahkezvs6NEZfMLeCer8
         6v6tkQE87ock7s8CVTbfctFXd9RRtjlZk2fTHvgGl5SDv2BFAjriv5WK2vEKxmL4iG6/
         ntSqNbmxAY7tYc1qEIljkF4FX7jOADp5IXwn0tLY4of1Nv0EZLRmzeqJZVcnImltw41s
         VFyiaYTuEvGticFfhczr5ANJuMkvvwkauLAjzdbimGIOeKXTYDup+bJ4dKsuQuZvCtGc
         lr5ZmwtNMIr1LZIYWFRGCrX6lEJEqdD4T0sMkYHr4jvZbvZb9F5nc6wx5SOvzQjGleRO
         KpyA==
X-Gm-Message-State: AOAM531j7HEBLbSchLMzyl8P9sYh8iVheXBecRBZs5eq5/JCDoCUTHgz
	9uL0hXTjmtPpjO3us54kzDI=
X-Google-Smtp-Source: ABdhPJwBVzR37PljzjD0gVObrHxup3WrspDVtvz1jIvlXiRM9MT4wa50eMTfw1GqyneXrXzcVuxTAA==
X-Received: by 2002:a5d:670f:: with SMTP id o15mr17456070wru.204.1605881976474;
        Fri, 20 Nov 2020 06:19:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:67c6:: with SMTP id b189ls3459579wmc.1.gmail; Fri, 20
 Nov 2020 06:19:35 -0800 (PST)
X-Received: by 2002:a1c:bc08:: with SMTP id m8mr10898935wmf.137.1605881975465;
        Fri, 20 Nov 2020 06:19:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605881975; cv=none;
        d=google.com; s=arc-20160816;
        b=1HtUFD0RaYGsJZxTdBa5QZkYfBHPSpVwngIoLS343XE7+twPWPWTnFA29uTLWj9PZN
         v3YCsrUAXFebtptvDn0MzL+Uae81vBBMxwRnUENfzw6g2x6duDRoVwdPdMtoVq6FMg4F
         N/GJDEYwPa1D6LnsNv1hxFFijDnxWS3Ce63rnwNXXMYFygBapOrudr0prEb+b9goLt1n
         gv3wJRK3iOwUFFFVPxi+Pny3P385wd8SyFxPWjBcbPZhs8Bt+6OVjIJnb2cZJsCCcsDx
         FPc0mcPFcaSvLw8HSojf9x4P+z/UXmiVFdb5GfKIZxSwrMKHDBqW8WKM461FIfrMUyth
         s6Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xxByCDasYrQl9/cr/4ND1bYYvzVsnbPeWW4lsY9uHSo=;
        b=w5i8yBuhbZyNaCy027Lm5ql+YQDebBAbGwrmusqqOp1qcSnto5RGbL7GDjEXnsOcxC
         qOBSA7B4tObN7LW4lG6jPTCqoMt1Dn9E1wa0GWuM7q2GHzUVe9WAuWf7aCU4vPxQx29M
         0905mkCfepH0npd85UFe9r7D4GiCNAZdm51zNUlB5tOLOFW/jDIAAJZh4XKhbINJlwqh
         ODSAhObO64C4DTV2UaQs+gNq1+ugGgyKWAAcHF3z3xfv60Z/KLI+BAv0l5IWFRuYnDU6
         AIAwsASnPuRjPVVOEmAx+Xml8sgfmcj3Mm5ZIbgQBzuUh6u6nwo8nm2tT8ZfWv+BzIxD
         TyOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f6nWmbpF;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id m5si90771wmc.0.2020.11.20.06.19.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 06:19:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id r17so10250489wrw.1
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 06:19:35 -0800 (PST)
X-Received: by 2002:adf:e74d:: with SMTP id c13mr17088093wrn.277.1605881974917;
        Fri, 20 Nov 2020 06:19:34 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id l13sm5307917wrm.24.2020.11.20.06.19.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Nov 2020 06:19:33 -0800 (PST)
Date: Fri, 20 Nov 2020 15:19:28 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120141928.GB3120165@elver.google.com>
References: <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201119213512.GB1437@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f6nWmbpF;       spf=pass
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

On Thu, Nov 19, 2020 at 01:35PM -0800, Paul E. McKenney wrote:
> On Thu, Nov 19, 2020 at 08:38:19PM +0100, Marco Elver wrote:
> > On Thu, Nov 19, 2020 at 10:48AM -0800, Paul E. McKenney wrote:
> > > On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:
> 
> [ . . . ]
> 
> > > > I can try bisection again, or reverting some commits that might be
> > > > suspicious? But we'd need some selection of suspicious commits.
> > > 
> > > The report claims that one of the rcu_node ->lock fields is held
> > > with interrupts enabled, which would indeed be bad.  Except that all
> > > of the stack traces that it shows have these locks held within the
> > > scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
> > > try_invoke_on_locked_down_task() with irqs disabled" but without the
> > > "sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
> > > commit, I understand why.  With both, I don't see how this happens.
> > 
> > I'm at a loss, but happy to keep bisecting and trying patches. I'm also
> > considering:
> > 
> > 	Is it the compiler? Probably not, I tried 2 versions of GCC.
> > 
> > 	Can we trust lockdep to precisely know IRQ state? I know there's
> > 	been some recent work around this, but hopefully we're not
> > 	affected here?
> > 
> > 	Is QEMU buggy?
> > 
> > > At this point, I am reduced to adding lockdep_assert_irqs_disabled()
> > > calls at various points in that code, as shown in the patch below.
> > > 
> > > At this point, I would guess that your first priority would be the
> > > initial bug rather than this following issue, but you never know, this
> > > might well help diagnose the initial bug.
> > 
> > I don't mind either way. I'm worried deadlocking the whole system might
> > be worse.
> 
> Here is another set of lockdep_assert_irqs_disabled() calls on the
> off-chance that they actually find something.
> 
> 							Thanx, Paul
> 
> ------------------------------------------------------------------------
> 
> commit bcca5277df3f24db15e15ccc8b05ecf346d05169
> Author: Paul E. McKenney <paulmck@kernel.org>
> Date:   Thu Nov 19 13:30:33 2020 -0800
> 
>     rcu: Add lockdep_assert_irqs_disabled() to raw_spin_unlock_rcu_node() macros

None of those triggered either.

I found that disabling ftrace for some of kernel/rcu (see below) solved
the stalls (and any mention of deadlocks as a side-effect I assume),
resulting in successful boot.

Does that provide any additional clues? I tried to narrow it down to 1-2
files, but that doesn't seem to work.

Thanks,
-- Marco

------ >8 ------

diff --git a/kernel/rcu/Makefile b/kernel/rcu/Makefile
index 0cfb009a99b9..678b4b094f94 100644
--- a/kernel/rcu/Makefile
+++ b/kernel/rcu/Makefile
@@ -3,6 +3,13 @@
 # and is generally not a function of system call inputs.
 KCOV_INSTRUMENT := n
 
+ifdef CONFIG_FUNCTION_TRACER
+CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
+endif
+
 ifeq ($(CONFIG_KCSAN),y)
 KBUILD_CFLAGS += -g -fno-omit-frame-pointer
 endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120141928.GB3120165%40elver.google.com.
