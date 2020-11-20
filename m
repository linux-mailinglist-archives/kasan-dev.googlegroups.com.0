Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSMQ4D6QKGQEA2X2LZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 988902BB245
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 19:17:46 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id j3sf2271766ljg.14
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 10:17:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605896266; cv=pass;
        d=google.com; s=arc-20160816;
        b=CuRHsUXXZSOKkWh2vtxe6q+9FZZgwnZNrKdue23Xa5YYkS3WbM/CgabyCdTJD9asjM
         4IrBOLlazh1m3HZ6bMIFomRTi5u2gpFjJmXXcLZ71OcVvpS2YJ1JvYUVmLkS6uOSSlsd
         84JVu3NsC4WQmOO56Cnr02CGh0UwLbCsSig7Y7brqNGBzBlp/bJdyI8ZbTOLvxyc1Tt2
         DlScm7Xj2oMIyixtdyUV7wZ7j7QpTMeId6P8OmM6gpG/bU/gPOycqYYbTq8LeJicjDYB
         9+68plonenxuCmbUyQzXUCwVCg7S34G6uwTApTrEWrIIxhYg4T7g9OtWpHIqnaXcxvlD
         NR+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=NgXCO5C0rgJ3MwcZLf+SMLrH3oExjQ8UWpWHY3LxZVs=;
        b=bfcA8/4FYA5Rn5T8Yepizw3AwdsW804jC0AXxHTPo+9VbduFEK6bIMEfG+AICHQ1jm
         Q6rLDujTaN5vmpwjp2oVk+ZHMNCsgpo+IuzXAGYldgw+e2z2ndqOkkIViPofvZNaYlwi
         uKwCQs2XapKlmHL187gpOGAKH0BT37RFjFO6iq2aAnuSXJPpyVF93i2r8mqGgja7pa1d
         KyquaE0tDDZsz+3qcEY3UEdaorYflx2upjrzi27pukvmwE1eV20t2CX/nHCHecnlQpDr
         RQmY2eqAw9idGQbrX2NU0U7x8b9SS4FCGa5T91uEg8o8MykK9oxVNhw2pOc9URj7yGPK
         R1BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wFr1zLBj;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=NgXCO5C0rgJ3MwcZLf+SMLrH3oExjQ8UWpWHY3LxZVs=;
        b=Ae/Cm3r18ILtwwA7oem0dq17JEn58wB+o1zAa6X7SVEYqGGMSpZR5R6+QTjhAlLBPU
         dY9pA5zq6Q4e1SYtRXUBEV9fdkeCAOOQmoZ9N7P3icRc0apnTBw4ZvLIMA3eRuMpVLKG
         KlDYVRX74kxNsRP/tQ5h7mOn2KRoW9LPwpz5aDgLE13ReNQftl+jYHS0AfIjzJobMiRR
         PP03pGdJl28bZ1Xo8TUYyQg694Oc+8uL4UaQ4FH0Di4LL+BIZmqB4ed2k55Ia+DeGmzC
         PowEUxjFpCTkl7eQ4F1uBI+N+iwmpRbNoOnq6hJ2A+vX3Rf35+q51MXuWF9z803+BuhS
         k86g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NgXCO5C0rgJ3MwcZLf+SMLrH3oExjQ8UWpWHY3LxZVs=;
        b=Ipw2kDmF+X5I0QoNhhcP7c49DsggiTx08Mbv/GuP779I7F+quhc2PPGTGAp1gHCPxV
         ZCeBBiBp34jbP+Sl+oG7p76fkNFFU03Vk6uAtYIXvmv/HlF3lcrMyI8fjW3ObuVUlHpX
         QUeUHShIVQZmcYGzHQl0+QfWCPfKx3+KJd+xrY53dTERABpW4+P1gzo/sbz1t5oJPNaA
         QkTYyJLN3V6ffKgg7YZVnvW8I2VN+q5HA7lIieXxbhr89JPVYFjhf5tSh+LEO81iciTY
         UfkFZulgDok74GjODq524wr62VoHP/Br5al9mcXOxxACnx+7uMzFo/NNwKjBoVObxgI9
         aaGA==
X-Gm-Message-State: AOAM531KZ3rc66d7Ljawde9oOFN7YmzJM36vi/jO9G5P3j/QltFd0HVQ
	P2DzETPwB1OK27AmcsFN1XI=
X-Google-Smtp-Source: ABdhPJwjUPRzlN1S5W7MpkSi/ojbhyEWm1dF+G+1NBtSVYuNIIjN7HEd0TstEMatKuVCC4xE+mCMkw==
X-Received: by 2002:a19:154:: with SMTP id 81mr10019516lfb.161.1605896266085;
        Fri, 20 Nov 2020 10:17:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls1053001lfa.2.gmail; Fri, 20 Nov
 2020 10:17:44 -0800 (PST)
X-Received: by 2002:ac2:550d:: with SMTP id j13mr9393850lfk.301.1605896264833;
        Fri, 20 Nov 2020 10:17:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605896264; cv=none;
        d=google.com; s=arc-20160816;
        b=uvkRl9VF/ldkosuE1XrWKwbVkqYUQK8Yey8CEpT+nHt7zu3C5gBuCZAG6fO/OJ35oA
         hm/lZaO/U6Fuo6B/Zgveatfl4sQA+Q7WSFXtEn3JS7flMf7R7uZmDHHHHWNZuiejw2nH
         wxnHofEzezOzbEpWkRoyWg6KvRCFhpgOZz97FL4BNPd1oeAcAHE2wjvnY2mC/TQl6wmw
         sbZ0g7wm9dG3daW+zTFcCy6Z3Zo6Epnhx3/GzHAJmgkQDcG8ThCc024mix2i9SFbaojm
         aJAs5UJk2Qs22Zdxvm5dbFNTPEjhTc4fza2262g03YjaxMf26QvnsYB/EBUpav6aGlev
         ZN0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=giLwGu45+mkpAyteW5JjczsUwt2xu5kU0h/C4LFwJ2c=;
        b=vTR9DoCq9igQOvYYeKXy/znQ6d1H7WmV14s8QUXVf5bXj3JJAVRwLF1uehTkY0lSVM
         YW7pqhk9y8UoVHxeCuTopCNUARGZD9D+poMF22yCmodbolMfvQhoMRAFdlV5AmPJjlpQ
         ZAAOuPKvxOXRSjk/Tr5+8XrQXI3Z1z6UxSwcXZkEUllG5dhu6jacnX+ZrT8tobhptbsL
         bMDd3ts+9QWmX5e3IsNIy6hO6YBCN91ggypkFqzYE1CZRfpQBkdbZodqA05N1zto+Cxf
         9WbtMpKUzEJDd8lRBLIZfVqJuHq0DRSu9dW1aTLFyTGdlaMlw1AZSdeKuwIJV1DJTet/
         /R3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wFr1zLBj;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id f5si153079ljc.0.2020.11.20.10.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 10:17:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id m6so10943272wrg.7
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 10:17:44 -0800 (PST)
X-Received: by 2002:adf:9e4c:: with SMTP id v12mr16806903wre.22.1605896264123;
        Fri, 20 Nov 2020 10:17:44 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id g11sm6243435wrq.7.2020.11.20.10.17.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Nov 2020 10:17:43 -0800 (PST)
Date: Fri, 20 Nov 2020 19:17:37 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
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
Message-ID: <20201120181737.GA3301774@elver.google.com>
References: <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201120141928.GB3120165@elver.google.com>
 <20201120102613.3d18b90e@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120102613.3d18b90e@gandalf.local.home>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wFr1zLBj;       spf=pass
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

On Fri, Nov 20, 2020 at 10:26AM -0500, Steven Rostedt wrote:
> On Fri, 20 Nov 2020 15:19:28 +0100
> Marco Elver <elver@google.com> wrote:
> 
> > None of those triggered either.
> > 
> > I found that disabling ftrace for some of kernel/rcu (see below) solved
> > the stalls (and any mention of deadlocks as a side-effect I assume),
> > resulting in successful boot.
> > 
> > Does that provide any additional clues? I tried to narrow it down to 1-2
> > files, but that doesn't seem to work.
> > 
> > Thanks,
> > -- Marco
> > 
> > ------ >8 ------  
> > 
> > diff --git a/kernel/rcu/Makefile b/kernel/rcu/Makefile
> > index 0cfb009a99b9..678b4b094f94 100644
> > --- a/kernel/rcu/Makefile
> > +++ b/kernel/rcu/Makefile
> > @@ -3,6 +3,13 @@
> >  # and is generally not a function of system call inputs.
> >  KCOV_INSTRUMENT := n
> >  
> > +ifdef CONFIG_FUNCTION_TRACER
> > +CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
> > +endif
> > +
> 
> Can you narrow it down further? That is, do you really need all of the
> above to stop the stalls?

I tried to reduce it to 1 or combinations of 2 files only, but that
didn't work.

> Also, since you are using linux-next, you have ftrace recursion debugging.
> Please enable:
> 
> CONFIG_FTRACE_RECORD_RECURSION=y
> CONFIG_RING_BUFFER_RECORD_RECURSION=y
> 
> when enabling any of the above. If you can get to a successful boot, you
> can then:
> 
>  # cat /sys/kernel/tracing/recursed_functions
> 
> Which would let me know if there's an recursion issue in RCU somewhere.

To get the system to boot in the first place (as mentioned in other
emails) I again needed to revert
  "rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled",
as otherwise would run into the deadlock. That used to still result in
stall warnings, except when ftrace's recursion detection is on it seems.

With that, this is what I get:

| # cat /sys/kernel/tracing/recursed_functions
| trace_selftest_test_recursion_func+0x34/0x48:   trace_selftest_dynamic_test_func+0x4/0x28
| el1_irq+0xc0/0x180:     gic_handle_irq+0x4/0x108
| gic_handle_irq+0x70/0x108:      __handle_domain_irq+0x4/0x130
| __handle_domain_irq+0x7c/0x130: irq_enter+0x4/0x28
| trace_rcu_dyntick+0x168/0x190:  rcu_read_lock_sched_held+0x4/0x98
| rcu_read_lock_sched_held+0x30/0x98:     rcu_read_lock_held_common+0x4/0x88
| rcu_read_lock_held_common+0x50/0x88:    rcu_lockdep_current_cpu_online+0x4/0xd0
| irq_enter+0x1c/0x28:    irq_enter_rcu+0x4/0xa8
| irq_enter_rcu+0x3c/0xa8:        irqtime_account_irq+0x4/0x198
| irq_enter_rcu+0x44/0xa8:        preempt_count_add+0x4/0x1a0
| trace_hardirqs_off+0x254/0x2d8: __srcu_read_lock+0x4/0xa0
| trace_hardirqs_off+0x25c/0x2d8: rcu_irq_enter_irqson+0x4/0x78
| trace_rcu_dyntick+0xd8/0x190:   __traceiter_rcu_dyntick+0x4/0x80
| trace_hardirqs_off+0x294/0x2d8: rcu_irq_exit_irqson+0x4/0x78
| trace_hardirqs_off+0x2a0/0x2d8: __srcu_read_unlock+0x4/0x88

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120181737.GA3301774%40elver.google.com.
