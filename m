Return-Path: <kasan-dev+bncBAABBINK376QKGQEFDD5BHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 449E12BAC07
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 15:39:31 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id y62sf7069371pfg.13
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 06:39:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605883170; cv=pass;
        d=google.com; s=arc-20160816;
        b=J4UFUZKvXPIdgVQak/+3hQDlLAXpP274RqtCQsxMRNMyS7ubjE9rGZa9MqwJpSb3nK
         DLjvF2XdJ+lNRhS2qOnFl930LMnCqAynv1VgCejv+z0vZ4uxEeoYZc5S7K9CbmRDE0on
         T0/+U1emt4LZle4VStKBPnyVF1CTD8fnbvxJmBBZzummq+yB5pD+Sa/ncEKWzVwM0pAm
         LCHeICqYzz8dOvrvLRx0zj4EjQlEDLQuU11yQLHTZHi6p55OKvJFoD48sPqQwPcXRPn1
         ViUmzVPMmsr0lik7WbC/wcKkm99hhW8Y58TJbhwQO+AJbL+VDRq3wCgBMN3Gt/cVI8oG
         cWdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=FgTqus5eIzxxcyCr+3GmI1MWKapcqys1bxtK728Xp2Q=;
        b=MoOtarlkx9nlVlF9T2R8wljbHqx/r6+sRWp4zymDwWC75O03lsls7CoclnsPZ7s2R6
         6qNgeFOs3WPzuUB/Wt3nPHyqGrYd4mmFogGIAcK4O6XL+LxvpvD1MHFyJWUD9FyO1Dm2
         hW9nuNoP+XWkOj3KZG/9U5G5RFeCa8HSvBiUunxUbDBSbLPCNU0cJq3yWkfH50TJEkXs
         ig/Oang3rVZ7A7aUDb1E2xxHWg3GgTYe9VtsJpAKcDqE4AabId3cCFnf1ffRG7R6B4Vk
         /AcM07PpzWrqvX6g+fovoWYJ02zRjhr33POm7+EekhKYcwchCoCtXP1B3MZv98eTrfja
         +rOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=FmgQYZ4o;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FgTqus5eIzxxcyCr+3GmI1MWKapcqys1bxtK728Xp2Q=;
        b=sPLf1tgPgx6e5Zszv6PNwSQC5veRt1baQFWQ1ZWSRSxuBMdeaT37RJEFEb2jQ5m5fu
         7rBE7/ERRy37cWQ58aEajCq6JTp85EIvCUUs/g9nGy0kh2WXT8kdqDTPkuZLU1lTFj1z
         aLtOkCTUHGD2QefERue0khsBqJyCsd2fTWGKycQdLxJtxbP+IzbF5KKqUhhda79Zjvt6
         anOikpEv2k3vUs+vCSP2KW7dHoAP+jZl2Z3SthXW1kpiUmuHtwkF+SmQ4gg8lknXVfdy
         zbUPrPHsCpDjVjaeFZhgmE9axMu5d9bjv3Jvecv0KEG2OscFAVZzAUFEg75bWaPbuOpY
         nMgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FgTqus5eIzxxcyCr+3GmI1MWKapcqys1bxtK728Xp2Q=;
        b=WmNnPj5lDQPpwdNfPXXfFhkyE4xtyol6VgwkrL0Bj4YfLXnaI/vOn8bA/BkOCMOrr1
         rA3NXgIIDd+7cq7KsmDO6rOvirh7XK3V3vZlp7sxPWr8VsL0AXnb4Xv+0S/lH/TSt/vU
         sNzRfRPN89f+NOuWeIlf5BGhXSJdVsqvyYRwbEKLXRqjgPjF4buPh9VESMoYkSm45wGy
         80WlDoLthfiQRgcSfq0bLg3cXb7b27E4G2NVJehRy3tpEa8RdLRCrlNK2Z2y20FBgAar
         1PGkD1D+i2Yw/ciXgw4LtUBlVtMp5Z8l016fjCyeO4gz8jhIw5ViF1fCFrQJu0qnR26m
         sI2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530aDIGWINlG00soZjK2V4Q3OGx8jPQQf165apLwtQ9Urbr1XGQs
	GItALowC6Stc1TviIVRSVRg=
X-Google-Smtp-Source: ABdhPJzX4vQEqRsC1XFR+jK+PzVhdZDxrkidjmMEy457AWzY0vxCx0g/C12nXSGW1PlSSOVUSTpAUg==
X-Received: by 2002:a17:902:ff16:b029:d8:d74d:2e3c with SMTP id f22-20020a170902ff16b02900d8d74d2e3cmr13774490plj.62.1605883169986;
        Fri, 20 Nov 2020 06:39:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8508:: with SMTP id bj8ls3284281plb.2.gmail; Fri, 20
 Nov 2020 06:39:29 -0800 (PST)
X-Received: by 2002:a17:902:70c1:b029:d9:2d09:69e with SMTP id l1-20020a17090270c1b02900d92d09069emr11752349plt.59.1605883169544;
        Fri, 20 Nov 2020 06:39:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605883169; cv=none;
        d=google.com; s=arc-20160816;
        b=O0Y2Ea18yIPv8dsNRZy6k3HLtzUYxKq5mrthhEwGFlsfAZG3rae9yB2jPqUvhcOrav
         9uPP9Cz2tgunMm/AHV3bUCfa3O273Cl8pztkHIj96g4caVTZBOqQ/ThcNa4rRJCSkup8
         swHTot5yChqCSuxSE31bmlbxzVL/+nr0C36xS3jrauZvyaf6IFvbeyBVAjJRtQT+hUIp
         oKMIREMCXs7moIuBm3KBrL2Xvf0ZsKfuEZyEEC45lCLn6xibVTOfxqAczhfb6UuEgsD2
         egsuhSTFAd8LrHqSG2rsndQFSJ5WRBNPXZ4RLap/xKCurJtwdshOO6n9OePmaODBTKVA
         7v3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=90DdBLsuMUDu8BZ97cs72i1+FH5dwhj4KmV1r7NIBDY=;
        b=w/L11+WvVMi+APXu2v7XAOHoQfiqIp0UTGpdXSx6uX0FuIGjFtJQCjHXx9suArd99s
         G3k78NtM/c/uOV5EGI8PvUsQ1t5PA6+hRXP2aVAGCfqhqV+7EF0sqOeH5HPIzZFrAnmZ
         rEleEnj17VSTFP13K9ZgrZfebFoUGxxbUmq6DsgO12ovXmgNi8fMR0+toCNi/21pw2NU
         sr63VL0PbSa1EBh8Zo4Lp9P3tw9u2zusHUEBpXT91i3sampnWxXoZ4Vr1K5OQtPClA3h
         8Z1CZq3kBJ0SrwOf1u/MSP3PAAL4RthI6wmPyQHhza+tlXZepaCSsRNj5DxSNaGoEM+U
         TrXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=FmgQYZ4o;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h11si240793plr.1.2020.11.20.06.39.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 06:39:29 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0E7122224C;
	Fri, 20 Nov 2020 14:39:29 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id AEB373522A6E; Fri, 20 Nov 2020 06:39:28 -0800 (PST)
Date: Fri, 20 Nov 2020 06:39:28 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
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
Message-ID: <20201120143928.GH1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201120141928.GB3120165@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120141928.GB3120165@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=FmgQYZ4o;       spf=pass
 (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 20, 2020 at 03:19:28PM +0100, Marco Elver wrote:
> On Thu, Nov 19, 2020 at 01:35PM -0800, Paul E. McKenney wrote:
> > On Thu, Nov 19, 2020 at 08:38:19PM +0100, Marco Elver wrote:
> > > On Thu, Nov 19, 2020 at 10:48AM -0800, Paul E. McKenney wrote:
> > > > On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:
> > 
> > [ . . . ]
> > 
> > > > > I can try bisection again, or reverting some commits that might be
> > > > > suspicious? But we'd need some selection of suspicious commits.
> > > > 
> > > > The report claims that one of the rcu_node ->lock fields is held
> > > > with interrupts enabled, which would indeed be bad.  Except that all
> > > > of the stack traces that it shows have these locks held within the
> > > > scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
> > > > try_invoke_on_locked_down_task() with irqs disabled" but without the
> > > > "sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
> > > > commit, I understand why.  With both, I don't see how this happens.
> > > 
> > > I'm at a loss, but happy to keep bisecting and trying patches. I'm also
> > > considering:
> > > 
> > > 	Is it the compiler? Probably not, I tried 2 versions of GCC.
> > > 
> > > 	Can we trust lockdep to precisely know IRQ state? I know there's
> > > 	been some recent work around this, but hopefully we're not
> > > 	affected here?
> > > 
> > > 	Is QEMU buggy?
> > > 
> > > > At this point, I am reduced to adding lockdep_assert_irqs_disabled()
> > > > calls at various points in that code, as shown in the patch below.
> > > > 
> > > > At this point, I would guess that your first priority would be the
> > > > initial bug rather than this following issue, but you never know, this
> > > > might well help diagnose the initial bug.
> > > 
> > > I don't mind either way. I'm worried deadlocking the whole system might
> > > be worse.
> > 
> > Here is another set of lockdep_assert_irqs_disabled() calls on the
> > off-chance that they actually find something.
> > 
> > 							Thanx, Paul
> > 
> > ------------------------------------------------------------------------
> > 
> > commit bcca5277df3f24db15e15ccc8b05ecf346d05169
> > Author: Paul E. McKenney <paulmck@kernel.org>
> > Date:   Thu Nov 19 13:30:33 2020 -0800
> > 
> >     rcu: Add lockdep_assert_irqs_disabled() to raw_spin_unlock_rcu_node() macros
> 
> None of those triggered either.
> 
> I found that disabling ftrace for some of kernel/rcu (see below) solved
> the stalls (and any mention of deadlocks as a side-effect I assume),
> resulting in successful boot.
> 
> Does that provide any additional clues? I tried to narrow it down to 1-2
> files, but that doesn't seem to work.

There were similar issues during the x86/entry work.  Are the ARM guys
doing arm64/entry work now?

							Thanx, Paul

> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> diff --git a/kernel/rcu/Makefile b/kernel/rcu/Makefile
> index 0cfb009a99b9..678b4b094f94 100644
> --- a/kernel/rcu/Makefile
> +++ b/kernel/rcu/Makefile
> @@ -3,6 +3,13 @@
>  # and is generally not a function of system call inputs.
>  KCOV_INSTRUMENT := n
>  
> +ifdef CONFIG_FUNCTION_TRACER
> +CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
> +endif
> +
>  ifeq ($(CONFIG_KCSAN),y)
>  KBUILD_CFLAGS += -g -fno-omit-frame-pointer
>  endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120143928.GH1437%40paulmck-ThinkPad-P72.
