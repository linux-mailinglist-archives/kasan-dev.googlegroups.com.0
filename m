Return-Path: <kasan-dev+bncBCS4VDMYRUNBBQV3V3AAMGQE725HSUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id BAC8AA9CBCB
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 16:35:48 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id af79cd13be357-7c95556f824sf250037385a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 07:35:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745591747; cv=pass;
        d=google.com; s=arc-20240605;
        b=c83jf5XsDoGZKdhfN1DAjSbGmtpuXCnAZE1Jeux60QgWt2x6+hQhq5fLb1k8rnd2/Y
         m3roz2vwPplSHFoXdlTjUy9QAajZocS/UlB+vG9EeiWWdW5uhrUbUX+Ii5exB5fsavtD
         pZIt8vu2cZufuvKY6yn5UF5oKRpGYE+WSSUUJHVPmOHhAXxIo9UHHozCCbXKw/IdNnQ7
         QvDsfiZ/nliZBNB2SlRe4jhKswvqxIEKv9kjJRTShOQoHzuTj5y1ozVt8TKkoFuXBOs4
         kCcs6EtVztY3cbAK3YykquamifBeiyuQ0Rg1AC6ZpAPToMVr81NPTjV8nfHLuruKlETu
         goSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9jz44E/cnHxn7b2MSvv2+wt7tN8HY5m8OnKJCF4lryE=;
        fh=oBKeZHSzPxC9fxHP/0c+bgUr2QR22SEP7BvxgX4sUfQ=;
        b=GX0CEp+C6Jj59SzhG+0U0whHKk41S6BEFyEJy4StapV6LLj97Tpz9yd3cTo/9VJY2a
         xvRJB7Oulnab5B3qwQCHdSAGH4BochPdZC8FQcx7/LeSODBJtiGfezrKJuvi/MryFwIC
         rK9ovk/a4VuFlfJhZXlE3nbSZElfzxRfhvPO95c1iN5v52gsF4PF+2PPkGw8jb1HELIo
         MX/ITA+aJHCfIAK2xkWi15x936vfmNnlA/XssnOGO2LiNuHQeSC+xLTKrm5wzfzMtWdr
         YPlcclVi4JKqZm7I65hC1lx3WXyqBWDNkCsXSrtzQYzL4QDzCX66dJN/vAOKfqnBMsor
         8lSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iXostuQV;
       spf=pass (google.com: domain of srs0=d47o=xl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=D47o=XL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745591747; x=1746196547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9jz44E/cnHxn7b2MSvv2+wt7tN8HY5m8OnKJCF4lryE=;
        b=XXjPYHWraFP9TbaZUuRdkS9hkXXqTowRHDq6lekqntARcdiWNEotiR3AC9uUkGxbtl
         b9ATRFbbM0bOYX6Vyap2scE9ETWaQRv5B4MK43EWEshYp3deBoXe3eFHZ/yvFyr13OBg
         hFpWgSwG5zIpJ8q86F9322dZ8cU6fwwGpwcABPFZHndG29KqXXrrHMoIJZNZLbIuzBsS
         9YhxwLmnUPalIECIAFtLAlpKd+QyxJ7dqLFUsY51y/V3HfHYawNLYJ7dS43tcHbXlJHj
         9NoVcNTynvmM88M2aAliwQ2Wswwre5aKDKOe6eQDOLgC4QSR0sYdZvSlw9alimh/RXX5
         kthQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745591747; x=1746196547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9jz44E/cnHxn7b2MSvv2+wt7tN8HY5m8OnKJCF4lryE=;
        b=lY2YhUR6Ivt2Q9IGrE7vNUPDPdaI+QTvmOgB1CYtcPb0idt6ttIMw774ROdOwnVsyb
         5Lj9eBm05QHx9uVGQ7X9nHuxP+uR9ZrJD33mTFfzNpkfAG3btU2k2CfTtKb3VcWG2SeT
         TUdITQkaR1yQeprfmM3020UcfDC0LQ9AC6j1bwr11rHAsl+rLyEkkfP0fu8DWPpyzuGQ
         qFyuzMdi40DJMMR6xRwH0s8Hk+DwbzEF0btCbG8Ox93Pik+gE2mSyjNNMdphaGfm6ZwW
         ktWDtI1DBJIJ683024L41zA8Ljgh1nLC24HX0y3TWYBUdXCOk6Z41pEgqdqcr0/S2g0u
         HiIw==
X-Forwarded-Encrypted: i=2; AJvYcCWKIKBUULC5/gYaOLaqmEhumAMjNw5JchHVydt6ctSRx0RDX0zouOPM5TKJ11QMs/KvFpQG4w==@lfdr.de
X-Gm-Message-State: AOJu0YwQNWBFXJvXgofu6aZ3uX/GWqIoxpQIsS4HG/lFKpHoubRxx7B4
	oSgePnpiMXGX1nNj+MX11ESMF7YV6AWBfjFMAI2UxbuVwuC0b0CX
X-Google-Smtp-Source: AGHT+IEJ3H/0i3ElE52hsZQx3p6SZ9j1P/vksVOoGIKlGYdEvUqxIX9qYYcc96exLmzkloPQv1J7sA==
X-Received: by 2002:ad4:5f06:0:b0:6d8:9d81:2107 with SMTP id 6a1803df08f44-6f4cb9d6df4mr38916996d6.20.1745591746591;
        Fri, 25 Apr 2025 07:35:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBE/mXFACY5U49EXEiZyNB/IcKoBQ+8jG1Tu39/5+TdXVw==
Received: by 2002:a0c:edcd:0:b0:6ec:ed6a:47dd with SMTP id 6a1803df08f44-6f4be4b16dbls7857556d6.1.-pod-prod-08-us;
 Fri, 25 Apr 2025 07:35:45 -0700 (PDT)
X-Received: by 2002:a05:6214:e66:b0:6e8:fcc6:35b6 with SMTP id 6a1803df08f44-6f4cb99d412mr44566416d6.2.1745591745481;
        Fri, 25 Apr 2025 07:35:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745591745; cv=none;
        d=google.com; s=arc-20240605;
        b=YY5h9BgXHQlYIrNQllcQaueVr7I+XVT1HX2gUdJy405D3hw4IymvkgqaKTGbKUd3iT
         dsSlQdame34lk7BBSL2kJ4FU034JUcoUWFj/LxOu9hdCvEx6IJ6ATLqel9DcndhTeTHl
         Pn+1bhAnZcuZFAHlaJHwPJLItM0ByjkdkDny1Z0liQysFT1W89Hs3hTT2dhhV64lhuTk
         d0S7QA3Rp/eUII4bvNPF5suLhcs8SftD7S6Q+kBN/DwCrZrclgTYJBiElNYYt8r9r8Nd
         rvmOne1CH+a7covymESDslcAlnWXva/kILNfwMKY6/Quvv3zO+6O1kLaqjR+zPjJcyvN
         3n9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qEOLc1zCu3QSACWlexKaPiLnzkOEuJR+G44IGN2p3uo=;
        fh=ZAoJMDmkXh64HvMHNbFbHQsFvJ5SGl8IEmYh5I8c2ys=;
        b=hHJ0llXNLHM0Iiff+en73w14lkQXdphZ0qQTy3jsNJSQX4H1fonIE0iorc6E3hlJrH
         ivjo12avO0L1w9u42WOLaHglJ8NPnwSCiOnQk8AgGOrMILoKbuqdq6b09psO+EGVFE9a
         X/b1lsyNeux6hXWm06EO3Say+m+XQfBn6Ertj0RP3wgiWXnjEL0Q/bqXgIZgINytN+7b
         nAyoCnjR4FsBP6vaB/1OPxmeRU46qj/Af809BYJzm0pL1+ZfR4m7VYtPJ4wPbqQbsXR5
         Kt8IX1GTpZUETcj4kmif3n84rm327CAo5OHIbutXst49WDcigtOk53z/xj/puVJMkob8
         tqbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iXostuQV;
       spf=pass (google.com: domain of srs0=d47o=xl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=D47o=XL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4c08b9b8dsi1483916d6.2.2025.04.25.07.35.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Apr 2025 07:35:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=d47o=xl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 25D2EA4D3DA;
	Fri, 25 Apr 2025 14:30:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C6F7DC4CEE4;
	Fri, 25 Apr 2025 14:35:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 755ECCE0485; Fri, 25 Apr 2025 07:35:44 -0700 (PDT)
Date: Fri, 25 Apr 2025 07:35:44 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, dvyukov@google.com,
	Taras Madan <tarasmadan@google.com>
Subject: Re: Dazed and confused by KCSAN report (but I eventually figured it
 out)
Message-ID: <4f7d9d27-49e0-4c27-8f24-0428671ec6d6@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <0dbb0354-9a89-438a-b009-5ac72e55efb1@paulmck-laptop>
 <CANpmjNOOWt4vpG6O_uB1=fzU16MwpLtQR3_S5eZ=BO6Bxw6adg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOOWt4vpG6O_uB1=fzU16MwpLtQR3_S5eZ=BO6Bxw6adg@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iXostuQV;       spf=pass
 (google.com: domain of srs0=d47o=xl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 147.75.193.91 as permitted sender) smtp.mailfrom="SRS0=D47o=XL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Fri, Apr 25, 2025 at 08:52:05AM +0200, Marco Elver wrote:
> Hi Paul,
> 
> On Fri, 25 Apr 2025 at 01:46, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Hello!
> >
> > OK, I *was* confused by the following KCSAN report.  It turned out that
> > the problem was that I did not realize that irq_work handlers do not run
> > with interrupts disabled.  Given that this particular irq_work handler is
> > not (very) performance sensitive, the fix is simply to disable interrupts,
> > as shown in the prototype patch shown at the end of this email.
> >
> > I am including my initial confusion for your amusement.
> >
> > So thank you all for KCSAN!  I am here to tell you that low-probability
> > bugs of this sort are a *real* pain to locate the hard way!  ;-)
> 
> Thank you for this report, always glad to hear how our tools help. :-)
> 
> For my own understanding, some questions below.
> 
> >                                                         Thanx, Paul
> >
> > ------------------------------------------------------------------------
> >
> > I am confused by this KCSAN report:
> >
> > [  611.741857] BUG: KCSAN: data-race in rcu_preempt_deferred_qs_handler / rcu_read_unlock_special
> [...]
> > [  611.742013]  run_irq_workd+0x91/0xc0
> > [  611.742020]  smpboot_thread_fn+0x24d/0x3b0
> > [  611.742029]  kthread+0x3bd/0x410
> 
> To clarify my understanding:
> 
> I assume the threaded dispatch of irq_work is because of PREEMPT_RT?
> Are irq_work also dispatched into kthreads on some non-RT kernels?
> 
> I recall that irq_work used either self-IPI or remote-IPI to queue the
> work, so perhaps this is happening in a kthreaded interrupt handler
> due to PREEMPT_RT?

Yes, this runs with CONFIG_PREEMPT_RT=y, which I only recently added to
my RCU acceptance test (AKA "torture.sh").

So my bad assumption wasn't bad until late last year.  At least it wasn't
bad in mainline kernels.  ;-)

							Thanx, Paul

> > [  611.742039]  ret_from_fork+0x35/0x40
> > [  611.742047]  ret_from_fork_asm+0x1a/0x30
> > [  611.742056]
> > [  611.742058] no locks held by irq_work/8/88.
> > [  611.742063] irq event stamp: 200272
> > [  611.742066] hardirqs last  enabled at (200272): [<ffffffffb0f56121>] finish_task_switch+0x131/0x320
> > [  611.742078] hardirqs last disabled at (200271): [<ffffffffb25c7859>] __schedule+0x129/0xd70
> > [  611.742089] softirqs last  enabled at (0): [<ffffffffb0ee093f>] copy_process+0x4df/0x1cc0
> > [  611.742112] softirqs last disabled at (0): [<0000000000000000>] 0x0
> > [  611.742119]
> > [  611.742142] Reported by Kernel Concurrency Sanitizer on:
> > [  611.742149] CPU: 8 UID: 0 PID: 88 Comm: irq_work/8 Not tainted 6.15.0-rc1-00063-g5e8a7c9a1a0a #2713 PREEMPT_{RT,(full)}
> > [  611.742154] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
> >
> > The rcu_preempt_deferred_qs_handler() IRQ-work handler's only memory
> > reference is the one-byte ->defer_qs_iw_pending field of the rcu_data
> > per-CPU structure.  This handler is scheduled using irq_work_queue_on(),
> > directed to the rcu_data structure's CPU.  All of the remaining references
> > are by rcu_read_unlock_special() with interrupts disabled, and with the
> > rcu_data structure selected for the current CPU.
> >
> > I did add WARN_ON_ONCE() calls to verify that the code really was always
> > accessing a given CPU's ->defer_qs_iw_pending field from that CPU.
> > That WARN_ON_ONCE() never triggered, and KCSAN still flagged the
> > ->defer_qs_iw_pending field as having a data race.
> >
> > [ At which point I realized that I was not so sure that irq-work handlers
> >   had interrupts disabled.  It turns out that they do not, so an RCU
> >   read-side critical section in a real interrupt handler that interrupted
> >   rcu_preempt_deferred_qs_handler() could legitimately cause this KCSAN
> >   complaint.  Again, thank you all for KCSAN!!! ]
> >
> > For completeness, the KCSAN Kconfig options are as follows:
> >
> > CONFIG_HAVE_ARCH_KCSAN=y
> > CONFIG_HAVE_KCSAN_COMPILER=y
> > CONFIG_KCSAN=y
> > CONFIG_CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE=y
> > CONFIG_KCSAN_VERBOSE=y
> > CONFIG_KCSAN_SELFTEST=y
> > CONFIG_KCSAN_EARLY_ENABLE=y
> > CONFIG_KCSAN_NUM_WATCHPOINTS=64
> > CONFIG_KCSAN_UDELAY_TASK=80
> > CONFIG_KCSAN_UDELAY_INTERRUPT=20
> > CONFIG_KCSAN_DELAY_RANDOMIZE=y
> > CONFIG_KCSAN_SKIP_WATCH=4000
> > CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE=y
> > CONFIG_KCSAN_INTERRUPT_WATCHER=y
> > CONFIG_KCSAN_REPORT_ONCE_IN_MS=100000
> > CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y
> > CONFIG_KCSAN_STRICT=y
> > CONFIG_KCSAN_WEAK_MEMORY=y
> >
> > ------------------------------------------------------------------------
> >
> > diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
> > index 3c0bbbbb686fe..003e549f65141 100644
> > --- a/kernel/rcu/tree_plugin.h
> > +++ b/kernel/rcu/tree_plugin.h
> > @@ -624,10 +624,13 @@ notrace void rcu_preempt_deferred_qs(struct task_struct *t)
> >   */
> >  static void rcu_preempt_deferred_qs_handler(struct irq_work *iwp)
> >  {
> > +       unsigned long flags;
> >         struct rcu_data *rdp;
> >
> >         rdp = container_of(iwp, struct rcu_data, defer_qs_iw);
> > +       local_irq_save(flags);
> >         rdp->defer_qs_iw_pending = false;
> > +       local_irq_restore(flags);
> >  }
> >
> >  /*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4f7d9d27-49e0-4c27-8f24-0428671ec6d6%40paulmck-laptop.
