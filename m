Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPHCVTAAMGQEPCOR7YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 48CE5A9BEEB
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 08:52:46 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-739764217ecsf1785705b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Apr 2025 23:52:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745563964; cv=pass;
        d=google.com; s=arc-20240605;
        b=QklCyTmA3IurIvBhyT9kV+E+5Xiz4+Dlcmag1bNbhfgo2yQriNatLjpiODjyQH2vcP
         H/3GitbODkSU3obpHGNc+arqhdcfsDPgsAIRfHXfTG4w1Je7eOdGpe8WoVNVop5nIgDE
         hAtx7Ted/BjdlxZqz1xUzNITvVHmeP9kIktMn0lv3L1KDohiMcx012AwHW1RbQ2rK970
         GzRFfug9zRHQuVLR7jq8Bf4u2gStZHrrUPM0tMXKSIbyfOCLLRU9N49yYT+7Qx1kjevM
         FLJPOvPITNK1QtyN0vZ2PmZhofxOjK3tHfhMEuheSj5gEcVz80PzVCROVaBHwmHiK0w2
         zv1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=58GK0XlbclLeHMB5TJH6PaiiVVk1qedfsU9EdCnB3cQ=;
        fh=BVKrmBZv7kvQFPHCFaoFEI8qrAvppbmRZBivufR9vy4=;
        b=TStdGqQEZIx1WlzLeioLARMiDHJJAEpvAXerK4pmCQvZYJ5ro2RSxQJHXtI9sy4J3n
         mAEC9ScXhDZS0aUTBakDfbqk462roQbWJ+oWtBstmZb92ITqzSJy/uHeNSYPcfpuaelq
         gbXdGvUnaajmXwXCwxkeDRR0QhnZ56c1mKtmNQ0S9vJg6E/9bGDjeJt1h1f/zGdfaYh5
         kL1IMPwTG8ArCy9eg9Bk9bEOD2d1WMliGaVJzfvEQR+V1mmO9UsOLGxsw5/tFHTGleNi
         r7UzEAHGUHcLbuAIvG6DdKubphjMTNsyNYvCjZbA0mQwdylJKL1LisBCVaR4xfLgXUaN
         lJTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rSdgSMx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745563964; x=1746168764; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=58GK0XlbclLeHMB5TJH6PaiiVVk1qedfsU9EdCnB3cQ=;
        b=CJC0HoeGWimb7Yb9x4dVLsTVF3SDGz0bR4wKEofHIMvp9Kn42ZQKzM1byY+0t6uiKA
         BtfD/PI1sqq0j3MhzBVctWVBF4yA4Uf85ggsy4Si9a8w+BIpboON8Emif51+O0YRYYuX
         9cdrfFZ1XUlneoNbvFY6HESAyICZ2/CSAri1Eo4Sq5NTGCh67OckyfENL/rQK1NWHINS
         N3/PuUnaqUWcpiI+flhNJdZRZ+tzotEsAQn2XgDZB6m+ZjKRC+iUWegqFL8VOTVuvIIn
         Rm8VQwZcZgbX1MEo0vWnlzJvJjlv5UzLKyJeEsVcnEO3rJnFv20mPo0r9yTJTVnRqpU7
         ud5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745563964; x=1746168764;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=58GK0XlbclLeHMB5TJH6PaiiVVk1qedfsU9EdCnB3cQ=;
        b=MRnHmk1eS6iJ2QJQCj7MZa6rWei3ZnFc1st1MRXfQhgFgr2B75iEbTkNmx+IeiwHl1
         hh1f/CNOZKvs8n2ylfwNJ0zI5OHGM1PNceaBHKylaUPvyk39HrJKgNH8inQA038hvxqR
         bYTNjLW9cz9tiCfHZhYXnYJmuGdhTHygac64E4/57XPjwrqxPwXkvxNEO/tlQ0upv8hR
         cLpWiuruhVcRVWd1Q1RoEgI0veNmYHv24b0c149e8rPcsbaVdCZNwbe6OCvXGSUOtQz9
         owatVoa5yh+1MRueYylbnhDpzapYO7m1y9QGPQX/m1qsRF/tQHyUPoJThy0SJfLgeTnw
         SmCA==
X-Forwarded-Encrypted: i=2; AJvYcCX0Ll+ZCAoqHL9Mxw7qKlkGgSUTnIgC3eHVpaNNLZJ02M4M7HFKo8oi7f918NteS1MANwhzmA==@lfdr.de
X-Gm-Message-State: AOJu0YyXEoMZobbe02vWI/Ebo27R0jR+zWcJY4+JyoVW5YA8KpzacqnE
	BD+tfF24/26EqwXm392njSnvks1w/cjD3FWEWetOP44vQDsicKJF
X-Google-Smtp-Source: AGHT+IE8ckuzNjaY+d36FpZDHkcX/x3lY9QuYdG+Ajoqqic1gOai0Bpu6aLVLFG0PIZPEFl63trvIA==
X-Received: by 2002:a05:6a00:98e:b0:736:3ea8:4813 with SMTP id d2e1a72fcca58-73fd519c414mr1888660b3a.2.1745563964283;
        Thu, 24 Apr 2025 23:52:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAImYVnsunqHrvldxVlX4czeV8YA0Y8/LlI9L43HvDxj+A==
Received: by 2002:a05:6a00:4602:b0:725:4630:50bd with SMTP id
 d2e1a72fcca58-73e219e756fls1006505b3a.0.-pod-prod-00-us; Thu, 24 Apr 2025
 23:52:42 -0700 (PDT)
X-Received: by 2002:a05:6a00:2306:b0:736:4e14:8ec5 with SMTP id d2e1a72fcca58-73fd7cba6d9mr1572600b3a.11.1745563962575;
        Thu, 24 Apr 2025 23:52:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745563962; cv=none;
        d=google.com; s=arc-20240605;
        b=kpnRR/J9ZiWs6QBy6P4ACOFmFCw8If279xonkAaHFaVl/LdTRq9vSGxnouaA+MPyZH
         WWxX6LS4J7grT5i++m+i3ED35dWpT6f6MZdtKSXjLlc5t657RSo45k/3efTLjoI5EwFn
         Jmik9eFpMdnnfIZKLGgGZfAq9+0lJgQ/oYb8sOkvhQFIRqeMgkb7a6r3O8zSOBgk05DP
         qvWrbE6OaC9szZJIwx5qITH2BnUQF88AUFepoEu4isyT9ux+Y1wUdOwxgTalw8sFZrEL
         f1a/yYvxSHeau1EGtPC5swbv6WlhaCudumRQU+/gdH/cjhQvuWwQaUqd6Uqoqd93mZsr
         otKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HKGIt0qxP1MaIOd7oil1QbdbivUqmGBa4ZJ0K7BsjOQ=;
        fh=mLumdTCXBlgKOAsrGCNG7JP6LsqGMdj7TTyeh677ESQ=;
        b=MK8VdkE4NloLkwnBTgDL8Zi6jB0bov+WUQG5cSvH3a9ija7ekbCerJxq5vjoxwSzjY
         1Fm1lmerzcGpIUWI2JLJGk9Bkks+GdEs2OlHSJdcmcdiFH8pdkwwCUWJnoVKEC4hCmGO
         ZMzNyzLT67pC8zz+8cEaDCuVWIYgBL28wHfQn320VlTfD1OHO1fsoWekRrRvOBgZLC1u
         zYNebj0jedAck8lYv3ENZNTn2aGb3z5614qH3cGhdc+l2j1x4wAFtl9aLVvCUWBGu0zW
         nmNJMp87PNMSCwnwyvRWHviJo7Qc0zPZWK9C5PecCNqaQGYvdWlqmlNaOjIzluNwtbWt
         PKzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1rSdgSMx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73e253871f1si10458b3a.5.2025.04.24.23.52.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Apr 2025 23:52:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-30863b48553so2771984a91.0
        for <kasan-dev@googlegroups.com>; Thu, 24 Apr 2025 23:52:42 -0700 (PDT)
X-Gm-Gg: ASbGnct7UhSSPZLznf/SGFgTgSr/CH532v4iL+EVHSbgOcEnT3bZTYgrakuIgpFnCa4
	MJOqXd+3qEiPZph4jM8vjkL9CvCciK2ch8kcl79Mx2jU0vaVjV2nCTHJX0Tp7+h+XyiuclkAG+4
	SHlSVXgi415LGb2C6c+VSra2ZjoFpJ7+8rb2szTuyWJn3lPs734MZw+51d2lweoSnr
X-Received: by 2002:a17:90b:268c:b0:309:f46e:a67c with SMTP id
 98e67ed59e1d1-309f8a0769dmr1863401a91.11.1745563961890; Thu, 24 Apr 2025
 23:52:41 -0700 (PDT)
MIME-Version: 1.0
References: <0dbb0354-9a89-438a-b009-5ac72e55efb1@paulmck-laptop>
In-Reply-To: <0dbb0354-9a89-438a-b009-5ac72e55efb1@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 25 Apr 2025 08:52:05 +0200
X-Gm-Features: ATxdqUGimc7-ku6BzP8AXpSTVMt8ub9sw79usxFQTs6qHrFktJJ7mpXt4hkawkw
Message-ID: <CANpmjNOOWt4vpG6O_uB1=fzU16MwpLtQR3_S5eZ=BO6Bxw6adg@mail.gmail.com>
Subject: Re: Dazed and confused by KCSAN report (but I eventually figured it out)
To: paulmck@kernel.org
Cc: kasan-dev@googlegroups.com, dvyukov@google.com, 
	Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1rSdgSMx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

Hi Paul,

On Fri, 25 Apr 2025 at 01:46, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> Hello!
>
> OK, I *was* confused by the following KCSAN report.  It turned out that
> the problem was that I did not realize that irq_work handlers do not run
> with interrupts disabled.  Given that this particular irq_work handler is
> not (very) performance sensitive, the fix is simply to disable interrupts,
> as shown in the prototype patch shown at the end of this email.
>
> I am including my initial confusion for your amusement.
>
> So thank you all for KCSAN!  I am here to tell you that low-probability
> bugs of this sort are a *real* pain to locate the hard way!  ;-)

Thank you for this report, always glad to hear how our tools help. :-)

For my own understanding, some questions below.

>                                                         Thanx, Paul
>
> ------------------------------------------------------------------------
>
> I am confused by this KCSAN report:
>
> [  611.741857] BUG: KCSAN: data-race in rcu_preempt_deferred_qs_handler / rcu_read_unlock_special
[...]
> [  611.742013]  run_irq_workd+0x91/0xc0
> [  611.742020]  smpboot_thread_fn+0x24d/0x3b0
> [  611.742029]  kthread+0x3bd/0x410

To clarify my understanding:

I assume the threaded dispatch of irq_work is because of PREEMPT_RT?
Are irq_work also dispatched into kthreads on some non-RT kernels?

I recall that irq_work used either self-IPI or remote-IPI to queue the
work, so perhaps this is happening in a kthreaded interrupt handler
due to PREEMPT_RT?

> [  611.742039]  ret_from_fork+0x35/0x40
> [  611.742047]  ret_from_fork_asm+0x1a/0x30
> [  611.742056]
> [  611.742058] no locks held by irq_work/8/88.
> [  611.742063] irq event stamp: 200272
> [  611.742066] hardirqs last  enabled at (200272): [<ffffffffb0f56121>] finish_task_switch+0x131/0x320
> [  611.742078] hardirqs last disabled at (200271): [<ffffffffb25c7859>] __schedule+0x129/0xd70
> [  611.742089] softirqs last  enabled at (0): [<ffffffffb0ee093f>] copy_process+0x4df/0x1cc0
> [  611.742112] softirqs last disabled at (0): [<0000000000000000>] 0x0
> [  611.742119]
> [  611.742142] Reported by Kernel Concurrency Sanitizer on:
> [  611.742149] CPU: 8 UID: 0 PID: 88 Comm: irq_work/8 Not tainted 6.15.0-rc1-00063-g5e8a7c9a1a0a #2713 PREEMPT_{RT,(full)}
> [  611.742154] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
>
> The rcu_preempt_deferred_qs_handler() IRQ-work handler's only memory
> reference is the one-byte ->defer_qs_iw_pending field of the rcu_data
> per-CPU structure.  This handler is scheduled using irq_work_queue_on(),
> directed to the rcu_data structure's CPU.  All of the remaining references
> are by rcu_read_unlock_special() with interrupts disabled, and with the
> rcu_data structure selected for the current CPU.
>
> I did add WARN_ON_ONCE() calls to verify that the code really was always
> accessing a given CPU's ->defer_qs_iw_pending field from that CPU.
> That WARN_ON_ONCE() never triggered, and KCSAN still flagged the
> ->defer_qs_iw_pending field as having a data race.
>
> [ At which point I realized that I was not so sure that irq-work handlers
>   had interrupts disabled.  It turns out that they do not, so an RCU
>   read-side critical section in a real interrupt handler that interrupted
>   rcu_preempt_deferred_qs_handler() could legitimately cause this KCSAN
>   complaint.  Again, thank you all for KCSAN!!! ]
>
> For completeness, the KCSAN Kconfig options are as follows:
>
> CONFIG_HAVE_ARCH_KCSAN=y
> CONFIG_HAVE_KCSAN_COMPILER=y
> CONFIG_KCSAN=y
> CONFIG_CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE=y
> CONFIG_KCSAN_VERBOSE=y
> CONFIG_KCSAN_SELFTEST=y
> CONFIG_KCSAN_EARLY_ENABLE=y
> CONFIG_KCSAN_NUM_WATCHPOINTS=64
> CONFIG_KCSAN_UDELAY_TASK=80
> CONFIG_KCSAN_UDELAY_INTERRUPT=20
> CONFIG_KCSAN_DELAY_RANDOMIZE=y
> CONFIG_KCSAN_SKIP_WATCH=4000
> CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE=y
> CONFIG_KCSAN_INTERRUPT_WATCHER=y
> CONFIG_KCSAN_REPORT_ONCE_IN_MS=100000
> CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=y
> CONFIG_KCSAN_STRICT=y
> CONFIG_KCSAN_WEAK_MEMORY=y
>
> ------------------------------------------------------------------------
>
> diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
> index 3c0bbbbb686fe..003e549f65141 100644
> --- a/kernel/rcu/tree_plugin.h
> +++ b/kernel/rcu/tree_plugin.h
> @@ -624,10 +624,13 @@ notrace void rcu_preempt_deferred_qs(struct task_struct *t)
>   */
>  static void rcu_preempt_deferred_qs_handler(struct irq_work *iwp)
>  {
> +       unsigned long flags;
>         struct rcu_data *rdp;
>
>         rdp = container_of(iwp, struct rcu_data, defer_qs_iw);
> +       local_irq_save(flags);
>         rdp->defer_qs_iw_pending = false;
> +       local_irq_restore(flags);
>  }
>
>  /*

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOOWt4vpG6O_uB1%3DfzU16MwpLtQR3_S5eZ%3DBO6Bxw6adg%40mail.gmail.com.
