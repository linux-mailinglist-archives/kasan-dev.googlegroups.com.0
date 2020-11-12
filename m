Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSW6WT6QKGQEWW4JVGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2017E2B0522
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 13:49:16 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id u3sf2591290pfm.22
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 04:49:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605185354; cv=pass;
        d=google.com; s=arc-20160816;
        b=UvZZFzSW2xsMRVP3nUAdHERRPNOW0fSwqcz1RnGG2Y126FfmbXM1CB0fBgFEioWrJ3
         rWDv05Tf0UoqLJQ9UkwAk3KBP4hctSGP8UAMfzM6BxG3ey/qhSHH+Xkaa9Bxpej75zAA
         9ZRxAFggXdDXthvRg12aWEHI+4rkGoiCScULdQzphORI1faHSf23U3v7pymqQAl/il8/
         FR/0UWYTCn5zX7CRrVt8rmyIuIeRCSnsQTJhYjQbnxCc2UBqfdqS0CMzRZnu06mGXlzI
         qMUEXKkNF4OkUM7IhmXaTjLBT36bUzK29KA+xfgTlfQLHGgB5Fo0T1+R06aJvq2cjSh4
         avnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jNT1wnBCrIAXAsFs0b+xvUmifzjKsydVDchgFFFjfec=;
        b=A9I7JOAfWOmcpz3X0HKhdqtVzsLlz/0ruoxpAFXf5EstW55zbpFPqvkMTjlWkoNBDK
         /np+GkhydOj6ljSDd1Q4cY/zhMawV5yKtghx3bukxJdQkWreh2b/CkKf0v7qGIoXftML
         rO/DjKrWNwDtqd1cS8fWSLMzKY31IwPxD9pc+w1mkW9nnpXRLPr6AN9Hc1BfheAeDYgZ
         NJwUQMid08cCQkt7a7ZAZ1u5n221DNdAZw9NAEjxoXzrimGWMhGyPuVrVqtrd+prNzP3
         1CBtqzjwHlD1E0MhD7zwV5kYFpoKXhSelFWAOariMkkf1/TWJJ/C0fbPytjiochzkYxA
         gDLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DtSbpKCy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jNT1wnBCrIAXAsFs0b+xvUmifzjKsydVDchgFFFjfec=;
        b=oXFLXzV7gGnv6UpxIIatNmWAJmvKghhin3H5c4gPq6NiHf+W5qJhc2R4KI09CjfGTX
         54xtqiMeW4oQy20NJFXMGwlgrY3eeq2uzHvgTYlnk8Ce1sMmucLqNLY17U/jPapVgehm
         tAGn98lAlW+cl+QJAeXhm3yiH44GCkTej7bldMi6g1gzjPa5nBa7GYyu4QoRxQGkXuAn
         6HWpyhC5u+uyH2BD/ubbczuRGal9cjayEsivJDkrWoBUAWZqsUXxbncjXExAoC8VV7rf
         WJJeO4mopziQLPSoAufhpF23kK7iFSnOx9c9DHi0uwZ4bKIU9kYEBk69wRYdf2wGeU34
         r8kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jNT1wnBCrIAXAsFs0b+xvUmifzjKsydVDchgFFFjfec=;
        b=U4+39OHGRcwq4JoaJyH+Rw+DoYADZa9w7WnfRToozcy89C0hZgO/0cIkS7IcGROYEM
         cD2KJus/yl/8S7Eo9EYm/HEL2FQ4+RBKbaViIPaklJHgg3YHsxIsw9MBl4dGn0fRG210
         dZRMxqwHnuX3is5qKo+eA7OyLrosZNWu2jfyDZy80+JNUgNDIHC7uspIWxKSJ2IjTXhx
         WenWIxscElyE2hCNZnvph4w0kJkw9y8Jda4Y2fa9K7q+kwIMnDccPsT4kyBHYuYoXUIy
         tC/49IZrCD4IqymsejrV9gw3cRMqOy63uROMHyjDZix3E8XwPbkcE62qIfVYcPTMyBvK
         Dw5g==
X-Gm-Message-State: AOAM533vdzh59s6gw46AOqTTD8ZpTTnh4FVPny43+MoweoPlUItOirx1
	3KiErJyRL0y1H5hH91qppfI=
X-Google-Smtp-Source: ABdhPJwvd5NMJOliZ43qwNb4oq7ed6siM3wSVp07Jl+H69eN6RNEY4b91z2ar7XO4DYYUWrJgGa5Jg==
X-Received: by 2002:a63:fc4c:: with SMTP id r12mr24442943pgk.309.1605185354425;
        Thu, 12 Nov 2020 04:49:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls1426516pld.8.gmail; Thu, 12
 Nov 2020 04:49:13 -0800 (PST)
X-Received: by 2002:a17:90a:69a4:: with SMTP id s33mr3867647pjj.197.1605185353684;
        Thu, 12 Nov 2020 04:49:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605185353; cv=none;
        d=google.com; s=arc-20160816;
        b=Ev/gw0F1h6CQTagLFNoqAscYohT6s+yY3H0lzAVjz2ZzyJmy9KHQXyqilWHgIpvIGS
         vd+sYETEX9AAKVrpuwxLkS6mGRJiFABSh/wBEEIWq/ZYEc/Z9GFzYwRc6llglkWH4eSk
         Er8n1cRg760ZTG8oNyhJulpEsLiROMD/78TDHDntoDRs06buSePmMNz7Rey3DDGjFjhA
         iP/aF3RHDtBkpXVjsALARXlpphQ3Uqw0YkCNqUgONKqlSOqiiwREdOaZTQGFjTkZ4wXK
         Ygke5ugGY6bd3k1e4skZSWvfdrkY7kjztmkMYy/+ciJfcMOzolhXIEKm5qEnrNFpY3Mb
         mFAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/zzVT0v3gmep680s+NflLICQeHQjw0uUukpoJ+hjBrc=;
        b=A49+YkVYr9/PKu1/kZXKQp2nKYD3QR+LgM9fh8mBZ4OldaWaVyKYlHi9nna7yjKaj9
         k7US7ZPDhf8LI13kMNLv4lGY5zl5l2yK2q98+xGIwG/Tszmw6cCEjBbgI0IXYRs+3MVZ
         C1LxbuRXzwSmBIyu57SzsHMIw8qnrup9zkAyjMFhJxYIC8yKEuoahXA2UfoFdz5qwJQf
         xp+l0ab/+LmeJ9ymqglPFvTjcHSs10OETEb8Gz120e+xZassZ+gCdc35zbMObtruEki+
         w/9QRsEeA64c9WJ6VlZMKuEEdDwvrWnifRwPGASxdywuM3vg6I0dHsUII79Fp1du/kjA
         7Z9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DtSbpKCy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc44.google.com (mail-oo1-xc44.google.com. [2607:f8b0:4864:20::c44])
        by gmr-mx.google.com with ESMTPS id o2si137926pjq.0.2020.11.12.04.49.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 04:49:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) client-ip=2607:f8b0:4864:20::c44;
Received: by mail-oo1-xc44.google.com with SMTP id r11so1267847oos.12
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 04:49:13 -0800 (PST)
X-Received: by 2002:a4a:d886:: with SMTP id b6mr1622933oov.14.1605185352811;
 Thu, 12 Nov 2020 04:49:12 -0800 (PST)
MIME-Version: 1.0
References: <20201110135320.3309507-1-elver@google.com> <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com> <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72> <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72> <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
In-Reply-To: <20201112001129.GD3249@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 13:49:00 +0100
Message-ID: <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without allocations
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>, Anders Roxell <anders.roxell@linaro.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, 
	Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DtSbpKCy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as
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

On Thu, 12 Nov 2020 at 01:11, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Wed, Nov 11, 2020 at 09:21:53PM +0100, Marco Elver wrote:
> > On Wed, Nov 11, 2020 at 11:21AM -0800, Paul E. McKenney wrote:
> > [...]
> > > > >     rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> > > >
> > > > Sadly, no, next-20201110 already included that one, and that's what I
> > > > tested and got me all those warnings above.
> > >
> > > Hey, I had to ask!  The only uncertainty I seee is the acquisition of
> > > the lock in rcu_iw_handler(), for which I add a lockdep check in the
> > > (untested) patch below.  The other thing I could do is sprinkle such
> > > checks through the stall-warning code on the assumption that something
> > > RCU is calling is enabling interrupts.
> > >
> > > Other thoughts?
> > >
> > >                                                     Thanx, Paul
> > >
> > > ------------------------------------------------------------------------
> > >
> > > diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
> > > index 70d48c5..3d67650 100644
> > > --- a/kernel/rcu/tree_stall.h
> > > +++ b/kernel/rcu/tree_stall.h
> > > @@ -189,6 +189,7 @@ static void rcu_iw_handler(struct irq_work *iwp)
> > >
> > >     rdp = container_of(iwp, struct rcu_data, rcu_iw);
> > >     rnp = rdp->mynode;
> > > +   lockdep_assert_irqs_disabled();
> > >     raw_spin_lock_rcu_node(rnp);
> > >     if (!WARN_ON_ONCE(!rdp->rcu_iw_pending)) {
> > >             rdp->rcu_iw_gp_seq = rnp->gp_seq;
> >
> > This assert didn't fire yet, I just get more of the below. I'll keep
> > rerunning, but am not too hopeful...
>
> Is bisection a possibility?

I've been running a bisection for past ~12h, and am making slow
progress. It might be another 12h, but I think it'll get there.

> Failing that, please see the updated patch below.  This adds a few more
> calls to lockdep_assert_irqs_disabled(), but perhaps more helpfully dumps
> the current stack of the CPU that the RCU grace-period kthread wants to
> run on in the case where this kthread has been starved of CPU.

Thanks, I will apply that after the bisection runs.

>                                                         Thanx, Paul
>
> ------------------------------------------------------------------------
>
> diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
> index 70d48c5..d203ea0 100644
> --- a/kernel/rcu/tree_stall.h
> +++ b/kernel/rcu/tree_stall.h
> @@ -189,6 +189,7 @@ static void rcu_iw_handler(struct irq_work *iwp)
>
>         rdp = container_of(iwp, struct rcu_data, rcu_iw);
>         rnp = rdp->mynode;
> +       lockdep_assert_irqs_disabled();
>         raw_spin_lock_rcu_node(rnp);
>         if (!WARN_ON_ONCE(!rdp->rcu_iw_pending)) {
>                 rdp->rcu_iw_gp_seq = rnp->gp_seq;
> @@ -449,21 +450,32 @@ static void print_cpu_stall_info(int cpu)
>  /* Complain about starvation of grace-period kthread.  */
>  static void rcu_check_gp_kthread_starvation(void)
>  {
> +       int cpu;
>         struct task_struct *gpk = rcu_state.gp_kthread;
>         unsigned long j;
>
>         if (rcu_is_gp_kthread_starving(&j)) {
> +               cpu = gpk ? task_cpu(gpk) : -1;
>                 pr_err("%s kthread starved for %ld jiffies! g%ld f%#x %s(%d) ->state=%#lx ->cpu=%d\n",
>                        rcu_state.name, j,
>                        (long)rcu_seq_current(&rcu_state.gp_seq),
>                        data_race(rcu_state.gp_flags),
>                        gp_state_getname(rcu_state.gp_state), rcu_state.gp_state,
> -                      gpk ? gpk->state : ~0, gpk ? task_cpu(gpk) : -1);
> +                      gpk ? gpk->state : ~0, cpu);
>                 if (gpk) {
>                         pr_err("\tUnless %s kthread gets sufficient CPU time, OOM is now expected behavior.\n", rcu_state.name);
>                         pr_err("RCU grace-period kthread stack dump:\n");
> +                       lockdep_assert_irqs_disabled();
>                         sched_show_task(gpk);
> +                       lockdep_assert_irqs_disabled();
> +                       if (cpu >= 0) {
> +                               pr_err("Stack dump where RCU grace-period kthread last ran:\n");
> +                               if (!trigger_single_cpu_backtrace(cpu))
> +                                       dump_cpu_task(cpu);
> +                       }
> +                       lockdep_assert_irqs_disabled();
>                         wake_up_process(gpk);
> +                       lockdep_assert_irqs_disabled();
>                 }
>         }
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNyZs6NrHPmomC4%3D9MPEvCy1bFA5R2pRsMhG7%3Dc3LhL_Q%40mail.gmail.com.
