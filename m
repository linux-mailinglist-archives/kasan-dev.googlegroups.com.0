Return-Path: <kasan-dev+bncBCBMVA7CUUHRBU7BZ77AKGQEB7PBMTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 24CB42D81DE
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 23:21:09 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id r1sf5418476pgm.13
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 14:21:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607725267; cv=pass;
        d=google.com; s=arc-20160816;
        b=RVr1cLRmV5X17KwcNbvlH5Bfe5WXh1L0++OULdZmIHrSL7kMD3ZgRkxILmlklQWN/l
         JdsRR/O54hJTYrDhS091EC/8xxcUBT0WT/tDmZyu6QZL4Bl+2JLTT5x0ITprSQyurgpQ
         zgqgnJDhcJMig4DNfqXBBLTL9h9lvJmUlYM1VOT4IfFlAVfdY3IgyK+MuZp3Fvb2iFmX
         +12eIFsrCbjf5qxQi8XJVGJP8QzzW4W/7SjhQk0tZ8Dq2/lRfMJqXKC8rC079euyzy8Q
         4t+cWfqoaLXpk0ggua1XT/T186Aw7L47LezaqwAIRv6rqwiAQQykBKcB74QZ8gFCUv5a
         K+Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9PrYHlRxVAp0PKntp/g5IXtOiRWuDez5zv9/khanWJY=;
        b=0iabR4r1GrgoYF8Sw3eo7dyT1mRZXQcutrN2Y+L1G+KvKy2M9fr9Wq7fFXNLZJ1Z7v
         WlBBOUtFzUn6uc3SubSmKrE41bDigH340dDcMdO343kj6eP81ni3oACZFdlSA86XJSTI
         zGdboKOliYwuujqClVi+gYl70pnXgChomGN7Rep3UddrD7NQaU+W+BbzWERDfwAZ9MuP
         yFgUCXkOaA6uP+tnrS0GpnSFOVbm/JtIWZM2U2OPmslyqvs9L70ffu4yv0zaM/ONiC9b
         o3uq8Y3Fx3kSJEekFQfMNWh0kJ4/FvOB1xFA13OHes3vomIOwRGsRPcPLI6PMB24/C+2
         hxQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PRfgAHmb;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9PrYHlRxVAp0PKntp/g5IXtOiRWuDez5zv9/khanWJY=;
        b=AjZVZRMhZl36WTvGJSJbLjeafyK/RB/RSZifLDNdkC/CD3ygvr+HH7puQ18lvl+IEw
         ISxZXLae5ZZstNfGGevpGqZz47xPp9bGtokMk2jtFQ3zQtlrzQtj1zhAoiqSnwH5sD+s
         PP42EpoH3KKve1ArJFvfh1D8D5Gd1jhKASojMhsEa/8U96J1X/T3HNDNB+/m5Fd78wl2
         OPZH1lL/lGkbNwGXmvJxiPXCXCIOFDE6fr2Zegaa9U3INxTr5s6En8aJZzY1T/9CrHOZ
         XVLt8gVi8R7g1XxLWz61Yr+UpkPEn+WGlNk3U3BotbC00fZtDm7hXf0P85AtKQHgeAME
         Ql9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9PrYHlRxVAp0PKntp/g5IXtOiRWuDez5zv9/khanWJY=;
        b=qlv2jEitiKBQZpUn9wlZmQHFFHJxF+wlNLqTWDJ7T6xal4oxJeY0rh47v7msMV3Q8A
         2mSdqhD2aZG8U0RdX19zrvTQNbQ/I1K0B0O7KuzGTQ7K6+6VYSwmh1MP+Sf1+y69kqm2
         DDd5/0mTFNa7GAoq8FRe5dPIBNLNvHUJHjMH7JR4JZRSQwSO92qtbRONe8/aaP8ypDyy
         dbOEWcgfeh//GuZ/0GD55PEctVSjv/lAnyuYgrH/ExdKELq8AOyYfTCnQ1n58r50We6T
         H8hFApgkwgUw7Iz9FfdAq6Co1Zt1pnE4Qp2pFkN4xdXTqm3//vv+Kjj8EiHBsOZqyDYS
         OLHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CjsgIPPbcQ4NLxZ84OliCEC0YdQf6m+Gv2f1KVIhfxdP6+0Oa
	3i633ZVXE1wk+vVC1PVwtxc=
X-Google-Smtp-Source: ABdhPJz3uIBG52/pJ7HCnn4D6h68RNgdOhYnMJq+kBh/ZUfvbMyYK7+iLMlt4tN+aeagPVMJHgTCSA==
X-Received: by 2002:a17:90b:24c:: with SMTP id fz12mr3094990pjb.138.1607725267430;
        Fri, 11 Dec 2020 14:21:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls4649577pld.8.gmail; Fri, 11
 Dec 2020 14:21:07 -0800 (PST)
X-Received: by 2002:a17:90a:d90e:: with SMTP id c14mr14951604pjv.85.1607725266950;
        Fri, 11 Dec 2020 14:21:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607725266; cv=none;
        d=google.com; s=arc-20160816;
        b=aDkKWATL0LrKO0HuPmjj62NrsaUvh4HfVZYyFvllTtfEaow8OkmHwuI9wenMBPyobs
         SbgtyBRBFEjOB+B5qrnZ//uWYJmT/4lcpKCtyvo2LcfwSXmPtWdw40akk26afLZC2OSt
         RRcw1KHoTPVyTqWwjjjvMKzijOyMYkmadA0TNhMiqUid5Xw9X753e8hH0c3cEfmPrWa3
         SQ5BAQdUnyAJwZ5C61P/HuojxzBaeoMHpPFv0nFigz822y63ZFp05vhUpuNHfeE9u2ny
         7Fh1QeNsT5IEU3GJKB77yVilkFtrJCNAg0YksQRzkfBEBjwIred+9brox4GG72Txc0iT
         aZ7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=M33/GbrA5rAEkfXts8qTtIq6RtlqxzbPQV+BXvS4r8Y=;
        b=qMnARyBvi/IkNDpAgbOp9PevosZM2bEdsbS+UXFex7yAoKpUdXXkpWFgAp+qSUpEv3
         uDCgdrbvRDCfqlSuPF/qT03jap1RpXBDrvA/iw1r3H0iX3VOAQrnETH6I/xE/Et3XItM
         4NS0pZgn2TRhaq3LY1WW2OkqzXBOSQ2/NWCxAIVkXIbENBueubBF1MT7ps8Wwr0WLSSo
         46nDuut6DmiZXTHOsM8uM36I0g9kbPYlOoRzlp3NeCG7Fs6cfpWn4iTP7u6Bz+A4XCch
         /pe2wCFLLX1t+2DP0tRX519fwWK0aEsLKvQEXvjRML8eBbv67jPPIedkWeqKJ6nhFHKj
         JX3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PRfgAHmb;
       spf=pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q18si767943pgv.5.2020.12.11.14.21.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Dec 2020 14:21:06 -0800 (PST)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Fri, 11 Dec 2020 23:21:04 +0100
From: Frederic Weisbecker <frederic@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [patch 1/3] tick: Remove pointless cpu valid check in hotplug
 code
Message-ID: <20201211222104.GB595642@lothringen>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.582579516@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201206212002.582579516@linutronix.de>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PRfgAHmb;       spf=pass
 (google.com: domain of frederic@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Sun, Dec 06, 2020 at 10:12:54PM +0100, Thomas Gleixner wrote:
> tick_handover_do_timer() which is invoked when a CPU is unplugged has a
> check for cpumask_first(cpu_online_mask) when it tries to hand over the
> tick update duty.
> 
> Checking the result of cpumask_first() there is pointless because if the
> online mask is empty at this point, then this would be the last CPU in the
> system going offline, which is impossible. There is always at least one CPU
> remaining. If online mask would be really empty then the timer duty would
> be the least of the resulting problems.
> 
> Remove the well meant check simply because it is pointless and confusing.
> 
> Signed-off-by: Thomas Gleixner <tglx@linutronix.de>
> ---
>  kernel/time/tick-common.c |   10 +++-------
>  1 file changed, 3 insertions(+), 7 deletions(-)
> 
> --- a/kernel/time/tick-common.c
> +++ b/kernel/time/tick-common.c
> @@ -407,17 +407,13 @@ EXPORT_SYMBOL_GPL(tick_broadcast_oneshot
>  /*
>   * Transfer the do_timer job away from a dying cpu.
>   *
> - * Called with interrupts disabled. Not locking required. If
> + * Called with interrupts disabled. No locking required. If
>   * tick_do_timer_cpu is owned by this cpu, nothing can change it.
>   */
>  void tick_handover_do_timer(void)
>  {
> -	if (tick_do_timer_cpu == smp_processor_id()) {
> -		int cpu = cpumask_first(cpu_online_mask);
> -
> -		tick_do_timer_cpu = (cpu < nr_cpu_ids) ? cpu :
> -			TICK_DO_TIMER_NONE;
> -	}
> +	if (tick_do_timer_cpu == smp_processor_id())
> +		tick_do_timer_cpu = cpumask_first(cpu_online_mask);

I was about to whine that this randomly chosen CPU may be idle and leave
the timekeeping stale until I realized that stop_machine() is running at that
time. Might be worth adding a comment about that.

Also why not just setting it to TICK_DO_TIMER_NONE and be done with it? Perhaps
to avoid that all the CPUs to compete and contend on jiffies update after stop
machine?

If so:

   Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201211222104.GB595642%40lothringen.
