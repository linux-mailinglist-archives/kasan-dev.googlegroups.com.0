Return-Path: <kasan-dev+bncBAABBAEJYLZAKGQED3ARX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E57E8168B93
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2020 02:31:45 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id z79sf4467368ilf.4
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 17:31:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582335105; cv=pass;
        d=google.com; s=arc-20160816;
        b=DXDAbTz3NRStGI0GkUkloPnQxmZeKsmd6l0oVUHIwb/8f4vnrO+UREoO7ObuEzs52h
         Ra6tMDX1XdOOFAi2N5lE5cOgQnj/ucTTony/3Eg7RCWN2YZG6rNWBH/ZXrK/BLI4vep4
         9uIJ+XcqyqiIaoZtYng3oG5B7MkL6DcB4inJ3GpgnGYb/tK6Gk+RHtKNPX+PbMjKPJnW
         p/2gM7FrrmAqVwAMtdo3Iw+1GG9n2TkZpcpVaCcsAfMj1lJmmZS10vh5mXR6N8D1IKxw
         G0z9iDt+zZoKu2RWH1L2xrMgH4eApbEqoSnnSUcYmPm1Hg4okPxskLtzt8PXioPPljIB
         dC/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=wfD1IQllI4gUfke8m4I//YPOHY9OfDf2bPOl5mu7GgQ=;
        b=DE1ZoOGW4a493GH5Pqa121uehC+U5Sig1G5a9HhQUtgVaSjUCkKEbiLFkIp555PM3Q
         1E0Zzy0/j7xfduL3zp7t/6rnm3qqDu7c3N18lkT8r6hLPAxE1euSl4W9KeoRSfym1chb
         7gV8kOVEpRhTmfhajJpg/b8//6Vfu9439l0C5wB+FXcAVO/ZJ9sIeQ4U7S2pT82VQuSG
         a37XjgLWqjUmAyCtUWlBOYilxRptHfA85JwEpfT/BUFMJhScA7fcDin0ZjpmlO1TXfig
         ErHCyw4H/0UdQmhMPukzyjY8oVzLGHab7I7TO/qHod4zLlm0wqj99lrndvm2OXjY7zoW
         4ZCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=QebuZBPu;
       spf=pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfD1IQllI4gUfke8m4I//YPOHY9OfDf2bPOl5mu7GgQ=;
        b=ZJm2ajH7ttxIdMgFi8E6dfW6JWN7Y9PFdw0Q1Ma5qa4TjpYlxedAJCfbIXLrPjROk+
         84uS8Gk9H/Nyxpn5+6Z2RKVi1UaafL5euMJuairgBOYabgnwgRwqlbX8T6N2fVE78bTA
         OI0H9KV8UsuMciGmphKQv0MOSfy5u9Ceoqz6LwFOIZHhdQIXm/camwx9d4j84hwiW/5P
         VLyAAYSRGS3QY96+4ogiye+ovMZf4+zv+OIrwIG0zvmREAf1AEI7RO/4XvmzBP4PEwni
         XfsvO2dq/fkt1yzeKn6AAJNdkIPxrA5ogFE8Lh5UTUr8WFwxzP+vFHeU2IsIzo8ipi9G
         5Teg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wfD1IQllI4gUfke8m4I//YPOHY9OfDf2bPOl5mu7GgQ=;
        b=pUU0v6x7nztMNrCqDF8RbNYLjFqHcp0TQBis65miV9QD0lql+7bxsZ4VYF6AxvPcMz
         taBSWxqeacPeVVj4BD/1+gGjTWdrWBHDquhRtSw9iW7HATySRjXuGXwZxtukB4DmFaWf
         DUXR1FTrGtS/8RekNtTTldI48VVyInDGibT90ArabR28g2+v9G41cMOtLaOsSY5QmN/u
         166Ttkb5kRFhbdHGK/t/6vIhTzIPJ1ynWHT6zvqQOVQ01gtMzGJf6UY3MztetLB/Vc7G
         KIiSNw3LpL3bmhK6V456yBbtPUhZmWQXTpZOVlWRslJhn+oJW/AMF9xB9l0XwQYYx4YX
         RIpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXP/U2rn/+iAZGsLdKTgqG0H582B1cj7f/qPfxRIWmtndKJ8BVD
	DA6NT/tl2IRaCmFEtRALZuw=
X-Google-Smtp-Source: APXvYqyePz+CKpiPzOHhp32+R3NJnh9sUF7nYMlRG2C3T6l6CcUhYUjYqVrEjWvpqwor52kif3gLpw==
X-Received: by 2002:a5d:980f:: with SMTP id a15mr34946969iol.203.1582335104861;
        Fri, 21 Feb 2020 17:31:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:384c:: with SMTP id v12ls373042jae.8.gmail; Fri, 21 Feb
 2020 17:31:44 -0800 (PST)
X-Received: by 2002:a05:6638:24f:: with SMTP id w15mr36565576jaq.130.1582335104440;
        Fri, 21 Feb 2020 17:31:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582335104; cv=none;
        d=google.com; s=arc-20160816;
        b=Zt9akjULgkyWn7TnaZdesh+48hBzkEFQIbij6kFARNWD+3rzZ4DJAaVwuMoz7wUvx5
         a90QcqdS+X2EYif+4NBxa8uiI3ModQPtC+tsm7LsTkiIR9AuwnF2niGeC3vcS9cwgNnm
         l7DSq6f9ucdVd54R/EHhypeRxBZcNCVKfNE6VPf9XwlR2UNVbQHqNZAPzlLDSCbeGU3k
         bZVFbhNoyEmO8KJZZ3gF6IwF1d0+I/eYke8tRvcQ+ylPYKQskJ42E6zn+feYRX1y3qFP
         3phawhBvCUmJydF9T6mOvSgnObQxzY8JWbeN3faw1lnnbP0WCCVaoVa25RG5Azj4CDYj
         79uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=BjpiOFCaz8HK3YOCIC48lhdzcvVKD5/DkMRNIV3boNc=;
        b=v0+Fz26NFA5ekWQPYTvq3mKJyT456WSpWNIAZMMeC3XRUaZvWqWyGoaCTZSGSc46mS
         Uf2wxKUm7zK1Ohxu/rSt22eRAGWzgRyhNTByqu7FlGPlHvpwfeQCX79NQ+0JScOv4RUE
         wTHCl+xIneAKXGYrxmuNtz+64lSbQXCqidRrsYY3kTs9U0F0JFTInNVatMY44/gk5Ie6
         VK1iQnJ9eRWzT0JTFQhRtwbPDjJr6oJDhc9vcl2q2ycbyb72j+Lrx/Oa8WXH6byBPIRX
         L4XwpQm/t3QEyj28+56f7M8qRxT9YpGzHiXWE33tGSKd91dNgklKFcY6o3ipWfsUEbNE
         ai6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=QebuZBPu;
       spf=pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h4si370305ilf.3.2020.02.21.17.31.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Feb 2020 17:31:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B73AD20675;
	Sat, 22 Feb 2020 01:31:43 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 90F5335226DB; Fri, 21 Feb 2020 17:31:43 -0800 (PST)
Date: Fri, 21 Feb 2020 17:31:43 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kcsan: Add option to allow watcher interruptions
Message-ID: <20200222013143.GP2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200221220209.164772-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200221220209.164772-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=QebuZBPu;       spf=pass
 (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Feb 21, 2020 at 11:02:09PM +0100, Marco Elver wrote:
> Add option to allow interrupts while a watchpoint is set up. This can be
> enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> parameter 'kcsan.interrupt_watcher=1'.
> 
> Note that, currently not all safe per-CPU access primitives and patterns
> are accounted for, which could result in false positives. For example,
> asm-generic/percpu.h uses plain operations, which by default are
> instrumented. On interrupts and subsequent accesses to the same
> variable, KCSAN would currently report a data race with this option.
> 
> Therefore, this option should currently remain disabled by default, but
> may be enabled for specific test scenarios.
> 
> To avoid new warnings, changes all uses of smp_processor_id() to use the
> raw version (as already done in kcsan_found_watchpoint()). The exact SMP
> processor id is for informational purposes in the report, and
> correctness is not affected.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Applied in place of V1, thank you!

							Thanx, Paul

> ---
> v2:
> * Change smp_processor_id() to raw_smp_processor_id() as already used in
>   kcsan_found_watchpoint() to avoid warnings.
> ---
>  kernel/kcsan/core.c | 34 ++++++++++------------------------
>  lib/Kconfig.kcsan   | 11 +++++++++++
>  2 files changed, 21 insertions(+), 24 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 589b1e7f0f253..e7387fec66795 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -21,6 +21,7 @@ static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
>  static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
>  static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
>  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
> +static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
>  
>  #ifdef MODULE_PARAM_PREFIX
>  #undef MODULE_PARAM_PREFIX
> @@ -30,6 +31,7 @@ module_param_named(early_enable, kcsan_early_enable, bool, 0);
>  module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
>  module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
>  module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
> +module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
>  
>  bool kcsan_enabled;
>  
> @@ -354,7 +356,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  	unsigned long access_mask;
>  	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
>  	unsigned long ua_flags = user_access_save();
> -	unsigned long irq_flags;
> +	unsigned long irq_flags = 0;
>  
>  	/*
>  	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
> @@ -370,26 +372,9 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  		goto out;
>  	}
>  
> -	/*
> -	 * Disable interrupts & preemptions to avoid another thread on the same
> -	 * CPU accessing memory locations for the set up watchpoint; this is to
> -	 * avoid reporting races to e.g. CPU-local data.
> -	 *
> -	 * An alternative would be adding the source CPU to the watchpoint
> -	 * encoding, and checking that watchpoint-CPU != this-CPU. There are
> -	 * several problems with this:
> -	 *   1. we should avoid stealing more bits from the watchpoint encoding
> -	 *      as it would affect accuracy, as well as increase performance
> -	 *      overhead in the fast-path;
> -	 *   2. if we are preempted, but there *is* a genuine data race, we
> -	 *      would *not* report it -- since this is the common case (vs.
> -	 *      CPU-local data accesses), it makes more sense (from a data race
> -	 *      detection point of view) to simply disable preemptions to ensure
> -	 *      as many tasks as possible run on other CPUs.
> -	 *
> -	 * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
> -	 */
> -	raw_local_irq_save(irq_flags);
> +	if (!kcsan_interrupt_watcher)
> +		/* Use raw to avoid lockdep recursion via IRQ flags tracing. */
> +		raw_local_irq_save(irq_flags);
>  
>  	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
>  	if (watchpoint == NULL) {
> @@ -507,7 +492,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
>  			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
>  
> -		kcsan_report(ptr, size, type, value_change, smp_processor_id(),
> +		kcsan_report(ptr, size, type, value_change, raw_smp_processor_id(),
>  			     KCSAN_REPORT_RACE_SIGNAL);
>  	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
>  		/* Inferring a race, since the value should not have changed. */
> @@ -518,13 +503,14 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  
>  		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
>  			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
> -				     smp_processor_id(),
> +				     raw_smp_processor_id(),
>  				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
>  	}
>  
>  	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
>  out_unlock:
> -	raw_local_irq_restore(irq_flags);
> +	if (!kcsan_interrupt_watcher)
> +		raw_local_irq_restore(irq_flags);
>  out:
>  	user_access_restore(ua_flags);
>  }
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index f0b791143c6ab..081ed2e1bf7b1 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -88,6 +88,17 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
>  	  KCSAN_WATCH_SKIP. If false, the chosen value is always
>  	  KCSAN_WATCH_SKIP.
>  
> +config KCSAN_INTERRUPT_WATCHER
> +	bool "Interruptible watchers"
> +	help
> +	  If enabled, a task that set up a watchpoint may be interrupted while
> +	  delayed. This option will allow KCSAN to detect races between
> +	  interrupted tasks and other threads of execution on the same CPU.
> +
> +	  Currently disabled by default, because not all safe per-CPU access
> +	  primitives and patterns may be accounted for, and therefore could
> +	  result in false positives.
> +
>  config KCSAN_REPORT_ONCE_IN_MS
>  	int "Duration in milliseconds, in which any given race is only reported once"
>  	default 3000
> -- 
> 2.25.0.265.gbab2e86ba0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200222013143.GP2935%40paulmck-ThinkPad-P72.
