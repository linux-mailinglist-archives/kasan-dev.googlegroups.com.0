Return-Path: <kasan-dev+bncBAABBE7QWXZAKGQERACO6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 653A9164D3D
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 19:01:57 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id z12sf623518pju.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2020 10:01:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582135316; cv=pass;
        d=google.com; s=arc-20160816;
        b=cK29GKAUr47l3dGrbnA+iebdmrF8/RBG8Rjbdunq1bxkNL6EVFP5sYK1YCEXAc5Np/
         h/ps0r1uhiNg0cisGYqxdA+6q3YW+6zLHEgAdcdEHrdNuO7lF3erScQzh82nCDVaZZef
         6S15ayHBfWWWQfTvUNoL53YAhNofxHoULIQHPzauOL2yTuv9NxSwOssning2KCI0hxbC
         I0OS1lXfUbLaZ97bUMjGX7dZELH4iSG0ZDFHNCC3MZ5Ic+Aw9B+HlKONEUAkaaFq0TEL
         OhyKOuVbaZxg4Q0j9LDYgydmfQ+tF+nV6BdtQ/QEkVY7XI8a9CjfyCdknD7g/6O4FEU+
         yiMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=BBaUT/8Ch6ygsLYRaYe4U9n3z7WNxYsZZ56EXhETwHA=;
        b=IdSAD4JEZaHspN3dPvEQ2uGWeLLYn/ZeJDT2zhX0dHd5qzlvn2hh5Vhnqea0zGUehk
         CM8S5uXjKYfAphwbyrjesQ4k29WMofhHMB0NpHDNmDkNq75Y+nRuYeQIFnFcHUvEkZ03
         vBKj/BYxYXEQIwoeVa2NYd5blCDiohxTcxT8dawXQ7hRG/k/xYOWvGP67BEbVARO6DQI
         yw1noyWSY3qFl0QxeH2vlgTMShC3Ebn6NvMqisZ6hy0T1RmZhR5fRfpRv/4idAp2SSkt
         DCBS7si33jiJ2a3EvmmyJzKnOHxCK538wf3cZ5FYtjfOrhyUPWW+XO/Xq9287iiIagQu
         i2zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PC5SIEBR;
       spf=pass (google.com: domain of srs0=16ht=4h=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=16Ht=4H=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BBaUT/8Ch6ygsLYRaYe4U9n3z7WNxYsZZ56EXhETwHA=;
        b=hTLoitcfp4ZW3/P7Li0Yh0MzrxpemWUPb6v3Z10R7FrxoX1Cz+O/KQ7bn3v9mWmNjK
         aJSBewLoMUQiyFEzCZmfpQGZGfKxSqq65Kda7/LeH1PrC9TuGYh5myP2yAODyRRobywS
         nouUu2ID0/pUnKziQcHQBdmpsCokH3XWZSBZopJxAgAGZ1jk0K3t1XuuPvIvF3xGBUTf
         FV9zow/xmU2aSmgk1DyWYtbkY4xM8kRUffWJs9C+69SdDCxYCDSNwUd/z0SjagGfUw2y
         Bsq87/6Wi7tA+gY5/VPG1S90GyAUwA1pzsdZUJYhhXiUVYpMYmjt84xvET41OLRlNG1J
         PsCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BBaUT/8Ch6ygsLYRaYe4U9n3z7WNxYsZZ56EXhETwHA=;
        b=n1JXvUOE46M6ieeMamGzaE3wGuaYA1m6iVtqMG4JAlOQ/+as4rfmbmL0GxFV23aAHh
         fKHhZtzqBKteTTcaFdOMbq7k1T6apDTBYsGdsMr9IPbkXar5o3Gbnx0/SPAnZIivAdBe
         maIYaqIAMVgASTB/i0wq6cW5PAKfgFYe6ZjZiFG0vJ8whwsb7i/GgsaefOxBiXP1rN3t
         U/pxKWui33m2lkZ/8lRSNZrSKwPxGFWzvqW8pBHxBYt+TGNJsfMnFn4kevojWNnIEVjX
         PMPnJyf4qS13JCdkNVb8UhFkT3j97uGxnCxsUEAcmd9zZrfb8FdE2Ke7K533Oifs0AdQ
         ez8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7nEGIYtvzjco6F6IYy6rG+YsKUl+o/cyp21po41Ux0IOquSay
	g1AvZqxJ33NAhHGgBwSQbUw=
X-Google-Smtp-Source: APXvYqymmiMxUaYLlv/2nJur6FKkXV2Y6paSht6jFQoNBGB9DwIOKgSCGODcbmvFuvEN9g5G88fyEg==
X-Received: by 2002:a63:cc09:: with SMTP id x9mr9846636pgf.339.1582135316041;
        Wed, 19 Feb 2020 10:01:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab86:: with SMTP id f6ls7591463plr.10.gmail; Wed, 19
 Feb 2020 10:01:55 -0800 (PST)
X-Received: by 2002:a17:90a:178f:: with SMTP id q15mr10480137pja.132.1582135315664;
        Wed, 19 Feb 2020 10:01:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582135315; cv=none;
        d=google.com; s=arc-20160816;
        b=PHlP9y6Mo0gRNJBDRWDDIeEi1I8X5HzlYB2mt5oAPYhE2XBHq+OMipoLoX4tSsPb2j
         bXgq2CDU7wofSfzSmWM0k1P4kvZQbOCbRzjRO+P/P4+I+nKXHODdNfgDt07A2U1w9e46
         x3oOOOIdHXS8mxeTdfkJxRcnD0QVfhpXik5TIEnTLf5wc9CmVnas23nh9s4cHjW/LSN8
         WZOb2oRCjBgluV9qwWUsGJ1N/Q6AapH6E52Iqc4rGLydAw16lfsc6cbur2MsQcRfYqNa
         SudVJe3E2inDDHI9oThPZ7Yac8719gY3EDhzp0Gk30YAIfP6oNq2+9QZeUeDISbJ1eB3
         QIHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=gnZ1F9gUnRDWBV4JdOstiTb0zYeGazVBoDuMiIXRXm8=;
        b=qdKALd5C5Z4qSeSVyAoD0AsnQImz3yM7OV1RR51KppQTXnIu8qbeYQVtFBmaYmEg/j
         TowvWxmAuahE+C3IIRmRmobmof087bYcrv1s58Fl8+lGmbnXFMd6yjszDrfUjy212Ba/
         62NGmr4ygqL6OnmPWoZ6Y8znHpNBOIogX6K/8ImR5ZfNyogPlKIPhZzH0xnWQz4aKsi7
         cL/EKYUXTTXKZudMRfg8wW+2LADCE1i/sdP5ecXwwYAQ3dhiPIuTIb5WWP2Sn/Iw2emC
         qH4BjLEkA7/FiIbH4Ew3iRGvCd3I/DxTyiyT0fqsAVz5EYx/BB/KQI4x57kyOK9zIW5U
         gyPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PC5SIEBR;
       spf=pass (google.com: domain of srs0=16ht=4h=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=16Ht=4H=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i16si365007pju.1.2020.02.19.10.01.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Feb 2020 10:01:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=16ht=4h=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 55DE924656;
	Wed, 19 Feb 2020 18:01:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 2AFF335209B0; Wed, 19 Feb 2020 10:01:55 -0800 (PST)
Date: Wed, 19 Feb 2020 10:01:55 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: Re: [PATCH] kcsan: Add option for verbose reporting
Message-ID: <20200219180155.GM2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200219151531.161515-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200219151531.161515-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=PC5SIEBR;       spf=pass
 (google.com: domain of srs0=16ht=4h=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=16Ht=4H=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Feb 19, 2020 at 04:15:31PM +0100, Marco Elver wrote:
> Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> Currently information about the reporting task's held locks and IRQ
> trace events are shown, if they are enabled.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: Qian Cai <cai@lca.pw>

Queued for testing and review, thank you!

							Thanx, Paul

> ---
>  kernel/kcsan/report.c | 48 +++++++++++++++++++++++++++++++++++++++++++
>  lib/Kconfig.kcsan     | 13 ++++++++++++
>  2 files changed, 61 insertions(+)
> 
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 11c791b886f3c..f14becb6f1537 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -1,10 +1,12 @@
>  // SPDX-License-Identifier: GPL-2.0
>  
> +#include <linux/debug_locks.h>
>  #include <linux/jiffies.h>
>  #include <linux/kernel.h>
>  #include <linux/lockdep.h>
>  #include <linux/preempt.h>
>  #include <linux/printk.h>
> +#include <linux/rcupdate.h>
>  #include <linux/sched.h>
>  #include <linux/spinlock.h>
>  #include <linux/stacktrace.h>
> @@ -245,6 +247,29 @@ static int sym_strcmp(void *addr1, void *addr2)
>  	return strncmp(buf1, buf2, sizeof(buf1));
>  }
>  
> +static void print_verbose_info(struct task_struct *task)
> +{
> +	if (!task)
> +		return;
> +
> +	if (task != current && task->state == TASK_RUNNING)
> +		/*
> +		 * Showing held locks for a running task is unreliable, so just
> +		 * skip this. The printed locks are very likely inconsistent,
> +		 * since the stack trace was obtained when the actual race
> +		 * occurred and the task has since continued execution. Since we
> +		 * cannot display the below information from the racing thread,
> +		 * but must print it all from the watcher thread, bail out.
> +		 * Note: Even if the task is not running, there is a chance that
> +		 * the locks held may be inconsistent.
> +		 */
> +		return;
> +
> +	pr_err("\n");
> +	debug_show_held_locks(task);
> +	print_irqtrace_events(task);
> +}
> +
>  /*
>   * Returns true if a report was generated, false otherwise.
>   */
> @@ -319,6 +344,26 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  				  other_info.num_stack_entries - other_skipnr,
>  				  0);
>  
> +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE) && other_info.task_pid != -1) {
> +			struct task_struct *other_task;
> +
> +			/*
> +			 * Rather than passing @current from the other task via
> +			 * @other_info, obtain task_struct here. The problem
> +			 * with passing @current via @other_info is that, we
> +			 * would have to get_task_struct/put_task_struct, and if
> +			 * we race with a task being released, we would have to
> +			 * release it in release_report(). This may result in
> +			 * deadlock if we want to use KCSAN on the allocators.
> +			 * Instead, make this best-effort, and if the task was
> +			 * already released, we just do not print anything here.
> +			 */
> +			rcu_read_lock();
> +			other_task = find_task_by_pid_ns(other_info.task_pid, &init_pid_ns);
> +			print_verbose_info(other_task);
> +			rcu_read_unlock();
> +		}
> +
>  		pr_err("\n");
>  		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
>  		       get_access_type(access_type), ptr, size,
> @@ -340,6 +385,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
>  			  0);
>  
> +	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +		print_verbose_info(current);
> +
>  	/* Print report footer. */
>  	pr_err("\n");
>  	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index f0b791143c6ab..ba9268076cfbc 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -20,6 +20,19 @@ menuconfig KCSAN
>  
>  if KCSAN
>  
> +config KCSAN_VERBOSE
> +	bool "Show verbose reports with more information about system state"
> +	depends on PROVE_LOCKING
> +	help
> +	  If enabled, reports show more information about the system state that
> +	  may help better analyze and debug races. This includes held locks and
> +	  IRQ trace events.
> +
> +	  While this option should generally be benign, we call into more
> +	  external functions on report generation; if a race report is
> +	  generated from any one of them, system stability may suffer due to
> +	  deadlocks or recursion.  If in doubt, say N.
> +
>  config KCSAN_DEBUG
>  	bool "Debugging of KCSAN internals"
>  
> -- 
> 2.25.0.265.gbab2e86ba0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200219180155.GM2935%40paulmck-ThinkPad-P72.
