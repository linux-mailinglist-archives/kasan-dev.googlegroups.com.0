Return-Path: <kasan-dev+bncBAABBK4LYLZAKGQEOJVQDHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B393168B96
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2020 02:36:45 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id t17sf3112742qkg.16
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 17:36:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582335404; cv=pass;
        d=google.com; s=arc-20160816;
        b=O4OkB1T1+uBwran8ExtTmafWlm8LFwztWptMHEXj+TErqhbTo07PGE0XC2z31GMQ0p
         bUMydrh2NG9vKzzxegA3vWtg2C8ogXt37kfjVK5KcWvqfwatrvpVbTZ/c83LPMwCHBHc
         lCN9rzYJzSkmrj0tta29e5exJ8TkvSfsvpqcwur60gYHYTc0/Kz+jOp8EJwSvB5NesKi
         qP3LgFL+Wd9OhVTCw4B3OkUrtXu+1huGBKQLVG9ygztvt5dpWi1B+7UjUA53qrUcNdIc
         c6I6tIGJAqWjiM+Ak5DY+MHjmERi5YwxT0QtU68nGs8XEVEplIXu7SA5MAncKFOoXiW4
         jSvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=/Pzs/UMsZFjsvMsl3jWmpkHSw4+Qnu0TSmX2GjSgeSg=;
        b=nhKKKS+dp9ntNiyuYjnX8RfsXGjlmNsWRMlpJBGm+upDfKpfg/5Be0j4OazTCPo8O3
         9536S5fYD9YrmzLOwtHD0C+UNS7OXHu+ZfTmA1RW9jmxl+ProlYabqvc8ehfMObfe5nQ
         iLr70hpCldEPzeRWO275f9SJxAC69rhBCFbUyo89sRkWCTjFj0JUx5BAeAPqbKZ6iD4R
         RiXxrCa0bQKuH6+eJUBs4DkZSVALcWbspqogZolHRSXa6xs2GThZUU4Niu5hCacrbbss
         F14LRMr/ioDiXfa14o3fMdvM5VJ8xMtcnxXV7eTRicEidVU3EWFAxlLjK4OUemsCzQ8s
         ePCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HYVeR6xC;
       spf=pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/Pzs/UMsZFjsvMsl3jWmpkHSw4+Qnu0TSmX2GjSgeSg=;
        b=URBalNrH5lxQ1eUrbiDspmVmxtEwa/1xSrBhVshUGPcw6JFf21F8alC4ntU8hnrjkn
         0OJ6YC3YUG2VXbZ/KC9UU64RdWDw2FA8ban+XkCyPLyOtK6dljJ95NdsB2YgFuopT2Ft
         nHPNRzUfYmycvbkzFoP5DDh5gZ3otnI1vEQ3c/EqWCEbdBb6GnyPqVinzr3SMsuxbpDH
         XzMS+VDfHKF/AFdyCNd22XcJPL7ZOZ2gIzsnB49mMt2vnD0aCkx8G6ee4bmPXxqzlYQi
         0PCgpyBPz5HrW1FQ4FcShVinsgia0jN9MyPFIlpJ663EtXsTVaCyqfWtXXR85UJM5goa
         QP5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/Pzs/UMsZFjsvMsl3jWmpkHSw4+Qnu0TSmX2GjSgeSg=;
        b=uI2qa73p3dX8BbIgASdP3JXwGHE/O/engpM0EyJXQ1T7SJb9X5I+rQ7DGinkpHFjLu
         J/ge3354+IckTqBP3i4jC2WhXxi/Z5/ynl2woMZ0JGzjp82xatWjnhF5hkicOa01h+Cv
         SUhH232qDNN65tO2u7m+604H9q5EruG4y5ghtkw/UIRoonED3VUiYBKs82URgDuHuO/4
         DW/QVnklupNN87ychJe026/6LGU7M8snbbvQLaN1Ak+MiUVBQu3LjKP+wJsj2649BhOL
         A9cMExUNyPFe0jaK9LH5fLDoFMkf0LaUo0b0TfVb/dbtSAFgVA8LHISPn3+/NgzWxuM9
         71Xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWi5YWRBd5FyOGvHF0gNvESOwxzLGjWBtCdL1A1mY7FNs84BIFt
	UwTkRaXAHNvWJJmE861rarM=
X-Google-Smtp-Source: APXvYqxwJZgxccFHM1NXAR3ObwIL8P3hKKFoYQXvLpEZtb4iYG9YI6yjLgXz/sYJ5R+kM1my7Tl86A==
X-Received: by 2002:ac8:71cf:: with SMTP id i15mr35293248qtp.383.1582335403755;
        Fri, 21 Feb 2020 17:36:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:312d:: with SMTP id g42ls1568954qtb.8.gmail; Fri, 21 Feb
 2020 17:36:43 -0800 (PST)
X-Received: by 2002:ac8:7765:: with SMTP id h5mr35147780qtu.223.1582335403465;
        Fri, 21 Feb 2020 17:36:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582335403; cv=none;
        d=google.com; s=arc-20160816;
        b=qzZpJNJSCWG4GrqTn5KowpMcEuObepaE4mNV31GgzYOAeGP83LGKnNZ1fycvKZHIwk
         zgHwjx/1jeD4giW33JAcZDYe4YWh0r46dFNCeNDiraORwKfaPZ+wZCbnL6HAvi0bTuTR
         Ma3eMVQq7QY5XALwnA6fBjhyiCCV1FsjRvtRRyyrSvSEaec9veZiQDEQNkOu7v4DkCst
         Txv7PgNCSirYpK9Y6+kXGhk6rDKGYqM7tWAdjq9u0ozpkjrUkhJ4WrAIKpczHBTupY0u
         ny2BqxO9epsn55mDUHqElar1wuP8MRA8RlMC6jQRKbxISdU1Cx4O50ju/WoCwr1miRw9
         1iGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=jJgI1hC7D9sOuSyil+oDFLANTEftnGwOPjC02exU7OM=;
        b=fcMul16lGrBSNaMH5h3iuKhyfiG6mR5+MVcJ10tKoNl6rPvUg12Zcx35oe2SdVHLTR
         5Vi8+i6w5Zn8/6kiBknrNmvQq5hTvhMyCa71g0Ag758DdDflz/5YWsoDPIoHprKYTpEz
         aeF9iN6hsYoNhG+n9DKTWl3Q/EKCvS1MoJ1XXyHoPNKx4YMcuUyQlBe7KBUsFI0SPcdr
         Z3WxWQuyFWL6SemkgPp8XOUyqeIrD1rfUkOzSN87JwOuG+mLAjWZ9FUjB/5q/cAC++gw
         NyWzKTxC5OH8OkEzNcy+e8Rzk7nZIIBL6uxJCbEPDt8eFEX/Bb/A5eKssm8PSdofRDVm
         n5jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HYVeR6xC;
       spf=pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=JASw=4K=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b15si202800qkh.5.2020.02.21.17.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Feb 2020 17:36:43 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=jasw=4k=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 43FBA206EF;
	Sat, 22 Feb 2020 01:36:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 16BD835226DB; Fri, 21 Feb 2020 17:36:42 -0800 (PST)
Date: Fri, 21 Feb 2020 17:36:42 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
Message-ID: <20200222013642.GQ2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200221231027.230147-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200221231027.230147-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=HYVeR6xC;       spf=pass
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

On Sat, Feb 22, 2020 at 12:10:27AM +0100, Marco Elver wrote:
> Adds CONFIG_KCSAN_VERBOSE to optionally enable more verbose reports.
> Currently information about the reporting task's held locks and IRQ
> trace events are shown, if they are enabled.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: Qian Cai <cai@lca.pw>

Applied in place of v1, thank you!  Please check -rcu's "dev" branch
to make sure that I have correct ordering and versions.

							Thanx, Paul

> ---
> v3:
> * Typos
> v2:
> * Rework obtaining 'current' for the "other thread" -- it now passes
>   'current' and ensures that we stall until the report was printed, so
>   that the lockdep information contained in 'current' is accurate. This
>   was non-trivial but testing so far leads me to conclude this now
>   reliably prints the held locks for the "other thread" (please test
>   more!).
> ---
>  kernel/kcsan/core.c   |   4 +-
>  kernel/kcsan/kcsan.h  |   3 ++
>  kernel/kcsan/report.c | 103 +++++++++++++++++++++++++++++++++++++++++-
>  lib/Kconfig.kcsan     |  13 ++++++
>  4 files changed, 120 insertions(+), 3 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index e7387fec66795..065615df88eaa 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -18,8 +18,8 @@
>  #include "kcsan.h"
>  
>  static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
> -static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> -static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
> +unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
> +unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
>  static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
>  static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
>  
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> index 892de5120c1b6..e282f8b5749e9 100644
> --- a/kernel/kcsan/kcsan.h
> +++ b/kernel/kcsan/kcsan.h
> @@ -13,6 +13,9 @@
>  /* The number of adjacent watchpoints to check. */
>  #define KCSAN_CHECK_ADJACENT 1
>  
> +extern unsigned int kcsan_udelay_task;
> +extern unsigned int kcsan_udelay_interrupt;
> +
>  /*
>   * Globally enable and disable KCSAN.
>   */
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 11c791b886f3c..7bdb515e3662f 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -1,5 +1,7 @@
>  // SPDX-License-Identifier: GPL-2.0
>  
> +#include <linux/debug_locks.h>
> +#include <linux/delay.h>
>  #include <linux/jiffies.h>
>  #include <linux/kernel.h>
>  #include <linux/lockdep.h>
> @@ -31,7 +33,26 @@ static struct {
>  	int			cpu_id;
>  	unsigned long		stack_entries[NUM_STACK_ENTRIES];
>  	int			num_stack_entries;
> -} other_info = { .ptr = NULL };
> +
> +	/*
> +	 * Optionally pass @current. Typically we do not need to pass @current
> +	 * via @other_info since just @task_pid is sufficient. Passing @current
> +	 * has additional overhead.
> +	 *
> +	 * To safely pass @current, we must either use get_task_struct/
> +	 * put_task_struct, or stall the thread that populated @other_info.
> +	 *
> +	 * We cannot rely on get_task_struct/put_task_struct in case
> +	 * release_report() races with a task being released, and would have to
> +	 * free it in release_report(). This may result in deadlock if we want
> +	 * to use KCSAN on the allocators.
> +	 *
> +	 * Since we also want to reliably print held locks for
> +	 * CONFIG_KCSAN_VERBOSE, the current implementation stalls the thread
> +	 * that populated @other_info until it has been consumed.
> +	 */
> +	struct task_struct	*task;
> +} other_info;
>  
>  /*
>   * Information about reported races; used to rate limit reporting.
> @@ -245,6 +266,16 @@ static int sym_strcmp(void *addr1, void *addr2)
>  	return strncmp(buf1, buf2, sizeof(buf1));
>  }
>  
> +static void print_verbose_info(struct task_struct *task)
> +{
> +	if (!task)
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
> @@ -319,6 +350,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  				  other_info.num_stack_entries - other_skipnr,
>  				  0);
>  
> +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +		    print_verbose_info(other_info.task);
> +
>  		pr_err("\n");
>  		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
>  		       get_access_type(access_type), ptr, size,
> @@ -340,6 +374,9 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
>  	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
>  			  0);
>  
> +	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +		print_verbose_info(current);
> +
>  	/* Print report footer. */
>  	pr_err("\n");
>  	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> @@ -357,6 +394,67 @@ static void release_report(unsigned long *flags, enum kcsan_report_type type)
>  	spin_unlock_irqrestore(&report_lock, *flags);
>  }
>  
> +/*
> + * Sets @other_info.task and awaits consumption of @other_info.
> + *
> + * Precondition: report_lock is held.
> + * Postcondition: report_lock is held.
> + */
> +static void
> +set_other_info_task_blocking(unsigned long *flags, const volatile void *ptr)
> +{
> +	/*
> +	 * We may be instrumenting a code-path where current->state is already
> +	 * something other than TASK_RUNNING.
> +	 */
> +	const bool is_running = current->state == TASK_RUNNING;
> +	/*
> +	 * To avoid deadlock in case we are in an interrupt here and this is a
> +	 * race with a task on the same CPU (KCSAN_INTERRUPT_WATCHER), provide a
> +	 * timeout to ensure this works in all contexts.
> +	 *
> +	 * Await approximately the worst case delay of the reporting thread (if
> +	 * we are not interrupted).
> +	 */
> +	int timeout = max(kcsan_udelay_task, kcsan_udelay_interrupt);
> +
> +	other_info.task = current;
> +	do {
> +		if (is_running) {
> +			/*
> +			 * Let lockdep know the real task is sleeping, to print
> +			 * the held locks (recall we turned lockdep off, so
> +			 * locking/unlocking @report_lock won't be recorded).
> +			 */
> +			set_current_state(TASK_UNINTERRUPTIBLE);
> +		}
> +		spin_unlock_irqrestore(&report_lock, *flags);
> +		/*
> +		 * We cannot call schedule() since we also cannot reliably
> +		 * determine if sleeping here is permitted -- see in_atomic().
> +		 */
> +
> +		udelay(1);
> +		spin_lock_irqsave(&report_lock, *flags);
> +		if (timeout-- < 0) {
> +			/*
> +			 * Abort. Reset other_info.task to NULL, since it
> +			 * appears the other thread is still going to consume
> +			 * it. It will result in no verbose info printed for
> +			 * this task.
> +			 */
> +			other_info.task = NULL;
> +			break;
> +		}
> +		/*
> +		 * If @ptr nor @current matches, then our information has been
> +		 * consumed and we may continue. If not, retry.
> +		 */
> +	} while (other_info.ptr == ptr && other_info.task == current);
> +	if (is_running)
> +		set_current_state(TASK_RUNNING);
> +}
> +
>  /*
>   * Depending on the report type either sets other_info and returns false, or
>   * acquires the matching other_info and returns true. If other_info is not
> @@ -388,6 +486,9 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
>  		other_info.cpu_id		= cpu_id;
>  		other_info.num_stack_entries	= stack_trace_save(other_info.stack_entries, NUM_STACK_ENTRIES, 1);
>  
> +		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
> +			set_other_info_task_blocking(flags, ptr);
> +
>  		spin_unlock_irqrestore(&report_lock, *flags);
>  
>  		/*
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 081ed2e1bf7b1..0f1447ff8f558 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200222013642.GQ2935%40paulmck-ThinkPad-P72.
