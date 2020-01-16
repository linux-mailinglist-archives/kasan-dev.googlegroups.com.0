Return-Path: <kasan-dev+bncBAABBUWBQLYQKGQE5M4EFUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 78C3313EA4B
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 18:43:47 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id i67sf16660161ilf.5
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:43:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579196626; cv=pass;
        d=google.com; s=arc-20160816;
        b=l2FQ1gvofZwbe765dw9JWTr2gPczSPzfhK8009T6ERntHHpK+/oAuFnZhqaTQbCjRc
         TuXn7y8yhRw7T3bQY/O0WjgxJ2Bziz//Kp54+RNyZ8UOY4TqrfmTOur6h7afGBn4a75n
         Hnqxv+eXLfYdQfn879+ecV9dUkG3HvmJzx40KyP9wazHV01PsvGl2fnkRJSsB/Ghn06k
         lvA8BR9BGXMCPtHdTVauhqIc5OHzSuePDrCor8YsuKOzIuZCxubVghV/8AsKLtGHeGYL
         p1BOqeCzv4vjJHVg2llI77yNjM36Q/cewKWl4kEAs5NvdL7XDU2Gq8n8qYGo6jcif8Hx
         cknA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+W9RV9q6c8mauLR9FMCw1Fr+rlTOqL9gKii3FSMqu4k=;
        b=OfGycN4l2N3X3ktrPNo80AyETzsZ6f9Pfjx9H2hrHq14grOYkxVoKXEkC9XOJSZL6A
         8buILUBc8QVPoaKu2Jc68/CKMcFmoOB6pcIVeSbeWVAjlVqUTjkEVuYnNoTRi6NUONZt
         +/fLlkKtCiRz1ua0cNrtQ6KRsyRF+RC7FwdsTDJAheY5eTCwdgzMs35f5zNrFHLhBN9R
         0Al3+esHx4HYwnSvNVf7GD8w8KULpCC+F97csnOFIzyR6I4oQMSBJ8kyqYIVCycNxAox
         QHSCdhvR6m+0NzJgMokVRCY6LZllsYNAEU9F5rYMAiA99pmxKs32JzQRi9vsqvVhoUrK
         uR0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=zQnA9E92;
       spf=pass (google.com: domain of srs0=tri3=3f=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=tri3=3F=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+W9RV9q6c8mauLR9FMCw1Fr+rlTOqL9gKii3FSMqu4k=;
        b=bkafXthA23UK+iEaZhahqbBekGwKIbI0ijahitiFCm5T5qFTDemy6bXfJpZfGcTQPx
         JaoUeaYWbcvoiFxCujemtCc9Pf3CLHb+ZCc33emZt+Mciy+hun5ANzWQqVP8ljzM1brH
         VVI3w4OE7WZcWWsmD94c+MCun/Q23Spc0dpmZxRvyr11tJMC/pSDdSS974wpWOBN9tTr
         ZX3UqobvArqqx3OBRyDoNKOf7it78L+e0zL3L/1bwrkSoytbettqwNBSZCtYeEQNZFfI
         qbBWKfDJZm8xUICy0DT2+HK9mSuZnpLbzE6CnH4xPZGS2j/j6ch/+EwsDivSarqjn+lo
         9KLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+W9RV9q6c8mauLR9FMCw1Fr+rlTOqL9gKii3FSMqu4k=;
        b=HgVlLo7LfqMeLqkaxZ/5f1Q4POLDE0Vk68Gqa9kNusnbhs3dd9MBYeWyIeWcptBnZj
         GizcNrn9ZdXAcMklHN7fc9fxBOpESjioViinfa3gbYMMKy2jUv6JAW00ccLphqnRP2En
         QuBDfRegW9VCZ/GwHQXOgtjjfJ0Eh8DuGZOSuOzeDDVhMZeyAStlOrvaj/CEAkmDGDlD
         X/2Z2lX8aEQXFJzeR3srdWB4/x+jGSqiErtTVOrCnbtHPyBNdEeg9p4kemExAXmzG+nz
         IeooqWQv0B/SSVQy4qHxrIHrYM2htxFl8zzwbBAsNWSHQjSlD4tx4MToeSYk0T51D/UO
         je2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVM4ChJE7h9nNKJFeLf/vE4uIstkLcoRnMiWK4Wb53lksQ4qHEZ
	akxJbadlSFjIdOPCqB7CJEQ=
X-Google-Smtp-Source: APXvYqzNusam9ihCQxV5mC1QX/ldEjuKM+yldUd3DEUmE2AVpnLXRQnbX8O5Lo+wz0JUO3WDGu3KsA==
X-Received: by 2002:a6b:6118:: with SMTP id v24mr28137337iob.73.1579196626404;
        Thu, 16 Jan 2020 09:43:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ba5b:: with SMTP id o88ls4080294ili.2.gmail; Thu, 16 Jan
 2020 09:43:46 -0800 (PST)
X-Received: by 2002:a92:d308:: with SMTP id x8mr4792791ila.42.1579196626130;
        Thu, 16 Jan 2020 09:43:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579196626; cv=none;
        d=google.com; s=arc-20160816;
        b=FoRVn+tvo/lY3gT0O8H/cv1P4RQnjfv9VuqYvRdYTVg1dps34iyrJAseT8EvAwJcG9
         IdezCoaLNJP9wgbcW/K8wb52i2UyLTrCwocZ/fh4BjNaXYYeNH1Y1GliiyjJXbfzx/QV
         LqgYeHcG35UUc7UPY37ip0j8x6S46opZMGfhsJvYdy8o8GG9eno4P7MetJrDHRTHzn5W
         MdPZdy/C70IOEZSvrMrIVE9UPX4sF55PUC2PSHb7tyLyPeQLsHt3IBC9TZVZYsSYvCiL
         VbsYxm2tZnSkMm7Lm6EHOL5FfEnHLI268Mv4DiRFyAvVscuCcnXysZukmmQC9QA9+gWd
         i36g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=OLgkjmyEMUm4i2dB7m7Am561R1lmHTN7eRAFy6Q/6KU=;
        b=QIbyP4FgrhrQed629K6UGLhuKNxCxRqp2LxT3/NjjubC9cLKJd3MKGZ1hg6TcquyC2
         AIJzfg45NdTyksLPSj096oq1CWc7bgQgzRP4wGoeaFWBmz3BI1rgo8SKwFFnJ9Z/nFqA
         9QND9Nrm1zk5rSNKXC0VPoZW50phHIKkS2f2LPJHLfJ6TM7bCBs5Z4bS4X2skjdwiTst
         aU56nyJ2QSl/ZjNsn+2P9wq+tNX3XGbBViaVHxwJrkAYR0xaZb8MDFJXvff2J3SjatdT
         ce+WrK8fvO6hy/lEoMiD5r0GS6z7vmdn2MA7Ba1OAaVtz3JCfKdUoQFevBSPFa47u6gN
         swSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=zQnA9E92;
       spf=pass (google.com: domain of srs0=tri3=3f=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=tri3=3F=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h13si965941ioe.5.2020.01.16.09.43.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Jan 2020 09:43:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=tri3=3f=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9268B2474E;
	Thu, 16 Jan 2020 17:43:45 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 15F6E35227B9; Thu, 16 Jan 2020 09:43:44 -0800 (PST)
Date: Thu, 16 Jan 2020 09:43:44 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	peterz@infradead.org, mingo@redhat.com, will@kernel.org,
	Qian Cai <cai@lca.pw>
Subject: Re: [PATCH -rcu v2] kcsan: Make KCSAN compatible with lockdep
Message-ID: <20200116174344.GV2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200115162512.70807-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200115162512.70807-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=zQnA9E92;       spf=pass
 (google.com: domain of srs0=tri3=3f=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=tri3=3F=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Jan 15, 2020 at 05:25:12PM +0100, Marco Elver wrote:
> We must avoid any recursion into lockdep if KCSAN is enabled on
> utilities used by lockdep. One manifestation of this is corrupting
> lockdep's IRQ trace state (if TRACE_IRQFLAGS). Fix this by:
> 
> 1. Using raw_local_irq{save,restore} in kcsan_setup_watchpoint().
> 2. Disabling lockdep in kcsan_report().
> 
> Tested with:
> 
>   CONFIG_LOCKDEP=y
>   CONFIG_DEBUG_LOCKDEP=y
>   CONFIG_TRACE_IRQFLAGS=y
> 
> Where previously, the following warning (and variants with different
> stack traces) was consistently generated, with the fix introduced in
> this patch, the warning cannot be reproduced.

I added Vlad's ack and Qian's Tested-by and queued this.  Thank you all!

							Thanx, Paul

>     WARNING: CPU: 0 PID: 2 at kernel/locking/lockdep.c:4406 check_flags.part.0+0x101/0x220
>     Modules linked in:
>     CPU: 0 PID: 2 Comm: kthreadd Not tainted 5.5.0-rc1+ #11
>     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.12.0-1 04/01/2014
>     RIP: 0010:check_flags.part.0+0x101/0x220
>     <snip>
>     Call Trace:
>      lock_is_held_type+0x69/0x150
>      freezer_fork+0x20b/0x370
>      cgroup_post_fork+0x2c9/0x5c0
>      copy_process+0x2675/0x3b40
>      _do_fork+0xbe/0xa30
>      ? _raw_spin_unlock_irqrestore+0x40/0x50
>      ? match_held_lock+0x56/0x250
>      ? kthread_park+0xf0/0xf0
>      kernel_thread+0xa6/0xd0
>      ? kthread_park+0xf0/0xf0
>      kthreadd+0x321/0x3d0
>      ? kthread_create_on_cpu+0x130/0x130
>      ret_from_fork+0x3a/0x50
>     irq event stamp: 64
>     hardirqs last  enabled at (63): [<ffffffff9a7995d0>] _raw_spin_unlock_irqrestore+0x40/0x50
>     hardirqs last disabled at (64): [<ffffffff992a96d2>] kcsan_setup_watchpoint+0x92/0x460
>     softirqs last  enabled at (32): [<ffffffff990489b8>] fpu__copy+0xe8/0x470
>     softirqs last disabled at (30): [<ffffffff99048939>] fpu__copy+0x69/0x470
> 
> Reported-by: Qian Cai <cai@lca.pw>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Update comments.
> ---
>  kernel/kcsan/core.c     |  6 ++++--
>  kernel/kcsan/report.c   | 11 +++++++++++
>  kernel/locking/Makefile |  3 +++
>  3 files changed, 18 insertions(+), 2 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 87bf857c8893..64b30f7716a1 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -336,8 +336,10 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  	 *      CPU-local data accesses), it makes more sense (from a data race
>  	 *      detection point of view) to simply disable preemptions to ensure
>  	 *      as many tasks as possible run on other CPUs.
> +	 *
> +	 * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
>  	 */
> -	local_irq_save(irq_flags);
> +	raw_local_irq_save(irq_flags);
>  
>  	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
>  	if (watchpoint == NULL) {
> @@ -429,7 +431,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  
>  	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
>  out_unlock:
> -	local_irq_restore(irq_flags);
> +	raw_local_irq_restore(irq_flags);
>  out:
>  	user_access_restore(ua_flags);
>  }
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index b5b4feea49de..33bdf8b229b5 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -2,6 +2,7 @@
>  
>  #include <linux/jiffies.h>
>  #include <linux/kernel.h>
> +#include <linux/lockdep.h>
>  #include <linux/preempt.h>
>  #include <linux/printk.h>
>  #include <linux/sched.h>
> @@ -410,6 +411,14 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
>  {
>  	unsigned long flags = 0;
>  
> +	/*
> +	 * With TRACE_IRQFLAGS, lockdep's IRQ trace state becomes corrupted if
> +	 * we do not turn off lockdep here; this could happen due to recursion
> +	 * into lockdep via KCSAN if we detect a data race in utilities used by
> +	 * lockdep.
> +	 */
> +	lockdep_off();
> +
>  	kcsan_disable_current();
>  	if (prepare_report(&flags, ptr, size, access_type, cpu_id, type)) {
>  		if (print_report(ptr, size, access_type, value_change, cpu_id, type) && panic_on_warn)
> @@ -418,4 +427,6 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
>  		release_report(&flags, type);
>  	}
>  	kcsan_enable_current();
> +
> +	lockdep_on();
>  }
> diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> index 45452facff3b..6d11cfb9b41f 100644
> --- a/kernel/locking/Makefile
> +++ b/kernel/locking/Makefile
> @@ -5,6 +5,9 @@ KCOV_INSTRUMENT		:= n
>  
>  obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
>  
> +# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
> +KCSAN_SANITIZE_lockdep.o := n
> +
>  ifdef CONFIG_FUNCTION_TRACER
>  CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_lockdep_proc.o = $(CC_FLAGS_FTRACE)
> -- 
> 2.25.0.rc1.283.g88dfdc4193-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116174344.GV2935%40paulmck-ThinkPad-P72.
