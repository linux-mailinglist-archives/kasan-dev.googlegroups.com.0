Return-Path: <kasan-dev+bncBAABBJVS37ZAKGQEYQGXVKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B92291721B8
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 15:58:47 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id q24sf3717013iot.20
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 06:58:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582815526; cv=pass;
        d=google.com; s=arc-20160816;
        b=H4cK6CROZPAv0Sy+U8h8s964d77sWZMLtkyUir6W2wQ3O89WKdbNvOStV4FqliFu+N
         P/UaYdu6jRlbL/bjRsm25Oh0MC4a+arJUI2zSwk/w09NiRHg2h8WF2TB/KbYwFRbhxg/
         IYapGoPHt8gAbVqyhlKtzWpXIYZm27+ZTxq6N8Kaqjd/Q1rh+KMVl9XyXTwtg1JP8ukm
         rQ2qyQT43nCWcjS5XvCOgnwFhoKbQB3Rfe3nT56XYq+Hr9T79EdQ3SVpHZVIvI3PtmGR
         LDrTpqy5JaI69eoCJM7h4MLMo6N/ShZaw8ImsMJLJKIYxxQh11oaquDPSBuTuuhmK3st
         mZvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=zdZGYeuSC5JrONyWrYYic/IjPyZex+9izePqRJumt/Q=;
        b=djUTIF9Iffc9NjHtRCfMgHa+7wm3xzN36k4h/5Amhe5Tc/aRvYCg4IIOo7J7E/1Jsv
         oVmFvWXF/vlVusyiMmJ07yZ52/TZ4dJC39mIKFwKhFBJoREkIEXOo7diIfM+0qPf/yRa
         M++9NFbg+WtaaYmdiiFsmzQzqDXH1d2POF6YlD+ZeAhPiDooaiRWsrgeb2aqHyff7oet
         9I/431y2H28bGC/Aweva+geg7HKFRRyID1qhzKXIr5xATPd6QFCAgFjfvAuaMsdfosvB
         nwFXgQU5wDuWBsjKolM8I3vQ67KeJ4lEim8iJelbvffbUcLnqTa1AIdL2iKj27nfQDG7
         XVgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Yhk/1XEH";
       spf=pass (google.com: domain of srs0=zvoe=4p=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZvoE=4P=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zdZGYeuSC5JrONyWrYYic/IjPyZex+9izePqRJumt/Q=;
        b=mSDo8LpJPKyMWX61dDt6AJkLZyF8DBEyeUEbHKoRZ+VmCv65ag5eDXjzNGNQ676XKV
         HDoFa1bcOlnfTPQUy4ZvI/A2F0Lbm/zymN2kK7VqNDLp6W/+41uQbg9IwMz1jfWfPy4H
         EKokOlQDqC+9h4MfwdfJzbO4qwPUe08C4qtAu7Jwj8GgbW2umUB3B8t4w5Y8ulhcynyp
         2TCEdSPIcsGQmmZj18OYUv6kKN0t8qgKCoXwZjDBi/6A646oaemUcrtJrxmUxffA3hNP
         /zjgx0ENVh/viLsXUCOsBhYK16qBuAOxUn5uzC0v++W+iWq9PjvpLJd6lRasc0if/T6y
         QMJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zdZGYeuSC5JrONyWrYYic/IjPyZex+9izePqRJumt/Q=;
        b=DvmMLFxWsmrbdEE0OBqGSOzrC3CpRJ3099Q3vo/nMg5ks/upNGbZ1gF6b+SdrHGIAJ
         mxKgZZ811zAaHoqbry6byYSxAf/fnr47AUDnDTjiYQNwEPMpJLh6fHNb9IXMSbCEuQmr
         0/C2SgaE4EJiAIC5IKhYvk9QFc/oqvyR2zSFQpOSgD1K4VzKuTqrz13hyTsulr5Jex9c
         EEeeozHe/EDrL1CBqiyWQJZJdjWN+59I+WMRTur3KfVNPlaABfdTo5BB3xWh7NGxAGnr
         8788tb2SqaZJo3M1BbwxuTYkgMaUbvVEF/Tjx168GXbM7MEmZKB/BFBZNsJzvic06TjB
         bm2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWnNPp/HmAavrr0PhFKwC1ywm/PxWlD/lrk6O1N1MUOIbc8Dblu
	9ephZ7wvmwMfYmW2U9c8oRw=
X-Google-Smtp-Source: APXvYqxUM9vW7ReLxPHpcpP5yUbrUkTVbV5SsrM7CUbXivFz8gobBRPPujy8CB5ooA4tfi/s0oyQqw==
X-Received: by 2002:a05:6e02:1014:: with SMTP id n20mr6649969ilj.172.1582815526369;
        Thu, 27 Feb 2020 06:58:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:6216:: with SMTP id f22ls622072iog.6.gmail; Thu, 27 Feb
 2020 06:58:46 -0800 (PST)
X-Received: by 2002:a5d:8f97:: with SMTP id l23mr1661613iol.158.1582815526009;
        Thu, 27 Feb 2020 06:58:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582815526; cv=none;
        d=google.com; s=arc-20160816;
        b=iIpZcyybn4A7uDJ0hxY+FwSE5ojzXbI+7jwr8RqmdFWk3mXeC9cHmJW1t+Fnb20+OZ
         0AX0jqUb11Ek6JldkosyEqeklSMTgo4Zw+pXLCjd/2IpaITgZgiK2q2O/GI+gbRAsRNE
         iD3lqJ2Wruth76LEULQq7DmnhKohJiM10YhTaJAtEoz6HjIZrD53VQt8VcigMNUGRv1b
         TuO9vcnyNNH92h7pZU55uvB1YO07LBrPUnfBq4lZk6ODGjOQZVO5FHTwoUQlMu6ALLoz
         LbRoJ/OOrXuzQSWSxQjL/3FmVB7maY76oXgRU9zT28YGWCbaXj1O6Rx6/TkZjWh9MHjY
         jLPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=CNv5Z2zD/KO7fFterpIfmykLfXeuaWhKq0c3uc5+M6w=;
        b=Ji8AnTlbY+TIoXe7UmwjNQoCn9TgGqw3qr/XtkxVe5ZAwN98VEtvPzriQlclT3RXgC
         8asqKWQBg93dNfcmZ1FHc0eWPKxIZeR/QJmMMvxR2+6mRerrKNfXYqbWlPavXkmIRdwk
         3FvK/ne2WknkIAKspGcFX3gC1EZztEqcSTTvEkQWprBX4h4VYqG9VjkyO0ZKEG6lL9CC
         bdh0tpMc8uAhdBm/XXNKH8vLhclVgwK9FQmsFvLp8k0tFDR0yXnO6yCWCWl1cPIVAASZ
         BJ7a7wtS6trjSCg8Evqpdi+JISrbmivClxp0YKxbGsJYtgOc9TcdTd6Nfg7MKij5Y44U
         pPvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Yhk/1XEH";
       spf=pass (google.com: domain of srs0=zvoe=4p=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZvoE=4P=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k9si299197ili.4.2020.02.27.06.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Feb 2020 06:58:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zvoe=4p=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (199-192-87-166.static.wiline.com [199.192.87.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 470CD2468A;
	Thu, 27 Feb 2020 14:58:45 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id E5FF53521A4D; Thu, 27 Feb 2020 06:58:44 -0800 (PST)
Date: Thu, 27 Feb 2020 06:58:44 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Add current->state to implicitly atomic accesses
Message-ID: <20200227145844.GH2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200225143258.97949-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200225143258.97949-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="Yhk/1XEH";       spf=pass
 (google.com: domain of srs0=zvoe=4p=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZvoE=4P=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Feb 25, 2020 at 03:32:58PM +0100, Marco Elver wrote:
> Add volatile current->state to list of implicitly atomic accesses. This
> is in preparation to eventually enable KCSAN on kernel/sched (which
> currently still has KCSAN_SANITIZE := n).
> 
> Since accesses that match the special check in atomic.h are rare, it
> makes more sense to move this check to the slow-path, avoiding the
> additional compare in the fast-path. With the microbenchmark, a speedup
> of ~6% is measured.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued for review and testing, thank you!

							Thanx, Paul

> ---
> 
> Example data race that was reported with KCSAN enabled on kernel/sched:
> 
> write to 0xffff9e42c4400050 of 8 bytes by task 311 on cpu 7:
>  ttwu_do_wakeup.isra.0+0x48/0x1f0 kernel/sched/core.c:2222
>  ttwu_remote kernel/sched/core.c:2286 [inline]
>  try_to_wake_up+0x9f8/0xbe0 kernel/sched/core.c:2585
>  wake_up_process+0x1e/0x30 kernel/sched/core.c:2669
>  __up.isra.0+0xb5/0xe0 kernel/locking/semaphore.c:261
>  ...
> 
> read to 0xffff9e42c4400050 of 8 bytes by task 310 on cpu 0:
>  sched_submit_work kernel/sched/core.c:4109 [inline]  <--- current->state read
>  schedule+0x3a/0x1a0 kernel/sched/core.c:4153
>  schedule_timeout+0x202/0x250 kernel/time/timer.c:1872
>  ...
> ---
>  kernel/kcsan/atomic.h  | 21 +++++++--------------
>  kernel/kcsan/core.c    | 22 +++++++++++++++-------
>  kernel/kcsan/debugfs.c | 27 ++++++++++++++++++---------
>  3 files changed, 40 insertions(+), 30 deletions(-)
> 
> diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> index a9c1930534914..be9e625227f3b 100644
> --- a/kernel/kcsan/atomic.h
> +++ b/kernel/kcsan/atomic.h
> @@ -4,24 +4,17 @@
>  #define _KERNEL_KCSAN_ATOMIC_H
>  
>  #include <linux/jiffies.h>
> +#include <linux/sched.h>
>  
>  /*
> - * Helper that returns true if access to @ptr should be considered an atomic
> - * access, even though it is not explicitly atomic.
> - *
> - * List all volatile globals that have been observed in races, to suppress
> - * data race reports between accesses to these variables.
> - *
> - * For now, we assume that volatile accesses of globals are as strong as atomic
> - * accesses (READ_ONCE, WRITE_ONCE cast to volatile). The situation is still not
> - * entirely clear, as on some architectures (Alpha) READ_ONCE/WRITE_ONCE do more
> - * than cast to volatile. Eventually, we hope to be able to remove this
> - * function.
> + * Special rules for certain memory where concurrent conflicting accesses are
> + * common, however, the current convention is to not mark them; returns true if
> + * access to @ptr should be considered atomic. Called from slow-path.
>   */
> -static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
> +static bool kcsan_is_atomic_special(const volatile void *ptr)
>  {
> -	/* only jiffies for now */
> -	return ptr == &jiffies;
> +	/* volatile globals that have been observed in data races. */
> +	return ptr == &jiffies || ptr == &current->state;
>  }
>  
>  #endif /* _KERNEL_KCSAN_ATOMIC_H */
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 065615df88eaa..eb30ecdc8c009 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -188,12 +188,13 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
>  	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
>  }
>  
> +/* Rules for generic atomic accesses. Called from fast-path. */
>  static __always_inline bool
>  is_atomic(const volatile void *ptr, size_t size, int type)
>  {
>  	struct kcsan_ctx *ctx;
>  
> -	if ((type & KCSAN_ACCESS_ATOMIC) != 0)
> +	if (type & KCSAN_ACCESS_ATOMIC)
>  		return true;
>  
>  	/*
> @@ -201,16 +202,16 @@ is_atomic(const volatile void *ptr, size_t size, int type)
>  	 * as atomic. This allows using them also in atomic regions, such as
>  	 * seqlocks, without implicitly changing their semantics.
>  	 */
> -	if ((type & KCSAN_ACCESS_ASSERT) != 0)
> +	if (type & KCSAN_ACCESS_ASSERT)
>  		return false;
>  
>  	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
> -	    (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long) &&
> +	    (type & KCSAN_ACCESS_WRITE) && size <= sizeof(long) &&
>  	    IS_ALIGNED((unsigned long)ptr, size))
>  		return true; /* Assume aligned writes up to word size are atomic. */
>  
>  	ctx = get_ctx();
> -	if (unlikely(ctx->atomic_next > 0)) {
> +	if (ctx->atomic_next > 0) {
>  		/*
>  		 * Because we do not have separate contexts for nested
>  		 * interrupts, in case atomic_next is set, we simply assume that
> @@ -224,10 +225,8 @@ is_atomic(const volatile void *ptr, size_t size, int type)
>  			--ctx->atomic_next; /* in task, or outer interrupt */
>  		return true;
>  	}
> -	if (unlikely(ctx->atomic_nest_count > 0 || ctx->in_flat_atomic))
> -		return true;
>  
> -	return kcsan_is_atomic(ptr);
> +	return ctx->atomic_nest_count > 0 || ctx->in_flat_atomic;
>  }
>  
>  static __always_inline bool
> @@ -367,6 +366,15 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>  	if (!kcsan_is_enabled())
>  		goto out;
>  
> +	/*
> +	 * Special atomic rules: unlikely to be true, so we check them here in
> +	 * the slow-path, and not in the fast-path in is_atomic(). Call after
> +	 * kcsan_is_enabled(), as we may access memory that is not yet
> +	 * initialized during early boot.
> +	 */
> +	if (!is_assert && kcsan_is_atomic_special(ptr))
> +		goto out;
> +
>  	if (!check_encodable((unsigned long)ptr, size)) {
>  		kcsan_counter_inc(KCSAN_COUNTER_UNENCODABLE_ACCESSES);
>  		goto out;
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index 2ff1961239778..72ee188ebc54a 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -74,25 +74,34 @@ void kcsan_counter_dec(enum kcsan_counter_id id)
>   */
>  static noinline void microbenchmark(unsigned long iters)
>  {
> +	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
> +	const bool was_enabled = READ_ONCE(kcsan_enabled);
>  	cycles_t cycles;
>  
> +	/* We may have been called from an atomic region; reset context. */
> +	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
> +	/*
> +	 * Disable to benchmark fast-path for all accesses, and (expected
> +	 * negligible) call into slow-path, but never set up watchpoints.
> +	 */
> +	WRITE_ONCE(kcsan_enabled, false);
> +
>  	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
>  
>  	cycles = get_cycles();
>  	while (iters--) {
> -		/*
> -		 * We can run this benchmark from multiple tasks; this address
> -		 * calculation increases likelyhood of some accesses
> -		 * overlapping. Make the access type an atomic read, to never
> -		 * set up watchpoints and test the fast-path only.
> -		 */
> -		unsigned long addr =
> -			iters % (CONFIG_KCSAN_NUM_WATCHPOINTS * PAGE_SIZE);
> -		__kcsan_check_access((void *)addr, sizeof(long), KCSAN_ACCESS_ATOMIC);
> +		unsigned long addr = iters & ((PAGE_SIZE << 8) - 1);
> +		int type = !(iters & 0x7f) ? KCSAN_ACCESS_ATOMIC :
> +				(!(iters & 0xf) ? KCSAN_ACCESS_WRITE : 0);
> +		__kcsan_check_access((void *)addr, sizeof(long), type);
>  	}
>  	cycles = get_cycles() - cycles;
>  
>  	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
> +
> +	WRITE_ONCE(kcsan_enabled, was_enabled);
> +	/* restore context */
> +	current->kcsan_ctx = ctx_save;
>  }
>  
>  /*
> -- 
> 2.25.0.265.gbab2e86ba0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227145844.GH2935%40paulmck-ThinkPad-P72.
