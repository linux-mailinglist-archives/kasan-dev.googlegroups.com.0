Return-Path: <kasan-dev+bncBAABBZ7J43YQKGQEAGMWTOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2534F152047
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 19:16:09 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id w205sf8075646oie.13
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 10:16:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580840168; cv=pass;
        d=google.com; s=arc-20160816;
        b=1DY9Uf4ADZKb1PZamkZKXoEqsehigl6OdVgMHjUj9xCRUmEA3RKMoteHbIlDDDOzGq
         nHbhcJgB3XIOUM4FwYxRaHa3E7iHNTilBVUsBzfagkq7WVJJ9SODc0+hCEZ2C98Kq+fp
         NRk1wkDLf+JgWe3JI+OqLlLiMOO+HhWAaLdxsabGyJ5jA8wKQG5jC5kI4RoVK6tOPdhe
         X/a0NCO+3yE94+yZoM55pr3+HNpxeEt++N4fHHsBBUBPkOkdQBYW1aO5DBafKWuzay+2
         i2ijuDf0lpSUyVLIcgYzCwulDzQsfTj/9pcgAZaf2mMM7LQjcKxk9tO+gFExhTbSWJ8U
         uGvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=t3wVQ521ezGH1UCQXWI6wfqciGlDN82vUwaJU6X4S4I=;
        b=qint3Nadjf8Qe/wfW4lAjRXqUAbhQ7D3tmRo87UVrA/+IEskG83HDjcWhLhByly7lR
         oONPoEb2MedZXa4BN9bFn1wDMoK6QEmrs37ViF3ggBCFTv32SLvM1Hv/lYSDlPSnc0On
         OvWi7bjGa9McoYgz8U4RiE06oy7+TdE1iMhXWDoLwdM6SfrXk1Xn636tB/vzlJOFD+d1
         4zsYwxvFWS4Qw2uYwFQm/Z+NcXg7ccYoaBZZiPUaiAuTagXiEDJgcnoTCMflWFy9C1Ih
         QyvYlPExwFW5H7ruRQvp7HCsr0uZPCqHV5C0jMIYT2n96MeqVohS95EO3QwndNnlDjM9
         GRxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rHKlYUGs;
       spf=pass (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2yFN=3Y=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t3wVQ521ezGH1UCQXWI6wfqciGlDN82vUwaJU6X4S4I=;
        b=h5gNFFWCmt20udZUKxQVHRRx89z4Jfqp9838Z39l94H/u40ZZ+MVOBI4pfWqsqFk5t
         xykIc7ZWi/d77JFimrmxTYoJgIZATK9vBRvBf4jfYCnX6/BetK3dLrxeX8ZgU/IVUQfC
         FTd85GXHOwTX7TE2DhadyilMWdBZ2y0fSzAORNfylLPassw/e/pNRqa3Pjd2uLALjdtL
         G6ChzzeZlmUBa3QI08OUFmHSCzSy1X+tmcZEAVpokjFkXT7v8cBzym8HSWgCAh3n12PJ
         oC8gNBD/BC7j9BB4f3riCWNVSEJXaz++fu6ZkkVJWs/t46I09e90tNQ/o0Dxl31401We
         5ghw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=t3wVQ521ezGH1UCQXWI6wfqciGlDN82vUwaJU6X4S4I=;
        b=W+jzm4DjalM9lxLq7Si1lWJafFUG+Bkclea5DWEpjNKrJ3V1go+qz5IfuM63Q+HjuH
         rT/Ec/wUQjsEtg60P/4wTJ1Bm8LRTrsLthfeTmn9z2R+TmV5xXIG6P1Vy3PpQJ6t7Ntc
         7z+3Xmh2Nz1bFfVw4+BbuvJJR4q4x8cYOZlJ7qwKPvF6uQIUpauGjq4cueGe1LHgfXE2
         lri3XHifOazL3UuVoP2UbrApNA7Q1lKmb95JZsZqnr5x6dpCPD56SLtrkoJbQ8T8eAVc
         Yznh+Uo6STItptSLsqvFkWHkm6tS7KL9rG8noxwtQ8s77FbFHXojGoHnq3xrKIY81Tgc
         Kiwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV3pMFCs0C63lt5GLLeAW0JOX5jFPhzDyZQKpqOH+DGdZ0UJ0Am
	4W8kAmfyRLbWWeS02AEk0co=
X-Google-Smtp-Source: APXvYqwpZOelkqyv0D207rdetmBZLuY9X5zczqR8ZP0ZEGuL0Bfu0Za8BsL3l5sIxKfbF+vxk2NWrA==
X-Received: by 2002:a05:6808:5d0:: with SMTP id d16mr205969oij.45.1580840167695;
        Tue, 04 Feb 2020 10:16:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7999:: with SMTP id h25ls1055514otm.2.gmail; Tue, 04 Feb
 2020 10:16:07 -0800 (PST)
X-Received: by 2002:a05:6830:10d5:: with SMTP id z21mr24344229oto.30.1580840167299;
        Tue, 04 Feb 2020 10:16:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580840167; cv=none;
        d=google.com; s=arc-20160816;
        b=f7j05cIqUMNv41WintM3mvYlfZ8O0MPidheLWubAIF+sWo6d8xt+pnrU5Hnkyt2Eyd
         m+Va6WKU7FMg817cxAHoDZtaaS69b6MqPbsrmTn4oshfovEI/Q65Uum91JA+ISia38wE
         3RX2y+zizZ45o5fRxTKJtf14d5w3eBeHdyw6PNOwUqA1ueADa4aLHgQMZfbksRfbeWgO
         9dQEUBW+H556iP1IFMJQfLN3zQLHFo9V0SmSZL/iYvJ+BQez+zzrVZuN9nJ2a6uj73OD
         PkdjeZhoeZm6wV96oUf7v2w30cDA9Mzp9KiWOE0c2IoNb9B8M2yP3XqN7t6uSNeY1enR
         +e1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=hyk1bBMM2H6m5GU61ItADyY7/+fE6E+0N+HbLG16WRg=;
        b=GNMdHt1S6l/DsE933ekwNNnq7xo7qfYt6MA/yn1rxkg/zWEF3RRovDtVHJe4pl1rif
         rjmq5W+Vlw7y9y0DiibNZ58vgSLcxNEmTUV8ZF/SvqTvNbexmLeUO1uujSdyhy+tNfDh
         znFE2Q9yjH6Q+GsR0S+gaebA3pNOl2HRqrGC4PwyaLChtCoIZsIsgLePQ4Jj2Q4/6LJn
         8kf7xjUm0A8S6Qq1qhpa1vGLbpEsSyfiygblcNLvmdYvTZEsy66N6AWX+hpMSigAmEFu
         KvBnJG2mVsWYOYMDDYBchGYovcIxcYIicUgX2V88/86GS5/LvktuEXMjBTubSxl/EBe0
         HoDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rHKlYUGs;
       spf=pass (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2yFN=3Y=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a17si1079921otr.1.2020.02.04.10.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Feb 2020 10:16:07 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 438C62082E;
	Tue,  4 Feb 2020 18:16:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 1D5CF352270F; Tue,  4 Feb 2020 10:16:05 -0800 (PST)
Date: Tue, 4 Feb 2020 10:16:05 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 1/3] kcsan: Add option to assume plain aligned writes
 up to word size are atomic
Message-ID: <20200204181605.GS2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200204172112.234455-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200204172112.234455-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=rHKlYUGs;       spf=pass
 (google.com: domain of srs0=2yfn=3y=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=2yFN=3Y=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Feb 04, 2020 at 06:21:10PM +0100, Marco Elver wrote:
> This adds option KCSAN_ASSUME_PLAIN_WRITES_ATOMIC. If enabled, plain
> aligned writes up to word size are assumed to be atomic, and also not
> subject to other unsafe compiler optimizations resulting in data races.
> 
> This option has been enabled by default to reflect current kernel-wide
> preferences.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued all three for further testing and review, thank you!

						Thanx, Paul

> ---
> v2:
> * Also check for alignment of writes.
> ---
>  kernel/kcsan/core.c | 22 +++++++++++++++++-----
>  lib/Kconfig.kcsan   | 27 ++++++++++++++++++++-------
>  2 files changed, 37 insertions(+), 12 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 64b30f7716a12..e3c7d8f34f2ff 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -5,6 +5,7 @@
>  #include <linux/delay.h>
>  #include <linux/export.h>
>  #include <linux/init.h>
> +#include <linux/kernel.h>
>  #include <linux/percpu.h>
>  #include <linux/preempt.h>
>  #include <linux/random.h>
> @@ -169,10 +170,20 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
>  	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
>  }
>  
> -static __always_inline bool is_atomic(const volatile void *ptr)
> +static __always_inline bool
> +is_atomic(const volatile void *ptr, size_t size, int type)
>  {
> -	struct kcsan_ctx *ctx = get_ctx();
> +	struct kcsan_ctx *ctx;
> +
> +	if ((type & KCSAN_ACCESS_ATOMIC) != 0)
> +		return true;
>  
> +	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
> +	    (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long) &&
> +	    IS_ALIGNED((unsigned long)ptr, size))
> +		return true; /* Assume aligned writes up to word size are atomic. */
> +
> +	ctx = get_ctx();
>  	if (unlikely(ctx->atomic_next > 0)) {
>  		/*
>  		 * Because we do not have separate contexts for nested
> @@ -193,7 +204,8 @@ static __always_inline bool is_atomic(const volatile void *ptr)
>  	return kcsan_is_atomic(ptr);
>  }
>  
> -static __always_inline bool should_watch(const volatile void *ptr, int type)
> +static __always_inline bool
> +should_watch(const volatile void *ptr, size_t size, int type)
>  {
>  	/*
>  	 * Never set up watchpoints when memory operations are atomic.
> @@ -202,7 +214,7 @@ static __always_inline bool should_watch(const volatile void *ptr, int type)
>  	 * should not count towards skipped instructions, and (2) to actually
>  	 * decrement kcsan_atomic_next for consecutive instruction stream.
>  	 */
> -	if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
> +	if (is_atomic(ptr, size, type))
>  		return false;
>  
>  	if (this_cpu_dec_return(kcsan_skip) >= 0)
> @@ -460,7 +472,7 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
>  	if (unlikely(watchpoint != NULL))
>  		kcsan_found_watchpoint(ptr, size, type, watchpoint,
>  				       encoded_watchpoint);
> -	else if (unlikely(should_watch(ptr, type)))
> +	else if (unlikely(should_watch(ptr, size, type)))
>  		kcsan_setup_watchpoint(ptr, size, type);
>  }
>  
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 3552990abcfe5..66126853dab02 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -91,13 +91,13 @@ config KCSAN_REPORT_ONCE_IN_MS
>  	  limiting reporting to avoid flooding the console with reports.
>  	  Setting this to 0 disables rate limiting.
>  
> -# Note that, while some of the below options could be turned into boot
> -# parameters, to optimize for the common use-case, we avoid this because: (a)
> -# it would impact performance (and we want to avoid static branch for all
> -# {READ,WRITE}_ONCE, atomic_*, bitops, etc.), and (b) complicate the design
> -# without real benefit. The main purpose of the below options is for use in
> -# fuzzer configs to control reported data races, and they are not expected
> -# to be switched frequently by a user.
> +# The main purpose of the below options is to control reported data races (e.g.
> +# in fuzzer configs), and are not expected to be switched frequently by other
> +# users. We could turn some of them into boot parameters, but given they should
> +# not be switched normally, let's keep them here to simplify configuration.
> +#
> +# The defaults below are chosen to be very conservative, and may miss certain
> +# bugs.
>  
>  config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
>  	bool "Report races of unknown origin"
> @@ -116,6 +116,19 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
>  	  the data value of the memory location was observed to remain
>  	  unchanged, do not report the data race.
>  
> +config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
> +	bool "Assume that plain aligned writes up to word size are atomic"
> +	default y
> +	help
> +	  Assume that plain aligned writes up to word size are atomic by
> +	  default, and also not subject to other unsafe compiler optimizations
> +	  resulting in data races. This will cause KCSAN to not report data
> +	  races due to conflicts where the only plain accesses are aligned
> +	  writes up to word size: conflicts between marked reads and plain
> +	  aligned writes up to word size will not be reported as data races;
> +	  notice that data races between two conflicting plain aligned writes
> +	  will also not be reported.
> +
>  config KCSAN_IGNORE_ATOMICS
>  	bool "Do not instrument marked atomic accesses"
>  	help
> -- 
> 2.25.0.341.g760bfbb309-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204181605.GS2935%40paulmck-ThinkPad-P72.
