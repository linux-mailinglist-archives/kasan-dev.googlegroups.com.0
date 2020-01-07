Return-Path: <kasan-dev+bncBAABBUHM2PYAKGQEYZBQE6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8A281333B9
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jan 2020 22:21:21 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id m18sf551862otp.20
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2020 13:21:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578432080; cv=pass;
        d=google.com; s=arc-20160816;
        b=rzZuXjOszxKZTGKpsf0wIZfw5V6yN2yjmgznxCzXKwrdRF1t8/fq9Y6DZuo+kIg2Sb
         NMjPgvAK+nTyV1is4hse5noky0Nwkk014RdmWFflx/gGBi2DVNOfKhT3cGmtsIQYEVqC
         ebxFoU7Ud+BYLmCW7OEildkwdb1gKcDui/33DZkjvdwPidZ8Xq8j4eGOHSJ4A47YDytq
         ZmYUpmLv7t5gEhE2f6pXGOtl3+gCkPPuYMFvCmYMBxapOG+V3WavdRDkLwjR58EhdVno
         dYIuusGthbG1bLu8D04CB8YQQTkhznpjx3QIfyB0z8piF9/TjavLuW6dz/tsnRfnt6hP
         FvQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=QrgmovI1bFYVQBL2JFsJRr2zDcXD08Cvmz5Hzi8xxuQ=;
        b=R0kPhWpus9LxbogaOIep9XyuIKbVkqVK7wMVI8/z8ZcPSzGBhTBDj7xgQ/Y1t9TyBk
         EYhgQeQYDKpeoGTFNXMtK7vc/qOtGUPFf+1ZGloUbLUbEaw8jg8lR/NzSaP2XZxzdVTW
         QoQHQVXj5md3N18gIDd87+E9e964SSiYIrNP49Uo/CG/bHH2PJ4ERli42vebV9Osf1OW
         5+xguiLv7IiQJh9dhojTU/ncVpZJFIH/LkPwKZlyGZuqaPiHsdI/Urs/ytAbfk+3nSy9
         465ViMS1fz2XoscBELQFrgSYX4SrovZA7XTv4zoElI1dP2uo99D5pfkzySdqUzWWzQv2
         0kXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AuSCEO+O;
       spf=pass (google.com: domain of srs0=p4iy=24=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=p4iy=24=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QrgmovI1bFYVQBL2JFsJRr2zDcXD08Cvmz5Hzi8xxuQ=;
        b=i7nMQT8wgVC5uHmkwuT0lms3RQs0hLeLHJ5WKOVbGqIOdcqlTtRGQqb8MXtizpB+n2
         roaz1/SKQGVgRWSOOGTgX6VO0UlH7WcfoJv4gachbmUN0DEGMtIGf3T8gypWvcYkY2D3
         lPXfO/IFMdPqLW+qB2S2pNoB4ToZxzXjIYipjGn8NDf6KXdX/p6CZVlg+SRd+ggBN8Q8
         2OL5+igpcQMow9QEul/VvX/zg/rTZd57AUmghHeYTyEe4JwbbN5QIUZ4o5fKI33Dtt5j
         ZfKzj/sErJ0z7X+ILja8gNFNum6JfrkvJN0elieNEJ+yzHBW0HmH5WM3wINdqu7QAVs8
         VAoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QrgmovI1bFYVQBL2JFsJRr2zDcXD08Cvmz5Hzi8xxuQ=;
        b=gbXFwe+u/0+mZs1TAT6BP5DT57957ImZR+SR9UX9UqmLmdkbTyKdCOP/ICeued5t8h
         Wn/tRA47H6qlLrx2K+9Pc8c7ejVyLpDHTlaTV39eFCeqIIjFql0cx1kKMeDikZYQ/brV
         TxPouNzvXU1xbV0rcBfEhqfmxckeQQjHECwJpyPLJrcchjmkPtIV88JkHxlUAZBhDZHZ
         H1q826tGLYoke8+rprlP/v1eou509H6+qn+s0bEfBO2GWuCEgkEOSccCOtRfDFn1V6td
         txUpDjVgfg1dBi4HUpOUgA8Mao9V3l/TWf9iqTU3fbb73jkphadZkr5W/21gW0JtYlLX
         nqTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWm9t91d6LAFodcqd/e0pM5jKCuAvIpamlkh8H/x1GIkO84LgJB
	u7RNWZwukXvnr22OpV/8Xso=
X-Google-Smtp-Source: APXvYqzr1GwREOWdUfXkwXhieQAkhWY2Iu4CUMnmQ1NaOaT4w3ACfATtL8y+omTA4zZdRWDlOty3xQ==
X-Received: by 2002:a05:6830:2110:: with SMTP id i16mr1647739otc.337.1578432080694;
        Tue, 07 Jan 2020 13:21:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf95:: with SMTP id f143ls145908oig.7.gmail; Tue, 07 Jan
 2020 13:21:20 -0800 (PST)
X-Received: by 2002:aca:d787:: with SMTP id o129mr374866oig.75.1578432080381;
        Tue, 07 Jan 2020 13:21:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578432080; cv=none;
        d=google.com; s=arc-20160816;
        b=qz+heR238002ftpdA76p9bfYCVTWgW9xjbGFtTzeN6+QyXSZZs43w9K/vv5EIfcI7+
         aWkcgW/YW3Q0oKChh/wpnNaqj4ooJn4KmqI38uPl0aHsRHOOc1QZdSmZXwZpupsF8k7l
         mRILDUNGQteAfaFOEDmxvtQRnmXcGvVdBXPaKk+DfE+1oTrTPECX7WNq+Utb2x0ZbDqE
         h7Msr6t4i2H/rcEtljJfBcMqYcQlUQRvRYWT6VFo7r30mGj8pv6T3gjpBu+pxKn96d/p
         Q/FglBnBglap7T90zO++90KdnSSG+0lyRm4MsZ7RBYfo8uUQnEjTjfzkBvltrYl2uCWO
         Brow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=K4FuwATRH/9EAkZDbUiiFseo42cSudOB1u7L+ZjjyKg=;
        b=YjcaTBzA2CDV6iSIz1mxSfmSfZXIyDXP6dVcKnsclkgaXNMdSuT2Y/HqwDXYkxBCNu
         WHEl97BW1UYftoeb3IFQYrI2SCyna7kT3MMcKh/ITAy9U/umc9kTyIzwyTqKKbRHit0O
         Fk9Nz7tKmDtEmgBaIQ+IOXE9IJWXO4Ie7jBOmB84L21CrLs5jp/R84W6nHEnLhWy64sJ
         y5WCvfS4sjbETaaRpSXLT1ktit01pIkBWYs45QhE/z2zdirE4m9ixtH7dHMVg9lXzHRl
         XaIMzV3iXc8fGmi8lNB81l8sm90nxXSY1vef3csiq1d2rsivmqnbCR1wsHFAl3hGXFMW
         se+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=AuSCEO+O;
       spf=pass (google.com: domain of srs0=p4iy=24=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=p4iy=24=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e14si79010otr.1.2020.01.07.13.21.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 07 Jan 2020 13:21:20 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=p4iy=24=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 75C532081E;
	Tue,  7 Jan 2020 21:21:19 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 4E1673522735; Tue,  7 Jan 2020 13:21:19 -0800 (PST)
Date: Tue, 7 Jan 2020 13:21:19 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	dvyukov@google.com, Randy Dunlap <rdunlap@infradead.org>
Subject: Re: [PATCH RESEND -rcu] kcsan: Prefer __always_inline for fast-path
Message-ID: <20200107212119.GB13449@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200107163104.143542-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200107163104.143542-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=AuSCEO+O;       spf=pass
 (google.com: domain of srs0=p4iy=24=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=p4iy=24=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Jan 07, 2020 at 05:31:04PM +0100, Marco Elver wrote:
> Prefer __always_inline for fast-path functions that are called outside
> of user_access_save, to avoid generating UACCESS warnings when
> optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
> surprises with compiler versions that change the inlining heuristic even
> when optimizing for performance.
> 
> Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> Reported-by: Randy Dunlap <rdunlap@infradead.org>
> Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Rebased against -rcu/dev branch.

Queued and pushed, thank you, Marco!

							Thanx, Paul

> ---
>  kernel/kcsan/atomic.h   |  2 +-
>  kernel/kcsan/core.c     | 18 +++++++++---------
>  kernel/kcsan/encoding.h | 14 +++++++-------
>  3 files changed, 17 insertions(+), 17 deletions(-)
> 
> diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> index 576e03ddd6a3..a9c193053491 100644
> --- a/kernel/kcsan/atomic.h
> +++ b/kernel/kcsan/atomic.h
> @@ -18,7 +18,7 @@
>   * than cast to volatile. Eventually, we hope to be able to remove this
>   * function.
>   */
> -static inline bool kcsan_is_atomic(const volatile void *ptr)
> +static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
>  {
>  	/* only jiffies for now */
>  	return ptr == &jiffies;
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 3314fc29e236..4d4ab5c5dc53 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -78,10 +78,10 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
>   */
>  static DEFINE_PER_CPU(long, kcsan_skip);
>  
> -static inline atomic_long_t *find_watchpoint(unsigned long addr,
> -					     size_t size,
> -					     bool expect_write,
> -					     long *encoded_watchpoint)
> +static __always_inline atomic_long_t *find_watchpoint(unsigned long addr,
> +						      size_t size,
> +						      bool expect_write,
> +						      long *encoded_watchpoint)
>  {
>  	const int slot = watchpoint_slot(addr);
>  	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> @@ -146,7 +146,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
>   *	2. the thread that set up the watchpoint already removed it;
>   *	3. the watchpoint was removed and then re-used.
>   */
> -static inline bool
> +static __always_inline bool
>  try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
>  {
>  	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
> @@ -160,7 +160,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
>  	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
>  }
>  
> -static inline struct kcsan_ctx *get_ctx(void)
> +static __always_inline struct kcsan_ctx *get_ctx(void)
>  {
>  	/*
>  	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
> @@ -169,7 +169,7 @@ static inline struct kcsan_ctx *get_ctx(void)
>  	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
>  }
>  
> -static inline bool is_atomic(const volatile void *ptr)
> +static __always_inline bool is_atomic(const volatile void *ptr)
>  {
>  	struct kcsan_ctx *ctx = get_ctx();
>  
> @@ -193,7 +193,7 @@ static inline bool is_atomic(const volatile void *ptr)
>  	return kcsan_is_atomic(ptr);
>  }
>  
> -static inline bool should_watch(const volatile void *ptr, int type)
> +static __always_inline bool should_watch(const volatile void *ptr, int type)
>  {
>  	/*
>  	 * Never set up watchpoints when memory operations are atomic.
> @@ -226,7 +226,7 @@ static inline void reset_kcsan_skip(void)
>  	this_cpu_write(kcsan_skip, skip_count);
>  }
>  
> -static inline bool kcsan_is_enabled(void)
> +static __always_inline bool kcsan_is_enabled(void)
>  {
>  	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
>  }
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index b63890e86449..f03562aaf2eb 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
>  		      (addr & WATCHPOINT_ADDR_MASK));
>  }
>  
> -static inline bool decode_watchpoint(long watchpoint,
> -				     unsigned long *addr_masked,
> -				     size_t *size,
> -				     bool *is_write)
> +static __always_inline bool decode_watchpoint(long watchpoint,
> +					      unsigned long *addr_masked,
> +					      size_t *size,
> +					      bool *is_write)
>  {
>  	if (watchpoint == INVALID_WATCHPOINT ||
>  	    watchpoint == CONSUMED_WATCHPOINT)
> @@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
>  /*
>   * Return watchpoint slot for an address.
>   */
> -static inline int watchpoint_slot(unsigned long addr)
> +static __always_inline int watchpoint_slot(unsigned long addr)
>  {
>  	return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
>  }
>  
> -static inline bool matching_access(unsigned long addr1, size_t size1,
> -				   unsigned long addr2, size_t size2)
> +static __always_inline bool matching_access(unsigned long addr1, size_t size1,
> +					    unsigned long addr2, size_t size2)
>  {
>  	unsigned long end_range1 = addr1 + size1 - 1;
>  	unsigned long end_range2 = addr2 + size2 - 1;
> -- 
> 2.24.1.735.g03f4e72817-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200107212119.GB13449%40paulmck-ThinkPad-P72.
