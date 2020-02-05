Return-Path: <kasan-dev+bncBAABBD7J5TYQKGQEJLKCKEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id CA17A153A43
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2020 22:33:04 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id o18sf2311283qtt.19
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2020 13:33:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580938384; cv=pass;
        d=google.com; s=arc-20160816;
        b=L4xBqrWViYxvH40PvDQWDvdgTQGsqXTC2N+fuBru3xUNA0IeviCsANn0pDeX71HruW
         3MX6vZDVSaj6nHTGk+IHjM9y4qqaD3rIkPvIELPlOm/7oBUG5PSnyVnsqEAdb9irM4Rt
         f1UCfYaFZvHR1LanbszVNkdks+Bwoh8vzyO83ix8a0PxiSTdIbFB/4RWREEjGr2AstAr
         jbw3HyPJK0gfWnQb23FDdOmbDGjfneDfraOMWVIPsA70sUCCETk0ENATTVYXcQm6kfOV
         Z2YSftGVcZ8PlRMlJ8n05VPZuK++PTaRQbDHWgECC+XCm5ABHrq2jlZ3rjHOUlqogGLv
         hQHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=4/PSxyJfrxHKH1F2EI+n1tQJR+p1p/ykeI1rGfDPhSw=;
        b=QZXgPyhB6ITt4PH2PFj96RVinJhmIQn+HFavWe02kTvr1FSCCbFwRIDjRrNLgrm8w9
         6xLLd2YrxqTL8Y431irhZRkdi2TLI1isHojjgou8hnAubN54TzLQjXAYWRp50fnAf3IY
         /tPv5oGD6gZdZq/XKPTED1opPKfosCz0qIZE8ixEwLlzJ5n0t/GLZUdIEBVv9s57Qn7+
         EgUbIpkCZPMNihsWB8IpX1OIh5LbiJ9tcuk55+dBUsqGsOv53ps1lCxNtLwBKIJmMRPs
         MgJbFTklA1P/e/nv59kZsRoCl9zF6xke9QCAhd3yeQbAUkg4zzVp1Lie+99Ph+D6uswy
         Gm9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="ih/4cfO0";
       spf=pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4/PSxyJfrxHKH1F2EI+n1tQJR+p1p/ykeI1rGfDPhSw=;
        b=RJz8ttyAI7KutFreqkZwEEASVTTrRLhNHQooQUKhQIUOJ5xY4pHHWvEczA0cSYRjnE
         hSIG+r4oNnbq8LA/7MG1QpWw38yjZ+gLcHgLAjizG+k+gYTFR+BtzEcDAoPL+LbWPbTO
         3B1GezR4ptBQmugX0RQdqlQmojJlDqSh+mecPU6bNtdd/oElyp8ow15YGLYLQ988UF95
         2+EYxu0rnR1ikBHH8XYgru6DSbVxpRc9e97gBkf0/0She4lwCwsPm8CGCD/okAqhMWnz
         p6z1rQnPYW4HzTgbez8nBLYULJYaG41ALxeiqMiaj0ewZLFO0DYseSLf3hNvfglJ8UIo
         B8bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4/PSxyJfrxHKH1F2EI+n1tQJR+p1p/ykeI1rGfDPhSw=;
        b=qIu9+l3aEVSOfvS2xcXz2g5GTvX5XJ31KZ4FdJd64qvUdZdw/ubWbymyYF+aYu4EmK
         Oq0om5oMhqUV1QFLAG9BYwANuvD9uZIDfRGG5l33+g47NCbQJFz061ThsdqKqTwBraO4
         Ya28aA7T4a3K7Lorh6AOPUN2nZzs6Oz7J2DxQSAR1IiCux9b+kXXRHWqIe1gPnNcP1Es
         AQfFZeyh90R3JhIj8Nl52xC8q85wofoXtvjkAbCc2inWurxAFukvsMdGheSR6Y1a2QTP
         oQzLC/UPYv/PDz69xsnINTHab5ILVbG3HBiTjnAT2vUYY1aaFFlRJYZkDrNqv8QvKztr
         RKxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXhhkOFHLLTT9fCmHEUGAmh7vOwe6SklhGYi1Dw7VUrNgK0kgsX
	vAKoXw7Jg5dmluhF2OWZRwA=
X-Google-Smtp-Source: APXvYqxAYufMj5LKn4W1EfM//8Mj1spuDIjwZIJIVVXsQLXYhfZcAmnuDhlsFLVRAqBWk5N0QUc1BA==
X-Received: by 2002:a0c:e1ce:: with SMTP id v14mr33346791qvl.39.1580938383857;
        Wed, 05 Feb 2020 13:33:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:528f:: with SMTP id s15ls1337382qtn.1.gmail; Wed, 05 Feb
 2020 13:33:03 -0800 (PST)
X-Received: by 2002:ac8:584:: with SMTP id a4mr35464519qth.240.1580938383523;
        Wed, 05 Feb 2020 13:33:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580938383; cv=none;
        d=google.com; s=arc-20160816;
        b=H+p47VKOgHqsSbCfDXdAbTU4B+uKiIuG/xuq7qEljC3GSXqd/6c6cLJCtxKS9X3zXW
         bzvH18ZthlGDIGoJS51EYfL3KqugPaXRO8IkK/lfWfP9CdbhMcr+mVMWzxlriHvYjWWM
         ObFDtA0zfgDkJqlbx9LKhzwWDrZikxDWincwjcA/j0EO9PuMgZ0QJs37KraHpJ7hQIFg
         mfA3/kDEk0xKaCPpAJ6dhJ/FG/pqLHyW9509JqXXZu3ECabBIEmQCRweVMd1ESZV4ZOA
         o7K0+cJ5F4fs88fNo0wPu4/QfAhwOFamjOZafV6zsP/kQSzSLCWZy51QRWL5jdIy1KTM
         3zaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=OHZoR+ph4dZNbJBa9c8LlIKkVekP5FMNDSknB3OYf3c=;
        b=odGb3Oi5f9Npk8JWYlrJgAMlh8Szb1W1CYxiE6qdZs/2hyLRWLVxnlBuV+aIoh0u5W
         V9RjRA3CcOvl1BwlzM1zHolZUEbrKC5rTG9lOs3yjXTgIKbkKu2EUgjzpkYgDire/R7j
         VgjB20h2c6OEMSpZAVnchZn8g1pvphifRvHn7BHBys8BIUuu/OLCv7yrK6pSdOfhlnKA
         CXrWfGedDPNNDGanppcMJiYcCtAlWJDl0H0s1Xfax0smbeD2hCNn0vIOgjykZVd2hNb4
         O266N20Y2sw8BaFV1Q1dUlHr//+Sgu7mYDL8/6aoAPQl0doTClZwuT6Homli81SSvhTs
         QAhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="ih/4cfO0";
       spf=pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c19si55779qtk.5.2020.02.05.13.33.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Feb 2020 13:33:03 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 901602072B;
	Wed,  5 Feb 2020 21:33:02 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 64BDC35227EB; Wed,  5 Feb 2020 13:33:02 -0800 (PST)
Date: Wed, 5 Feb 2020 13:33:02 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/3] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
Message-ID: <20200205213302.GA2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200205204333.30953-1-elver@google.com>
 <20200205204333.30953-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200205204333.30953-2-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="ih/4cfO0";       spf=pass
 (google.com: domain of srs0=vsdd=3z=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VSDD=3Z=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Feb 05, 2020 at 09:43:32PM +0100, Marco Elver wrote:
> Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
> may be used to assert properties of synchronization logic, where
> violation cannot be detected as a normal data race.
> 
> Examples of the reports that may be generated:
> 
>     ==================================================================
>     BUG: KCSAN: data-race in test_thread / test_thread
> 
>     write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
>      test_thread+0x8d/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
> 
>     assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
>      test_thread+0xa3/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
>     ==================================================================
> 
>     ==================================================================
>     BUG: KCSAN: data-race in test_thread / test_thread
> 
>     assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
>      test_thread+0xb9/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
> 
>     read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
>      test_thread+0x77/0x111
>      debugfs_write.cold+0x32/0x44
>      ...
>     ==================================================================
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Suggested-by: Paul E. McKenney <paulmck@kernel.org>
> ---
> 
> Please let me know if the names make sense, given they do not include a
> KCSAN_ prefix.

I am OK with this, but there might well be some bikeshedding later on.
Which should not be a real problem, irritating though it might be.

> The names are unique across the kernel. I wouldn't expect another macro
> with the same name but different semantics to pop up any time soon. If
> there is a dual use to these macros (e.g. another tool that could hook
> into it), we could also move it elsewhere (include/linux/compiler.h?).
> 
> We can also revisit the original suggestion of WRITE_ONCE_EXCLUSIVE(),
> if it is something that'd be used very widely. It'd be straightforward
> to add with the help of these macros, but would need to be added to
> include/linux/compiler.h.

A more definite use case for ASSERT_EXCLUSIVE_ACCESS() is a
reference-counting algorithm where exclusive access is expected after
a successful atomic_dec_and_test().  Any objection to making the
docbook header use that example?  I believe that a more familiar
example would help people see the point of all this.  ;-)

I am queueing these as-is for review and testing, but please feel free
to send updated versions.  Easy to do the replacement!

And you knew that this was coming...  It looks to me that I can
do something like this:

	struct foo {
		int a;
		char b;
		long c;
		atomic_t refctr;
	};

	void do_a_foo(struct foo *fp)
	{
		if (atomic_dec_and_test(&fp->refctr)) {
			ASSERT_EXCLUSIVE_ACCESS(*fp);
			safely_dispose_of(fp);
		}
	}

Does that work, or is it necessary to assert for each field separately?

							Thanx, Paul

> ---
>  include/linux/kcsan-checks.h | 34 ++++++++++++++++++++++++++++++++++
>  1 file changed, 34 insertions(+)
> 
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 21b1d1f214ad5..1a7b51e516335 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -96,4 +96,38 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
>  	kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
>  #endif
>  
> +/**
> + * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
> + *
> + * Assert that there are no other threads writing @var; other readers are
> + * allowed. This assertion can be used to specify properties of synchronization
> + * logic, where violation cannot be detected as a normal data race.
> + *
> + * For example, if a per-CPU variable is only meant to be written by a single
> + * CPU, but may be read from other CPUs; in this case, reads and writes must be
> + * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
> + * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
> + * race condition. Using this macro allows specifying this property in the code
> + * and catch such bugs.
> + *
> + * @var variable to assert on
> + */
> +#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
> +	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
> +
> +/**
> + * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
> + *
> + * Assert that no other thread is accessing @var (no readers nor writers). This
> + * assertion can be used to specify properties of synchronization logic, where
> + * violation cannot be detected as a normal data race.
> + *
> + * For example, if a variable is not read nor written by the current thread, nor
> + * should it be touched by any other threads during the current execution phase.
> + *
> + * @var variable to assert on
> + */
> +#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
> +	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
> +
>  #endif /* _LINUX_KCSAN_CHECKS_H */
> -- 
> 2.25.0.341.g760bfbb309-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200205213302.GA2935%40paulmck-ThinkPad-P72.
