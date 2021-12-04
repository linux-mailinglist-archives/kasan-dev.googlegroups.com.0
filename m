Return-Path: <kasan-dev+bncBCS4VDMYRUNBBZ4KV2GQMGQE5ZZ4ASY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AB464685DC
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Dec 2021 16:12:40 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id bx28-20020a0564020b5c00b003e7c42443dbsf4899552edb.15
        for <lists+kasan-dev@lfdr.de>; Sat, 04 Dec 2021 07:12:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638630760; cv=pass;
        d=google.com; s=arc-20160816;
        b=tOD4CqqhtN4A4t4GQSxHs2RIIkN/+JnZL6nrNqQidG4oFKpfwRB97lTZJF5SJUhF/G
         RGAbvoUjJ/YG3eCgDpI5nobjHCrjGBBIxNg1fgHXiWJ0fpEJ1kjHDRc8kCMuIgWIX0Sk
         tYgMsi/M291JhJ+Cu93VT2/CJqdnCAaEhj2BVoxQEkUMew97HgsfJap+rf2nB3kI4cBf
         adJorJrIcmIWXN/Cj5fipGx74lgC4o+YUHnEA06f2kHYFuM74V36VWvk31RaeykWYUMF
         /9Az1mIw7520SOOj1L0EyyWHYtcRKYT/MD7ZeAI8K2XJB9lMcmzm6ORAAhVdvrAZhgI4
         X14Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=59Oc972XmNKliZUHOXCqjPByNsT29t5hQBt2ZYmgO3Q=;
        b=Y+YTzl5e59E2Bl7ogWim2aIEUVcj+/mU4tSniRLOVM2V/yCD3o+xSuLYA00C/kN8OE
         0kWz18KwMoiSDB/X9dl+Qn6EIijulo7uOKI2Yzg4uy6gnIOG6jeTwOOaM/o6O5s35H8e
         hUr5yUsq6vHEUEGshyzmcaNQlcmf4d9w8WO55U6srGwQgkM4Izc0xCRFI16CNGv62dO+
         F7r84wu/Dvlb57FvZb3xoXST1e7TpbJ/GqNmsD8e40aEMVqWCaKRTCcJPNmBhH6rmE0c
         RURUGvRANl4TZHZb5HCrIeewQPO1APsPhlwi4B7IxU7ixXq1G8XKYXT3ehiS/K9V+Kc1
         f9rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z7v462ua;
       spf=pass (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WkCX=QV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=59Oc972XmNKliZUHOXCqjPByNsT29t5hQBt2ZYmgO3Q=;
        b=XFba+klu7sn6ZW/p+Vf9jXc97NtLuCYvL2Ms3hUaJ/61SueBS2nOtj4H+Z7MCNgB+Z
         QgvLn2kns9NnzbgN4NVkiXL8kjvkghG9DFYphmKZYPRFOvvFWNgp7E74iW5FgUJHwcXp
         G3GLtY8jJPFi/KkWv/AbJ1ZjuJ+TT/fNDD9bWdD4OMOG/xrXE3jd8O0SvZaOn+rF7jXu
         ru3HvXU/0vB4RinPyYxnvgYI3lIE6ldN6gyaoKA6MsH8pm7q7xSg8aWWUfVfX5f+n2Vn
         U1GMVTnVSjonAJ6eDZ44DhTQzGy4bxBlY8iJTLWG7i3RJHRDGo0eZLFAWvq29m7UpxrI
         cimw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=59Oc972XmNKliZUHOXCqjPByNsT29t5hQBt2ZYmgO3Q=;
        b=Uy+DNAErRKx8YrHKJF8zC4E4tC10wsLQZDHJm2PYQNsq2ffHy0sm3IWU78ro34hzjD
         hZUrejKiuEE8aX9PqZbHR35P6HnxeNeXGz90Er89lQ3lJDKqVX5vBNeulkCptU5C0F22
         UpIM6guV+ysuPnSSXQK1tD7o5pHU8b1lFZzQdIrSsXQbLel8kJUEtPUOSjO+9HGmYu31
         UmZTSsZgeOT9w7Li7YGSkU1hpMXuNWK7s69UIQXuvvREDwhSSMRoqGQEOlC1BjZeDqgs
         vAdnt/Ho8KxzyOPowu4zRyAThItpHuYvSZtucfDuwoGhrQDKXa2KUytYGmd5abPOvbI7
         fVRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fmE+ZP9BeBYH6SYCFdAdNUX8aziOraKDk3oKLW+2DqTS70Ibg
	CQG/fo957CkHsk2/fhlkonk=
X-Google-Smtp-Source: ABdhPJyLxPUa8AM0RmEdH+uL3BPYIVZrUQ8p2VqFsM69duP6+AeunlW31kC/8Ni36CPFHNhW3LQlqw==
X-Received: by 2002:a50:9eca:: with SMTP id a68mr36871850edf.127.1638630760194;
        Sat, 04 Dec 2021 07:12:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7e93:: with SMTP id qb19ls4690160ejc.4.gmail; Sat,
 04 Dec 2021 07:12:39 -0800 (PST)
X-Received: by 2002:a17:907:1c15:: with SMTP id nc21mr31453053ejc.260.1638630759170;
        Sat, 04 Dec 2021 07:12:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638630759; cv=none;
        d=google.com; s=arc-20160816;
        b=L+l4wvxDYHZ1f71odfZrCDS0KD/BJC6kW46N5Wp97p5yVS93asdNLtcmdXJ1ek8Lpw
         DwgCWEuxSW+psN4qAFa2Kicu2UuP7hKm8iOvk7Swp6UKJPr+bVsB+9xXPCsw0myJ2Uys
         euhqAn36Xn2iNS6fAfYaalbyjmtMEGtNSk0YpTTOR8yVqutzLNPIdldhVxmH5jEbKKkP
         CCJ3yNlCN3QT46EGjYheVjJ41puq/Csj3HI23c5Mvs8QJgY6wREA3DZI2IEUEVEhtTWQ
         3niuV39GJAsyOoGHP2w0M5lnQRiH9ruWP4pyJmg1B34sT8yrCGAEQeBIK4BNAhCufZOF
         ecUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Avr2CDSMTq1/HhYdY6OdMwL80dSc5M0hNRQbmaxhMn4=;
        b=qs3oRcbiRtcvpYYTiup2fPjjbHnu0alqMYj+j7Y5TSbuyEXb+8bU5ZAmEx+HFAzfrE
         WxDzYXqdSG7RpM5CpCxk74gs1/Lrk1m8o1FL3rUAPXwewlNcaAUiS9Tf7pmALS3in5u8
         Wn0JkBdjkgi/AHIzH3kPpm8gTaPjMxHoKU4gIyHUfarxE6c00dcn0VgLsZ1BEPKTP+0H
         S2Zzp9QWMk91jqXyVtZ5D1mP/9h4mvOnNV89x7c3wjukkD/Vh4IJUj+2j/M5YnvVeKu/
         tkXs3ayJ/3ldMhQF/DucAoFYzJPFDQOThKcb2XfK9J8ERPOqjLTBniRo3+ckpnX9Zise
         d+KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z7v462ua;
       spf=pass (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WkCX=QV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i23si367870edr.1.2021.12.04.07.12.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 04 Dec 2021 07:12:39 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F3E3060E71;
	Sat,  4 Dec 2021 15:12:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 66D11C341C2;
	Sat,  4 Dec 2021 15:12:37 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 282825C1010; Sat,  4 Dec 2021 07:12:37 -0800 (PST)
Date: Sat, 4 Dec 2021 07:12:37 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kernel test robot <lkp@intel.com>
Subject: Re: [PATCH -rcu] kcsan: Turn barrier instrumentation into macros
Message-ID: <20211204151237.GX641268@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211204125703.3344454-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211204125703.3344454-1-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Z7v462ua;       spf=pass
 (google.com: domain of srs0=wkcx=qv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WkCX=QV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Sat, Dec 04, 2021 at 01:57:03PM +0100, Marco Elver wrote:
> Some architectures use barriers in 'extern inline' functions, from which
> we should not refer to static inline functions.
> 
> For example, building Alpha with gcc and W=1 shows:
> 
> ./include/asm-generic/barrier.h:70:30: warning: 'kcsan_rmb' is static but used in inline function 'pmd_offset' which is not static
>    70 | #define smp_rmb()       do { kcsan_rmb(); __smp_rmb(); } while (0)
>       |                              ^~~~~~~~~
> ./arch/alpha/include/asm/pgtable.h:293:9: note: in expansion of macro 'smp_rmb'
>   293 |         smp_rmb(); /* see above */
>       |         ^~~~~~~
> 
> Which seems to warn about 6.7.4#3 of the C standard:
>   "An inline definition of a function with external linkage shall not
>    contain a definition of a modifiable object with static or thread
>    storage duration, and shall not contain a reference to an identifier
>    with internal linkage."
> 
> Fix it by turning barrier instrumentation into macros, which matches
> definitions in <asm/barrier.h>.
> 
> Perhaps we can revert this change in future, when there are no more
> 'extern inline' users left.
> 
> Link: https://lkml.kernel.org/r/202112041334.X44uWZXf-lkp@intel.com
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>

Queued and pushed, thank you!

							Thanx, Paul

> ---
>  include/linux/kcsan-checks.h | 24 +++++++++++++-----------
>  1 file changed, 13 insertions(+), 11 deletions(-)
> 
> diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> index 9d2c869167f2..92f3843d9ebb 100644
> --- a/include/linux/kcsan-checks.h
> +++ b/include/linux/kcsan-checks.h
> @@ -241,28 +241,30 @@ static inline void __kcsan_disable_current(void) { }
>   * disabled with the __no_kcsan function attribute.
>   *
>   * Also see definition of __tsan_atomic_signal_fence() in kernel/kcsan/core.c.
> + *
> + * These are all macros, like <asm/barrier.h>, since some architectures use them
> + * in non-static inline functions.
>   */
>  #define __KCSAN_BARRIER_TO_SIGNAL_FENCE(name)					\
> -	static __always_inline void kcsan_##name(void)				\
> -	{									\
> +	do {									\
>  		barrier();							\
>  		__atomic_signal_fence(__KCSAN_BARRIER_TO_SIGNAL_FENCE_##name);	\
>  		barrier();							\
> -	}
> -__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
> -__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)
> -__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
> -__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
> +	} while (0)
> +#define kcsan_mb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
> +#define kcsan_wmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)
> +#define kcsan_rmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
> +#define kcsan_release()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
>  #elif defined(CONFIG_KCSAN_WEAK_MEMORY) && defined(__KCSAN_INSTRUMENT_BARRIERS__)
>  #define kcsan_mb	__kcsan_mb
>  #define kcsan_wmb	__kcsan_wmb
>  #define kcsan_rmb	__kcsan_rmb
>  #define kcsan_release	__kcsan_release
>  #else /* CONFIG_KCSAN_WEAK_MEMORY && ... */
> -static inline void kcsan_mb(void)		{ }
> -static inline void kcsan_wmb(void)		{ }
> -static inline void kcsan_rmb(void)		{ }
> -static inline void kcsan_release(void)		{ }
> +#define kcsan_mb()	do { } while (0)
> +#define kcsan_wmb()	do { } while (0)
> +#define kcsan_rmb()	do { } while (0)
> +#define kcsan_release()	do { } while (0)
>  #endif /* CONFIG_KCSAN_WEAK_MEMORY && ... */
>  
>  /**
> -- 
> 2.34.1.400.ga245620fadb-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211204151237.GX641268%40paulmck-ThinkPad-P17-Gen-1.
