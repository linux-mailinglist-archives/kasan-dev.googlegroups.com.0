Return-Path: <kasan-dev+bncBCS4VDMYRUNBBZOL326QMGQEQX6QXUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 61972A3E726
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 23:00:07 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e670e4ecefsf37359076d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 14:00:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740088806; cv=pass;
        d=google.com; s=arc-20240605;
        b=UHJn75MKHQ/sVs0H25rZW4rFxyY6hJTxG5FdomHpEquYaP+G8DakR1fO3NBu5Wx7gs
         yydi18yV1N9Wxm2+yzyoIN92ZPt4CRmNy3W12MXACpVDHxgJk9OvHKYSFgGDFfRnk0WH
         pgl+Vsn28UEjXj3u58iAJGIS0w4h6hopAKSoiMsY3iIBFe8BOwhJFvgKYmfVKcoL1H0+
         ggIdTeyJTG8cj84wTGosOB1WZwiAkBu+VbgGo64kQX6GeTi5FxfnHsnKRMGZPtLnEgGc
         lMM+05BLFQg9JhVD//03I2QwdZxhv16BnLcQfSTchaTVMwmdPnXoesbUQSRyrWTh/ahE
         1giw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=vYCyghhkaCii4iF0G3Zg1nWiIG6gLSBJwoas59P9xvA=;
        fh=HpkIaBnATsiJCY4ExjHo771O+gAHKhEIO3d0MXIC6F8=;
        b=g5DTCC4YvBzxEiRbNXiQd4/VBMJry3kYVgnocKSzZmNZT3cmXfkjdXij2Z84tF7ruz
         R6PjeYpRO25CmTdSwYomk6F0BlAX60Y0CS64OKqNH/0jZf1/6R40dOwDX7+wrzeuin2w
         N840cmFWy05407+vrSOVIvXjf3Wj+SoojwDZjOFfoFJA+gU/fDwr3FkJwiCuCMuKay46
         kB1dswkJ+5oqhJ2qwQB6NTSM8DCivN6EMqLCYwcyiO7TgVIGx5qb/jPImTbgbH92vvJ1
         gzmOtlroxG1jixDsAKMZlZ5Sm9+/aO+dq6vXwM8HgusypiCGLL1Uz3OaXK4Hrh6tOfLe
         CE/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OBxxi8Bd;
       spf=pass (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=eDkt=VL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740088806; x=1740693606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vYCyghhkaCii4iF0G3Zg1nWiIG6gLSBJwoas59P9xvA=;
        b=Cs5SXvOzbxIP5AccjPnAhcwy9pnxuzuel/2sGGgUWBQR8rJPtmJCJQ4ML+3HQQYqXU
         CJq4Gr0oUL6knPj0ZFY1B0um5M6JN7NTtQMBwsyrQZxaVaJpRAFv8EXAX0R6j7A4En/+
         GmnsuFXEG1AzcD2NjFmNGoahNn7d2jCZlW61qM4PseOLe6xaADu8odm93XS9/WOGuNd/
         rqBRhGZzEqV2P2GbOsl/HEWWmFuiw0fWaRgwoT95B5ktYwo4GE4jF8Ic9CHn6VflzW2Y
         h4v+nQ7aag0fagHGabGkGOG+1wgRKDxe0dN7OKMb8xKWnkL9nm5hPaDFCR755g1fsAaF
         CF4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740088806; x=1740693606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vYCyghhkaCii4iF0G3Zg1nWiIG6gLSBJwoas59P9xvA=;
        b=UfcAXrlGTu1FLD8OOImKq6KbGDjsdbhBDAdleXWmsZSOjE5r0HFm7Aw9DSSx0QtVru
         6/EevqfHV1xVka/2SZQ3bC6POh7TCYI99meBa0K5ieP6w/U7YTClP3ofvnauSMBgxG4b
         TQ6RamZtBYCBQSn7J96sWQvc1HwD8QqFywyB/r9218KZISI60zGtepjNJrXmlQHjN/4a
         8rcrONTaIR2oAgIo7mijin26Ap6EI/Fl45znc+GKQ5zJBtG1DT9rXfL9ZH2FCO2rTM3t
         DoRz+YWTGABWXj3HAfO4wFwDDonicNj7DAMY3+/SnKpbfpZnlL+WSSr+uDdLJxFJLsEp
         7WuA==
X-Forwarded-Encrypted: i=2; AJvYcCX+KyjA4rjswI9wbJgFzbFA0rtbbgXP+ZHa9np1+AWsfj71n/fzIw+rGEqc/xyJOwUXcmbt1A==@lfdr.de
X-Gm-Message-State: AOJu0YzmrcCic1HvfWy9+0BPJyii+PUHmMs/So3BUMK7fi4NyU4dxF3p
	ToBimUohrg9LIIUS1qJKLOYHSPaXORJaP5Wcco8u5MaC/fdsfvgv
X-Google-Smtp-Source: AGHT+IGNA4+S6xnUjtj/RV+E0RRv/URVyAuZDd6sxUrghBTFyOr1TJ4PVgwskZbNf+s0TLXbd4Deqg==
X-Received: by 2002:a05:6214:ca4:b0:6d1:7433:3670 with SMTP id 6a1803df08f44-6e6ae7c708cmr10762716d6.4.1740088806090;
        Thu, 20 Feb 2025 14:00:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGtML286VlnqeDDj3xWUd7XS8UHmpb1wVaSD8KujJNRVg==
Received: by 2002:a0c:e58b:0:b0:6df:8164:cdb0 with SMTP id 6a1803df08f44-6e6a2255d2dls10100976d6.1.-pod-prod-06-us;
 Thu, 20 Feb 2025 14:00:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXjLFwbvpG2Ycs4qcyNIly0Ia9rlSdGnhmJ4mXB9b1EF7VERP682kpnZ9SaRP61qQYl8ks2b308PcI=@googlegroups.com
X-Received: by 2002:a05:6122:788:b0:520:61ee:c7fc with SMTP id 71dfb90a1353d-521ee22bb4bmr723936e0c.4.1740088805130;
        Thu, 20 Feb 2025 14:00:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740088805; cv=none;
        d=google.com; s=arc-20240605;
        b=IBN43et7Lc8KnWNYb675VKAorbi0CQJRXD5OSQJLMtmbBPTq7RTwh8OdjgSl/CHWAs
         4hHQSAlKd5cux2lCltZcnqIyJzOC4zBudj5WdtUDsVMlRmru4saqzmnbF4qrVIpvbqPM
         nDTAFWW/pJEQBQDo01f0gyVxfV+2a5gKjuhbAGf635cVCp+yaNIM5P7o1UEvrEhMVW8E
         OSg/1dU2mjo/f3KvYFcsqR7Jn6CrbXc8Mc7phxcT9cpsdszHcbt16WekuxLnOMzerNGZ
         AD454Q1tAKU0Jx6gYu1bBSqouRPcMiqNauTpNa6Y4TGAZapyzTjrUu7oe9cyFLEeO8Eu
         8KbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NNuTHNPAt5RZA//hKc0T6v78aqBBjNznsj6szEvylmw=;
        fh=6daLWNj2ng9AC7k6NsHppG+JXGUhij4U/k8Liihd2jM=;
        b=JgM30m+prbkzsHQxkxUxPAzK/U6M8Pm6R/ooXyimVXeoUUSg8M8KB+8G+9UVpw5OKF
         T3EL6RrerQ0Rc7IknvRkKfuTxdlKJxuOsKlJ2qzySHkMfKkGV2A4EZ45MGN1X0f2BUOF
         TU5kxQWZyOJ2Lc9cLsXUWQS8oNcPenSIJpaUmTf+se9K9/rPeJoMRpToG9GFXm4cFhbw
         cABUmfJ9idTpihehrc9EaE0qcLGZSCvwSHwrqPcVr82rCHVm+BAZuDvVmPgL5okl14oO
         wT86rlV70yTy7pzSvy0YAtU9plQJAto4BXNOA2kGBnqOF4/X85xA/SkTzbVaA2CFTMQ2
         u0QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OBxxi8Bd;
       spf=pass (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=eDkt=VL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5209d09e834si572907e0c.1.2025.02.20.14.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Feb 2025 14:00:05 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1AC4B5C5AA7;
	Thu, 20 Feb 2025 21:59:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C41DCC4CED1;
	Thu, 20 Feb 2025 22:00:03 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6FE07CE0B34; Thu, 20 Feb 2025 14:00:03 -0800 (PST)
Date: Thu, 20 Feb 2025 14:00:03 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
Message-ID: <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-16-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250206181711.1902989-16-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OBxxi8Bd;       spf=pass
 (google.com: domain of srs0=edkt=vl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=eDkt=VL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Thu, Feb 06, 2025 at 07:10:09PM +0100, Marco Elver wrote:
> Improve the existing annotations to properly support Clang's capability
> analysis.
> 
> The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED.
> However, it does not make sense to acquire rcu_read_lock_bh() after
> rcu_read_lock() - annotate the _bh() and _sched() variants to also
> acquire 'RCU', so that Clang (and also Sparse) can warn about it.

You lost me on this one.  What breaks if rcu_read_lock_bh() is invoked
while rcu_read_lock() is in effect?

							Thanx, Paul

> The above change also simplified introducing annotations, where it would
> not matter if RCU, RCU_BH, or RCU_SCHED is acquired: through the
> introduction of __rcu_guarded, we can use Clang's capability analysis to
> warn if a pointer is dereferenced without any of the RCU locks held, or
> updated without the appropriate helpers.
> 
> The primitives rcu_assign_pointer() and friends are wrapped with
> capability_unsafe(), which enforces using them to update RCU-protected
> pointers marked with __rcu_guarded.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  .../dev-tools/capability-analysis.rst         |  2 +-
>  include/linux/cleanup.h                       |  4 +
>  include/linux/rcupdate.h                      | 73 +++++++++++++------
>  lib/test_capability-analysis.c                | 68 +++++++++++++++++
>  4 files changed, 123 insertions(+), 24 deletions(-)
> 
> diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
> index a34dfe7b0b09..73dd28a23b11 100644
> --- a/Documentation/dev-tools/capability-analysis.rst
> +++ b/Documentation/dev-tools/capability-analysis.rst
> @@ -86,7 +86,7 @@ Supported Kernel Primitives
>  
>  Currently the following synchronization primitives are supported:
>  `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
> -`bit_spinlock`.
> +`bit_spinlock`, RCU.
>  
>  For capabilities with an initialization function (e.g., `spin_lock_init()`),
>  calling this function on the capability instance before initializing any
> diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
> index 93a166549add..7d70d308357a 100644
> --- a/include/linux/cleanup.h
> +++ b/include/linux/cleanup.h
> @@ -404,6 +404,10 @@ static inline class_##_name##_t class_##_name##_constructor(void)	\
>  	return _t;							\
>  }
>  
> +#define DECLARE_LOCK_GUARD_0_ATTRS(_name, _lock, _unlock)		\
> +static inline class_##_name##_t class_##_name##_constructor(void) _lock;\
> +static inline void class_##_name##_destructor(class_##_name##_t *_T) _unlock
> +
>  #define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
>  __DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
>  __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, __VA_ARGS__)		\
> diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
> index 48e5c03df1dd..ee68095ba9f0 100644
> --- a/include/linux/rcupdate.h
> +++ b/include/linux/rcupdate.h
> @@ -31,6 +31,16 @@
>  #include <asm/processor.h>
>  #include <linux/context_tracking_irq.h>
>  
> +token_capability(RCU);
> +token_capability_instance(RCU, RCU_SCHED);
> +token_capability_instance(RCU, RCU_BH);
> +
> +/*
> + * A convenience macro that can be used for RCU-protected globals or struct
> + * members; adds type qualifier __rcu, and also enforces __var_guarded_by(RCU).
> + */
> +#define __rcu_guarded __rcu __var_guarded_by(RCU)
> +
>  #define ULONG_CMP_GE(a, b)	(ULONG_MAX / 2 >= (a) - (b))
>  #define ULONG_CMP_LT(a, b)	(ULONG_MAX / 2 < (a) - (b))
>  
> @@ -431,7 +441,8 @@ static inline void rcu_preempt_sleep_check(void) { }
>  
>  // See RCU_LOCKDEP_WARN() for an explanation of the double call to
>  // debug_lockdep_rcu_enabled().
> -static inline bool lockdep_assert_rcu_helper(bool c)
> +static inline bool lockdep_assert_rcu_helper(bool c, const struct __capability_RCU *cap)
> +	__asserts_shared_cap(RCU) __asserts_shared_cap(cap)
>  {
>  	return debug_lockdep_rcu_enabled() &&
>  	       (c || !rcu_is_watching() || !rcu_lockdep_current_cpu_online()) &&
> @@ -444,7 +455,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * Splats if lockdep is enabled and there is no rcu_read_lock() in effect.
>   */
>  #define lockdep_assert_in_rcu_read_lock() \
> -	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map)))
> +	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map), RCU))
>  
>  /**
>   * lockdep_assert_in_rcu_read_lock_bh - WARN if not protected by rcu_read_lock_bh()
> @@ -454,7 +465,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * actual rcu_read_lock_bh() is required.
>   */
>  #define lockdep_assert_in_rcu_read_lock_bh() \
> -	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map)))
> +	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map), RCU_BH))
>  
>  /**
>   * lockdep_assert_in_rcu_read_lock_sched - WARN if not protected by rcu_read_lock_sched()
> @@ -464,7 +475,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * instead an actual rcu_read_lock_sched() is required.
>   */
>  #define lockdep_assert_in_rcu_read_lock_sched() \
> -	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map)))
> +	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map), RCU_SCHED))
>  
>  /**
>   * lockdep_assert_in_rcu_reader - WARN if not within some type of RCU reader
> @@ -482,17 +493,17 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>  	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map) &&			\
>  					       !lock_is_held(&rcu_bh_lock_map) &&		\
>  					       !lock_is_held(&rcu_sched_lock_map) &&		\
> -					       preemptible()))
> +					       preemptible(), RCU))
>  
>  #else /* #ifdef CONFIG_PROVE_RCU */
>  
>  #define RCU_LOCKDEP_WARN(c, s) do { } while (0 && (c))
>  #define rcu_sleep_check() do { } while (0)
>  
> -#define lockdep_assert_in_rcu_read_lock() do { } while (0)
> -#define lockdep_assert_in_rcu_read_lock_bh() do { } while (0)
> -#define lockdep_assert_in_rcu_read_lock_sched() do { } while (0)
> -#define lockdep_assert_in_rcu_reader() do { } while (0)
> +#define lockdep_assert_in_rcu_read_lock() __assert_shared_cap(RCU)
> +#define lockdep_assert_in_rcu_read_lock_bh() __assert_shared_cap(RCU_BH)
> +#define lockdep_assert_in_rcu_read_lock_sched() __assert_shared_cap(RCU_SCHED)
> +#define lockdep_assert_in_rcu_reader() __assert_shared_cap(RCU)
>  
>  #endif /* #else #ifdef CONFIG_PROVE_RCU */
>  
> @@ -512,11 +523,11 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>  #endif /* #else #ifdef __CHECKER__ */
>  
>  #define __unrcu_pointer(p, local)					\
> -({									\
> +capability_unsafe(							\
>  	typeof(*p) *local = (typeof(*p) *__force)(p);			\
>  	rcu_check_sparse(p, __rcu);					\
>  	((typeof(*p) __force __kernel *)(local)); 			\
> -})
> +)
>  /**
>   * unrcu_pointer - mark a pointer as not being RCU protected
>   * @p: pointer needing to lose its __rcu property
> @@ -592,7 +603,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * other macros that it invokes.
>   */
>  #define rcu_assign_pointer(p, v)					      \
> -do {									      \
> +capability_unsafe(							      \
>  	uintptr_t _r_a_p__v = (uintptr_t)(v);				      \
>  	rcu_check_sparse(p, __rcu);					      \
>  									      \
> @@ -600,7 +611,7 @@ do {									      \
>  		WRITE_ONCE((p), (typeof(p))(_r_a_p__v));		      \
>  	else								      \
>  		smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
> -} while (0)
> +)
>  
>  /**
>   * rcu_replace_pointer() - replace an RCU pointer, returning its old value
> @@ -843,9 +854,10 @@ do {									      \
>   * only when acquiring spinlocks that are subject to priority inheritance.
>   */
>  static __always_inline void rcu_read_lock(void)
> +	__acquires_shared(RCU)
>  {
>  	__rcu_read_lock();
> -	__acquire(RCU);
> +	__acquire_shared(RCU);
>  	rcu_lock_acquire(&rcu_lock_map);
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(),
>  			 "rcu_read_lock() used illegally while idle");
> @@ -874,11 +886,12 @@ static __always_inline void rcu_read_lock(void)
>   * See rcu_read_lock() for more information.
>   */
>  static inline void rcu_read_unlock(void)
> +	__releases_shared(RCU)
>  {
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(),
>  			 "rcu_read_unlock() used illegally while idle");
>  	rcu_lock_release(&rcu_lock_map); /* Keep acq info for rls diags. */
> -	__release(RCU);
> +	__release_shared(RCU);
>  	__rcu_read_unlock();
>  }
>  
> @@ -897,9 +910,11 @@ static inline void rcu_read_unlock(void)
>   * was invoked from some other task.
>   */
>  static inline void rcu_read_lock_bh(void)
> +	__acquires_shared(RCU) __acquires_shared(RCU_BH)
>  {
>  	local_bh_disable();
> -	__acquire(RCU_BH);
> +	__acquire_shared(RCU);
> +	__acquire_shared(RCU_BH);
>  	rcu_lock_acquire(&rcu_bh_lock_map);
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(),
>  			 "rcu_read_lock_bh() used illegally while idle");
> @@ -911,11 +926,13 @@ static inline void rcu_read_lock_bh(void)
>   * See rcu_read_lock_bh() for more information.
>   */
>  static inline void rcu_read_unlock_bh(void)
> +	__releases_shared(RCU) __releases_shared(RCU_BH)
>  {
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(),
>  			 "rcu_read_unlock_bh() used illegally while idle");
>  	rcu_lock_release(&rcu_bh_lock_map);
> -	__release(RCU_BH);
> +	__release_shared(RCU_BH);
> +	__release_shared(RCU);
>  	local_bh_enable();
>  }
>  
> @@ -935,9 +952,11 @@ static inline void rcu_read_unlock_bh(void)
>   * rcu_read_lock_sched() was invoked from an NMI handler.
>   */
>  static inline void rcu_read_lock_sched(void)
> +	__acquires_shared(RCU) __acquires_shared(RCU_SCHED)
>  {
>  	preempt_disable();
> -	__acquire(RCU_SCHED);
> +	__acquire_shared(RCU);
> +	__acquire_shared(RCU_SCHED);
>  	rcu_lock_acquire(&rcu_sched_lock_map);
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(),
>  			 "rcu_read_lock_sched() used illegally while idle");
> @@ -945,9 +964,11 @@ static inline void rcu_read_lock_sched(void)
>  
>  /* Used by lockdep and tracing: cannot be traced, cannot call lockdep. */
>  static inline notrace void rcu_read_lock_sched_notrace(void)
> +	__acquires_shared(RCU) __acquires_shared(RCU_SCHED)
>  {
>  	preempt_disable_notrace();
> -	__acquire(RCU_SCHED);
> +	__acquire_shared(RCU);
> +	__acquire_shared(RCU_SCHED);
>  }
>  
>  /**
> @@ -956,18 +977,22 @@ static inline notrace void rcu_read_lock_sched_notrace(void)
>   * See rcu_read_lock_sched() for more information.
>   */
>  static inline void rcu_read_unlock_sched(void)
> +	__releases_shared(RCU) __releases_shared(RCU_SCHED)
>  {
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(),
>  			 "rcu_read_unlock_sched() used illegally while idle");
>  	rcu_lock_release(&rcu_sched_lock_map);
> -	__release(RCU_SCHED);
> +	__release_shared(RCU_SCHED);
> +	__release_shared(RCU);
>  	preempt_enable();
>  }
>  
>  /* Used by lockdep and tracing: cannot be traced, cannot call lockdep. */
>  static inline notrace void rcu_read_unlock_sched_notrace(void)
> +	__releases_shared(RCU) __releases_shared(RCU_SCHED)
>  {
> -	__release(RCU_SCHED);
> +	__release_shared(RCU_SCHED);
> +	__release_shared(RCU);
>  	preempt_enable_notrace();
>  }
>  
> @@ -1010,10 +1035,10 @@ static inline notrace void rcu_read_unlock_sched_notrace(void)
>   * ordering guarantees for either the CPU or the compiler.
>   */
>  #define RCU_INIT_POINTER(p, v) \
> -	do { \
> +	capability_unsafe( \
>  		rcu_check_sparse(p, __rcu); \
>  		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
> -	} while (0)
> +	)
>  
>  /**
>   * RCU_POINTER_INITIALIZER() - statically initialize an RCU protected pointer
> @@ -1172,4 +1197,6 @@ DEFINE_LOCK_GUARD_0(rcu,
>  	} while (0),
>  	rcu_read_unlock())
>  
> +DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU));
> +
>  #endif /* __LINUX_RCUPDATE_H */
> diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
> index fc8dcad2a994..f5a1dda6ca38 100644
> --- a/lib/test_capability-analysis.c
> +++ b/lib/test_capability-analysis.c
> @@ -7,6 +7,7 @@
>  #include <linux/bit_spinlock.h>
>  #include <linux/build_bug.h>
>  #include <linux/mutex.h>
> +#include <linux/rcupdate.h>
>  #include <linux/seqlock.h>
>  #include <linux/spinlock.h>
>  
> @@ -277,3 +278,70 @@ static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
>  		bit_spin_unlock(3, &d->bits);
>  	}
>  }
> +
> +/*
> + * Test that we can mark a variable guarded by RCU, and we can dereference and
> + * write to the pointer with RCU's primitives.
> + */
> +struct test_rcu_data {
> +	long __rcu_guarded *data;
> +};
> +
> +static void __used test_rcu_guarded_reader(struct test_rcu_data *d)
> +{
> +	rcu_read_lock();
> +	(void)rcu_dereference(d->data);
> +	rcu_read_unlock();
> +
> +	rcu_read_lock_bh();
> +	(void)rcu_dereference(d->data);
> +	rcu_read_unlock_bh();
> +
> +	rcu_read_lock_sched();
> +	(void)rcu_dereference(d->data);
> +	rcu_read_unlock_sched();
> +}
> +
> +static void __used test_rcu_guard(struct test_rcu_data *d)
> +{
> +	guard(rcu)();
> +	(void)rcu_dereference(d->data);
> +}
> +
> +static void __used test_rcu_guarded_updater(struct test_rcu_data *d)
> +{
> +	rcu_assign_pointer(d->data, NULL);
> +	RCU_INIT_POINTER(d->data, NULL);
> +	(void)unrcu_pointer(d->data);
> +}
> +
> +static void wants_rcu_held(void)	__must_hold_shared(RCU)       { }
> +static void wants_rcu_held_bh(void)	__must_hold_shared(RCU_BH)    { }
> +static void wants_rcu_held_sched(void)	__must_hold_shared(RCU_SCHED) { }
> +
> +static void __used test_rcu_lock_variants(void)
> +{
> +	rcu_read_lock();
> +	wants_rcu_held();
> +	rcu_read_unlock();
> +
> +	rcu_read_lock_bh();
> +	wants_rcu_held_bh();
> +	rcu_read_unlock_bh();
> +
> +	rcu_read_lock_sched();
> +	wants_rcu_held_sched();
> +	rcu_read_unlock_sched();
> +}
> +
> +static void __used test_rcu_assert_variants(void)
> +{
> +	lockdep_assert_in_rcu_read_lock();
> +	wants_rcu_held();
> +
> +	lockdep_assert_in_rcu_read_lock_bh();
> +	wants_rcu_held_bh();
> +
> +	lockdep_assert_in_rcu_read_lock_sched();
> +	wants_rcu_held_sched();
> +}
> -- 
> 2.48.1.502.g6dc24dfdaf-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a1483cb1-13a5-4d6e-87b0-fda5f66b0817%40paulmck-laptop.
