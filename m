Return-Path: <kasan-dev+bncBCS4VDMYRUNBBSEU47EQMGQEGCB33LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13d.google.com (mail-yx1-xb13d.google.com [IPv6:2607:f8b0:4864:20::b13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BE0DCB3DBA
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 20:30:20 +0100 (CET)
Received: by mail-yx1-xb13d.google.com with SMTP id 956f58d0204a3-6421389b970sf238355d50.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 11:30:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765395017; cv=pass;
        d=google.com; s=arc-20240605;
        b=GbuIKaVydKUnr/EkHKD68+bBVvYWQGv4vf0gT87MZriNz6WagnlfcEg4KkJWGm/xuu
         Apc0/FxmltgYyJkgB+ERChuu9MonFOfQzTrMKHKoEDYJkQS2AmLUk+VD7z2Nvt6cVZwi
         8Y97rk8iGUNzsUdq16TVipw9I81fhKAHRxJHCQf/dByipPaDpENKmlOWphwjc9W/GgE8
         h3vv2wHdm61OdaLlGHmJIIg8DbLbEFo9d2uIGDB4Cjm9HwltYm9IJKTD1zgO4L8DGV8y
         ZcBSggBqSm6sdlakW1pqUoMBcMi0I2LEnWx7g5aWq5ix88/HdoktMhxMCZv1NtlVUaVk
         zQDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=JqM4zPgPhjahUumtcV1Wkdfgb1iXU9dgQ4yFdqIV0Nw=;
        fh=pFnmDaAYiid2gDAZi7qP/xvs9goza3znetAHxYum/lc=;
        b=Qd1D861ivgUYZhmDPGeoh1GUexVF98d+hMPWay0WaH5SSaORgg317KB3KDjk4zmzVk
         A8+Xzbs/TR980GMte9ZEEypeMo0IVXytlv6g6BtWNf8DF6XHzD30j8OEngLLtCvrsC+j
         x5ASgwA5Wy9g+GpQeI1mubRrhsCckTuzR9/C7iNO0NKaL/Crlm5aes4Ry0/q3/PoAWGA
         Xmz4H2oS3VDdTfZfUT7KOWWVNqhbVXm1jbHQoT5mnbwJk5tZnzqHVsN+pjxVgK1PieWZ
         1CSx3m3DWbkt3clwASkMiqN7p72ThPqhCJl8uVjZHW/ohIDNLN0L+tzNRW8oJzxhpv0L
         wNZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pJrAU1X3;
       spf=pass (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=0X6L=6Q=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765395017; x=1765999817; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JqM4zPgPhjahUumtcV1Wkdfgb1iXU9dgQ4yFdqIV0Nw=;
        b=hjshMzSkLFtAebKhk1vn6ZsWAkWJDkc5exlPxiLEVvpR1ikxAc0nhu2+fP0vUtC/RU
         AowZ5sJxFMH65ez3Ke7JC/2TV/IgRsExvcgNh3n6g5boXYb7rjZ6ne2NDcVgswwPKTYn
         sF6HK2CFPE23l7sfVEulMNIiWbiZfzxOlFb/d70NiPjlZHOhRbrr+jSDOK3WnqXnhPkT
         5kdQqpwZhG+IcidmPgLuynqg8V5nxMzutVpIqXLRKmox+973CVQMMxL3HtMzffC151sM
         2rOLG6GyfUn8Dn2qLnFXMrGqLNemqsTARO9yHVCPGg7GLpgDL4hkY0auP0IXi7RYFm40
         szfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765395017; x=1765999817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JqM4zPgPhjahUumtcV1Wkdfgb1iXU9dgQ4yFdqIV0Nw=;
        b=UoxlQCylIBPaPpsB2qYpu/1hh7IfDIvnvm8eDrpdP7eIjoiCGrKA2VnuAffpeWKoSv
         oOkeXgWQR2KFb39dbC9ohlwX0DI/of2Mxr7ZX6QH/6IGbHhTjaHNIbjkw6OH97zEmNJJ
         pX1VxAC569VotvcJuQ4pPaomb9cSEqB2ub3WdJS8M4gz8IILV8HFhL7pdmR987ISJSC7
         BJDRiP1Z+P7myY5NRJ0dZ7xK+saY8PHYTBbIFV57yY+jvP5QJCMD2fEJ4hT+XuQwl40f
         BeA5gqfTObwjC5Kior87UJ/5dnLROtg8Tvq8qQ4Jm/jmeSASDpoBdlI69gs/so4xxgzi
         HPgw==
X-Forwarded-Encrypted: i=2; AJvYcCX2E8Nu9idCc3M1Z+JivkeCsabwa8zwD50QdHNsbMF4OmFJxR8hA/2nfnhxNFXLX7EDk3csJw==@lfdr.de
X-Gm-Message-State: AOJu0YxkxZ1+EyBmwgGH/2qqKYUXNVmdHv3+cUvS/FB6djKMGhf689hq
	9RiN9W1TgxIRk/n1dZ6ezp+GJRQS3/rariJKwfBMWZOyOuxh/QWXzcdl
X-Google-Smtp-Source: AGHT+IEyAcCzYuhzz1rD/JP9Zr+tlZpZTAwW1eUPxNCKzPQI9P09K5OSle+3e3b3j+PGV/f45NCNJg==
X-Received: by 2002:a53:c055:0:20b0:63f:a103:5d2d with SMTP id 956f58d0204a3-6446e948be3mr2504807d50.37.1765395017130;
        Wed, 10 Dec 2025 11:30:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaEj6nyMp+gZOo1oSLbIhfmz2Z1XmhmDzg2IzCql6Mcug=="
Received: by 2002:a53:b689:0:b0:641:f6b6:6482 with SMTP id 956f58d0204a3-64478e280c3ls59762d50.3.-pod-prod-07-us;
 Wed, 10 Dec 2025 11:30:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXowtkJQcPp9FJ6uVeYjDBQgGiRiQXAREL1bVPMwYf+0cmIvZby5NkGLzI7AKIwJEq6xrbicfcWds0=@googlegroups.com
X-Received: by 2002:a05:690c:fc8:b0:786:5851:2b4 with SMTP id 00721157ae682-78c9d6fa712mr31620737b3.27.1765395015858;
        Wed, 10 Dec 2025 11:30:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765395015; cv=none;
        d=google.com; s=arc-20240605;
        b=Sd5W1n9tJyGK7yD8Y8Ua5C3gBagndGDgSzRFv87CqsttIUMSka20PLOG6/rT/iwrIr
         6n2oMh1yY08goCRk4+XyqnAtD1XEvyTjjhHFLWbKSvaD6IsZuMnmLgEMGLzNQPqIxbNy
         u3U1e8ATBTR7y99/xiCMGu7SSszuNOWVr6Ov+Dhw+cbjXXfNUfl9qTJfWw3rF3GzdOHh
         AXrdk/Ek/4wfkBl5Q3R8cPVgpS6AYAx7NpfibOnORPOvBLarRpato+zoizcVLvNKuhqF
         DYQvTgWo2qs8f+VmTrmsGqj+GPhVCV6kLJgl0swG7xVOw/DRUwa3LJhaeQ5FJZMwYJ9K
         ICNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=MgD/MT77kKvzo1IRBH9g0uloGKAYrGS1XSqVo/vq9TE=;
        fh=ydmDXTPQBUm8gYjTRTOr6oYMuSaewZBXZ+dcUdAtNU8=;
        b=FPTnOgl248EKhUVfn3V8FubQvwM7TQ8EY0wou5iqJjjwbNR7wQczHByEMfcQaLmi3V
         4VpyH9dFN6xOYasVCzX/5bEjf3LWLGf88eweN3z+4htnf6F/TINVC43EjETmNNpBGohc
         +pI2si5o/QkogzBEbRDiEsMohgERnV9wR03J7B0cieLFK/T1LvR1U0/ocGijUY8L9Cqo
         TVJdr5qdi+K5cLawlfilTfqAuMa3LpYD1w7yx7uBArip5lI8e0HIlI/v5oPzTUXQQ6PN
         l8ZjE0sbVMy3yaL7RQvAJepEXqc0sX4kH95Qly1EiqgW3YXVQFv5NDs/Ha6h8zLMo9/p
         5BYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pJrAU1X3;
       spf=pass (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=0X6L=6Q=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78d69db0dc9si341147b3.3.2025.12.10.11.30.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 11:30:15 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CF32C60053;
	Wed, 10 Dec 2025 19:30:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 34116C4CEF1;
	Wed, 10 Dec 2025 19:30:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id D5BE5CE0C93; Wed, 10 Dec 2025 11:30:11 -0800 (PST)
Date: Wed, 10 Dec 2025 11:30:11 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 14/35] rcu: Support Clang's context analysis
Message-ID: <98453e19-7df2-43cb-8f05-87632f360028@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-15-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120151033.3840508-15-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pJrAU1X3;       spf=pass
 (google.com: domain of srs0=0x6l=6q=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender)
 smtp.mailfrom="SRS0=0X6L=6Q=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Nov 20, 2025 at 04:09:39PM +0100, Marco Elver wrote:
> Improve the existing annotations to properly support Clang's context
> analysis.
> 
> The old annotations distinguished between RCU, RCU_BH, and RCU_SCHED;
> however, to more easily be able to express that "hold the RCU read lock"
> without caring if the normal, _bh(), or _sched() variant was used we'd
> have to remove the distinction of the latter variants: change the _bh()
> and _sched() variants to also acquire "RCU".
> 
> When (and if) we introduce context guards to denote more generally that
> "IRQ", "BH", "PREEMPT" contexts are disabled, it would make sense to
> acquire these instead of RCU_BH and RCU_SCHED respectively.
> 
> The above change also simplified introducing __guarded_by support, where
> only the "RCU" context guard needs to be held: introduce __rcu_guarded,
> where Clang's context analysis warns if a pointer is dereferenced
> without any of the RCU locks held, or updated without the appropriate
> helpers.
> 
> The primitives rcu_assign_pointer() and friends are wrapped with
> context_unsafe(), which enforces using them to update RCU-protected
> pointers marked with __rcu_guarded.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Good reminder!  I had lost track of this series.

My big questions here are:

o	What about RCU readers using (say) preempt_disable() instead
	of rcu_read_lock_sched()?

o	What about RCU readers using local_bh_disable() instead of
	rcu_read_lock_sched()?

And keeping in mind that such readers might start in assembly language.

One reasonable approach is to require such readers to use something like
rcu_dereference_all() or rcu_dereference_all_check(), which could then
have special dispensation to instead rely on run-time checks.

Another more powerful approach would be to make this facility also
track preemption, interrupt, NMI, and BH contexts.

Either way could be a significant improvement over what we have now.

Thoughts?

							Thanx, Paul

> ---
> v3:
> * Properly support reentrancy via new compiler support.
> 
> v2:
> * Reword commit message and point out reentrancy caveat.
> ---
>  Documentation/dev-tools/context-analysis.rst |  2 +-
>  include/linux/rcupdate.h                     | 77 ++++++++++++------
>  lib/test_context-analysis.c                  | 85 ++++++++++++++++++++
>  3 files changed, 139 insertions(+), 25 deletions(-)
> 
> diff --git a/Documentation/dev-tools/context-analysis.rst b/Documentation/dev-tools/context-analysis.rst
> index a3d925ce2df4..05164804a92a 100644
> --- a/Documentation/dev-tools/context-analysis.rst
> +++ b/Documentation/dev-tools/context-analysis.rst
> @@ -81,7 +81,7 @@ Supported Kernel Primitives
>  
>  Currently the following synchronization primitives are supported:
>  `raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`,
> -`bit_spinlock`.
> +`bit_spinlock`, RCU.
>  
>  For context guards with an initialization function (e.g., `spin_lock_init()`),
>  calling this function before initializing any guarded members or globals
> diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
> index c5b30054cd01..5cddb9019a99 100644
> --- a/include/linux/rcupdate.h
> +++ b/include/linux/rcupdate.h
> @@ -31,6 +31,16 @@
>  #include <asm/processor.h>
>  #include <linux/context_tracking_irq.h>
>  
> +token_context_guard(RCU, __reentrant_ctx_guard);
> +token_context_guard_instance(RCU, RCU_SCHED);
> +token_context_guard_instance(RCU, RCU_BH);
> +
> +/*
> + * A convenience macro that can be used for RCU-protected globals or struct
> + * members; adds type qualifier __rcu, and also enforces __guarded_by(RCU).
> + */
> +#define __rcu_guarded __rcu __guarded_by(RCU)
> +
>  #define ULONG_CMP_GE(a, b)	(ULONG_MAX / 2 >= (a) - (b))
>  #define ULONG_CMP_LT(a, b)	(ULONG_MAX / 2 < (a) - (b))
>  
> @@ -425,7 +435,8 @@ static inline void rcu_preempt_sleep_check(void) { }
>  
>  // See RCU_LOCKDEP_WARN() for an explanation of the double call to
>  // debug_lockdep_rcu_enabled().
> -static inline bool lockdep_assert_rcu_helper(bool c)
> +static inline bool lockdep_assert_rcu_helper(bool c, const struct __ctx_guard_RCU *ctx)
> +	__assumes_shared_ctx_guard(RCU) __assumes_shared_ctx_guard(ctx)
>  {
>  	return debug_lockdep_rcu_enabled() &&
>  	       (c || !rcu_is_watching() || !rcu_lockdep_current_cpu_online()) &&
> @@ -438,7 +449,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * Splats if lockdep is enabled and there is no rcu_read_lock() in effect.
>   */
>  #define lockdep_assert_in_rcu_read_lock() \
> -	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map)))
> +	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_lock_map), RCU))
>  
>  /**
>   * lockdep_assert_in_rcu_read_lock_bh - WARN if not protected by rcu_read_lock_bh()
> @@ -448,7 +459,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * actual rcu_read_lock_bh() is required.
>   */
>  #define lockdep_assert_in_rcu_read_lock_bh() \
> -	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map)))
> +	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_bh_lock_map), RCU_BH))
>  
>  /**
>   * lockdep_assert_in_rcu_read_lock_sched - WARN if not protected by rcu_read_lock_sched()
> @@ -458,7 +469,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * instead an actual rcu_read_lock_sched() is required.
>   */
>  #define lockdep_assert_in_rcu_read_lock_sched() \
> -	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map)))
> +	WARN_ON_ONCE(lockdep_assert_rcu_helper(!lock_is_held(&rcu_sched_lock_map), RCU_SCHED))
>  
>  /**
>   * lockdep_assert_in_rcu_reader - WARN if not within some type of RCU reader
> @@ -476,17 +487,17 @@ static inline bool lockdep_assert_rcu_helper(bool c)
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
> +#define lockdep_assert_in_rcu_read_lock() __assume_shared_ctx_guard(RCU)
> +#define lockdep_assert_in_rcu_read_lock_bh() __assume_shared_ctx_guard(RCU_BH)
> +#define lockdep_assert_in_rcu_read_lock_sched() __assume_shared_ctx_guard(RCU_SCHED)
> +#define lockdep_assert_in_rcu_reader() __assume_shared_ctx_guard(RCU)
>  
>  #endif /* #else #ifdef CONFIG_PROVE_RCU */
>  
> @@ -506,11 +517,11 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>  #endif /* #else #ifdef __CHECKER__ */
>  
>  #define __unrcu_pointer(p, local)					\
> -({									\
> +context_unsafe(								\
>  	typeof(*p) *local = (typeof(*p) *__force)(p);			\
>  	rcu_check_sparse(p, __rcu);					\
> -	((typeof(*p) __force __kernel *)(local)); 			\
> -})
> +	((typeof(*p) __force __kernel *)(local)) 			\
> +)
>  /**
>   * unrcu_pointer - mark a pointer as not being RCU protected
>   * @p: pointer needing to lose its __rcu property
> @@ -586,7 +597,7 @@ static inline bool lockdep_assert_rcu_helper(bool c)
>   * other macros that it invokes.
>   */
>  #define rcu_assign_pointer(p, v)					      \
> -do {									      \
> +context_unsafe(							      \
>  	uintptr_t _r_a_p__v = (uintptr_t)(v);				      \
>  	rcu_check_sparse(p, __rcu);					      \
>  									      \
> @@ -594,7 +605,7 @@ do {									      \
>  		WRITE_ONCE((p), (typeof(p))(_r_a_p__v));		      \
>  	else								      \
>  		smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
> -} while (0)
> +)
>  
>  /**
>   * rcu_replace_pointer() - replace an RCU pointer, returning its old value
> @@ -861,9 +872,10 @@ do {									      \
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
> @@ -891,11 +903,12 @@ static __always_inline void rcu_read_lock(void)
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
> @@ -914,9 +927,11 @@ static inline void rcu_read_unlock(void)
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
> @@ -928,11 +943,13 @@ static inline void rcu_read_lock_bh(void)
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
> @@ -952,9 +969,11 @@ static inline void rcu_read_unlock_bh(void)
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
> @@ -962,9 +981,11 @@ static inline void rcu_read_lock_sched(void)
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
> @@ -973,22 +994,27 @@ static inline notrace void rcu_read_lock_sched_notrace(void)
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
>  static __always_inline void rcu_read_lock_dont_migrate(void)
> +	__acquires_shared(RCU)
>  {
>  	if (IS_ENABLED(CONFIG_PREEMPT_RCU))
>  		migrate_disable();
> @@ -996,6 +1022,7 @@ static __always_inline void rcu_read_lock_dont_migrate(void)
>  }
>  
>  static inline void rcu_read_unlock_migrate(void)
> +	__releases_shared(RCU)
>  {
>  	rcu_read_unlock();
>  	if (IS_ENABLED(CONFIG_PREEMPT_RCU))
> @@ -1041,10 +1068,10 @@ static inline void rcu_read_unlock_migrate(void)
>   * ordering guarantees for either the CPU or the compiler.
>   */
>  #define RCU_INIT_POINTER(p, v) \
> -	do { \
> +	context_unsafe( \
>  		rcu_check_sparse(p, __rcu); \
>  		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
> -	} while (0)
> +	)
>  
>  /**
>   * RCU_POINTER_INITIALIZER() - statically initialize an RCU protected pointer
> @@ -1206,4 +1233,6 @@ DEFINE_LOCK_GUARD_0(rcu,
>  	} while (0),
>  	rcu_read_unlock())
>  
> +DECLARE_LOCK_GUARD_0_ATTRS(rcu, __acquires_shared(RCU), __releases_shared(RCU))
> +
>  #endif /* __LINUX_RCUPDATE_H */
> diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
> index 77e599a9281b..f18b7252646d 100644
> --- a/lib/test_context-analysis.c
> +++ b/lib/test_context-analysis.c
> @@ -7,6 +7,7 @@
>  #include <linux/bit_spinlock.h>
>  #include <linux/build_bug.h>
>  #include <linux/mutex.h>
> +#include <linux/rcupdate.h>
>  #include <linux/seqlock.h>
>  #include <linux/spinlock.h>
>  
> @@ -277,3 +278,87 @@ static void __used test_bit_spin_lock(struct test_bit_spinlock_data *d)
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
> +static void __used test_rcu_lock_reentrant(void)
> +{
> +	rcu_read_lock();
> +	rcu_read_lock();
> +	rcu_read_lock_bh();
> +	rcu_read_lock_bh();
> +	rcu_read_lock_sched();
> +	rcu_read_lock_sched();
> +
> +	rcu_read_unlock_sched();
> +	rcu_read_unlock_sched();
> +	rcu_read_unlock_bh();
> +	rcu_read_unlock_bh();
> +	rcu_read_unlock();
> +	rcu_read_unlock();
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
> 2.52.0.rc1.455.g30608eb744-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/98453e19-7df2-43cb-8f05-87632f360028%40paulmck-laptop.
