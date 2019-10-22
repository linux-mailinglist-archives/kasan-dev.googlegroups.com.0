Return-Path: <kasan-dev+bncBDV37XP3XYDRBA44XTWQKGQEMFFYCNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 63A81E060D
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 16:11:16 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id p18sf2991395ljn.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 07:11:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571753476; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZroGL7W/UP9UdSwke4h2v1ysP6qB1iJ/lTO3kTCP3qbITmnYeO7wIzVpyxeeOmCKpy
         hw4UrJgS3OccVlJAzJM7jlxqBLGm7r4yvEHMvX7IUEl2UxWKLDmhEOhp/GzK/GcaltyQ
         jewqCoRG2mRmdFB9Pw+wbsZYbsRZvdeYjiZSyZCdP98ISmlnKUtMbZCjZbU5kGFUMGqX
         lUSTvzC68as8IxMxPjr0jctK14e9njPyzlaGQzUQAq8H+8TeLF0eBWgXFD1ieZBCqqBn
         p9j7e4fnQ9Fm92L6KIjgXB8KFkCzH0vSK3T27xF/2pTTWJiD446ooYwvuN36ANAS7ZxE
         m6ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OZX7bVKAhjScProI5Kefv6VW2yqVdG/z2wqweEzsBGw=;
        b=uogr7w1/i7G48+Xzg6AO0O5hw/lxKoCNtX5FqNFarV8eRYZJpuBjKSpjDtzO9F6d2e
         NcysHg6bEECZAxxaccQWlsprjWu8nCpHYRQ7j9hQNEi4y3qhKQ5TpF1gYHoa1dba7tpd
         XejWu25vJDMblL7p2BNAwVSfR+k9qiYvSxxEpjumAMfQe6O6XMoqtcNafUZ8pHz/ccAS
         nxS6V8XAlke0ykkIOmzuEadgYy0/0cDPhqOVhTio1KAbww7G/CXBTQp4AJe0ugvuNygS
         qkQK+bgGylBtX38fc1RKMFOJEI7Dr80oT5OelcBGUjz4qPjKrFRjJQAXKamCBK3KuHkA
         LBdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OZX7bVKAhjScProI5Kefv6VW2yqVdG/z2wqweEzsBGw=;
        b=Fz/FJq1C0W0tROmPVwrUPaOYKTxpMaalVhu1J9/ctv3y/Ca7G1HiAmYFCj73emcwwx
         fZwZVH77G9+6IPu7kI5Yd6UnOE388uQZL8jAH/IaTEnzIYSTWzEiUbFdcT+TZ+q6i1cJ
         bnEgx0lRPn6NrfHt9OxC7okWTcOugVSZT1q/tw2q9PI/QF8lG50hvdw35N2n1c+KbA2w
         lOjAuvpUeQb2Zj5jL6omvUczg6ROtrnVswqKvS6r4Zr4Gmr1nmBen2rI2y9pN8sDOsQU
         yoABhhQVzjgtCcYA9lZqmChT6lDVtFQYujsaU3gkMSEsiNCSFmAJuk/v5sGreu5+rT58
         6+1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OZX7bVKAhjScProI5Kefv6VW2yqVdG/z2wqweEzsBGw=;
        b=uQIi4wUpQfBbkS6z3LzVnZHIhL0FcCfSuGRfIi4nH2pfcA7teViy8NHlczocpsF65T
         kKULgBoW/ne6Dw7d0XagWClLnTOSHZ5YPx8dFctGo6beWK6iVGOEsV5yVvmA3I5f3FSE
         ca4gQir/tnzx9hzVCV0Zzth2fIhwDAMMRSEEjHr2h4B3tEyAbih8SqhdXtlOkCuDVkmj
         CM67pkEmpHiy3d6/rje2T+2Xt++ak/cGWbeUIEyLb3A5xdobUpxvvO1m28Xdmz0f2Sa+
         hEKIYjlmY+d3cbPrBtjrRa44n8YapjeHcEJ/9/0nC2cDcdZxCBcvt8RlIS5DNqdfmWXo
         mlMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7z/uck4PIRd8Fk5DRBHSM/mfA5miNlMO9180CgPetyCw0XA/I
	t4QRx7L0Gweow3GE4Qr8Vjw=
X-Google-Smtp-Source: APXvYqwGl6IPP9aFdcjgSc8VRo9yFcoECvRjRi+GYAjRlfrn6O3l/jCNCgNG/YlsjYCO/3SKRxBRcw==
X-Received: by 2002:a2e:9d56:: with SMTP id y22mr18991735ljj.37.1571753475846;
        Tue, 22 Oct 2019 07:11:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8915:: with SMTP id d21ls2051145lji.0.gmail; Tue, 22 Oct
 2019 07:11:15 -0700 (PDT)
X-Received: by 2002:a2e:5dd5:: with SMTP id v82mr19040522lje.54.1571753475067;
        Tue, 22 Oct 2019 07:11:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571753475; cv=none;
        d=google.com; s=arc-20160816;
        b=vaRyE0jBx3ce9rVLssK2z6bqli1RFS07mYETfJ7h9aX+xoUolLqcharV2yUrr0ZSSa
         C5CCXAR88TpQsZ3ywSlmEZujDqzeWNa/IB0PYOlSBo27mYPWSEAt6jsTAbm+vy3jFsll
         P0pRVDR+5vqLD4taWNTxMwnKMQzlB1zKd7uMnF3h5Mvb+GZ+1UEwoqEzLzeryG2wC7hz
         TzyUYy5GPly6HSukSg5DNBVqrPdhpwY9Yxxbnz2KLzIMOaG3JumEyWPAilasVUgJBUR7
         UGycYCgm5f7FF3sPWa9WHNjJMDMgFRvkKvVJDDP2fInAdVSHAH1pDKsKN60BhfLI23/Q
         iquA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Cl9G/9ScgaRqR3zKYvT4k9g56lboQumH42lfnYTLfRw=;
        b=vzGvcTWLJ2GxO7ibBJmd1GkL87CTYArF6Tj8Kfky/deS4I1DrXZbBgrc3z4ojHELHJ
         2z0mhrVWLy6XN427o0B3KiAXNe2xfa272bBXoQkZjQXoYVsk5S/T5iLWZ1VRVit5malS
         hXrGFmoi/smfoXgGg4ygeld2hFST1PG52EEB3uO9Q37ykhwjRu1ojMyzmxCd1nhEsrde
         tuzKQn8vTu4TlgHh6SCt1TnTNxm5lPw0BHmw81GjwkxHeBX8vCmCbtA1N8UYfVenlfrb
         D2WiQX3Z/Hgcade1icq6bms0NGvhPl/SFL+exuRkUYOKmuKodgqHS1SdX4pZMcydWqv1
         BNlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com ([217.140.110.172])
        by gmr-mx.google.com with ESMTP id z9si1296099ljj.4.2019.10.22.07.11.13
        for <kasan-dev@googlegroups.com>;
        Tue, 22 Oct 2019 07:11:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 97B851764;
	Tue, 22 Oct 2019 07:11:10 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5E6AC3F71A;
	Tue, 22 Oct 2019 07:11:06 -0700 (PDT)
Date: Tue, 22 Oct 2019 15:11:04 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, npiggin@gmail.com,
	paulmck@linux.ibm.com, peterz@infradead.org, tglx@linutronix.de,
	will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191022141103.GE11583@lakrids.cambridge.arm.com>
References: <20191017141305.146193-1-elver@google.com>
 <20191017141305.146193-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191017141305.146193-2-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

Hi Marco,

On Thu, Oct 17, 2019 at 04:12:58PM +0200, Marco Elver wrote:
> Kernel Concurrency Sanitizer (KCSAN) is a dynamic data-race detector for
> kernel space. KCSAN is a sampling watchpoint-based data-race detector.
> See the included Documentation/dev-tools/kcsan.rst for more details.
> 
> This patch adds basic infrastructure, but does not yet enable KCSAN for
> any architecture.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Elaborate comment about instrumentation calls emitted by compilers.
> * Replace kcsan_check_access(.., {true, false}) with
>   kcsan_check_{read,write} for improved readability.
> * Change bug title of race of unknown origin to just say "data-race in".
> * Refine "Key Properties" in kcsan.rst, and mention observed slow-down.
> * Add comment about safety of find_watchpoint without user_access_save.
> * Remove unnecessary preempt_disable/enable and elaborate on comment why
>   we want to disable interrupts and preemptions.
> * Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
>   contexts [Suggested by Mark Rutland].

This is generally looking good to me.

I have a few comments below. Those are mostly style and naming things to
minimize surprise, though I also have a couple of queries (nested vs
flat atomic regions and the number of watchpoints).

[...]

> diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
> new file mode 100644
> index 000000000000..fd5de2ba3a16
> --- /dev/null
> +++ b/include/linux/kcsan.h
> @@ -0,0 +1,108 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef _LINUX_KCSAN_H
> +#define _LINUX_KCSAN_H
> +
> +#include <linux/types.h>
> +#include <linux/kcsan-checks.h>
> +
> +#ifdef CONFIG_KCSAN
> +
> +/*
> + * Context for each thread of execution: for tasks, this is stored in
> + * task_struct, and interrupts access internal per-CPU storage.
> + */
> +struct kcsan_ctx {
> +	int disable; /* disable counter */

Can we call this disable_count? That would match the convention used for
preempt_count, and make it clear this isn't a boolean.

> +	int atomic_next; /* number of following atomic ops */

I'm a little unclear on why we need this given the begin ... end
helpers -- isn't knowing that we're in an atomic region sufficient?

> +
> +	/*
> +	 * We use separate variables to store if we are in a nestable or flat
> +	 * atomic region. This helps make sure that an atomic region with
> +	 * nesting support is not suddenly aborted when a flat region is
> +	 * contained within. Effectively this allows supporting nesting flat
> +	 * atomic regions within an outer nestable atomic region. Support for
> +	 * this is required as there are cases where a seqlock reader critical
> +	 * section (flat atomic region) is contained within a seqlock writer
> +	 * critical section (nestable atomic region), and the "mismatching
> +	 * kcsan_end_atomic()" warning would trigger otherwise.
> +	 */
> +	int atomic_region;
> +	bool atomic_region_flat;
> +};

I think we need to introduce nestability and flatness first. How about:

	/*
	 * Some atomic sequences are flat, and cannot contain another
	 * atomic sequence. Other atomic sequences are nestable, and may
	 * contain other flat and/or nestable sequences.
	 *
	 * For example, a seqlock writer critical section is nestable
	 * and may contain a seqlock reader critical section, which is
	 * flat.
	 *
	 * To support this we track the depth of nesting, and whether
	 * the leaf level is flat.
	 */
	int atomic_nest_count;
	bool in_flat_atomic;

That said, I'm not entirely clear on the distinction. Why would nesting
a reader within another reader not be legitimate?

> +
> +/**
> + * kcsan_init - initialize KCSAN runtime
> + */
> +void kcsan_init(void);
> +
> +/**
> + * kcsan_disable_current - disable KCSAN for the current context
> + *
> + * Supports nesting.
> + */
> +void kcsan_disable_current(void);
> +
> +/**
> + * kcsan_enable_current - re-enable KCSAN for the current context
> + *
> + * Supports nesting.
> + */
> +void kcsan_enable_current(void);
> +
> +/**
> + * kcsan_begin_atomic - use to denote an atomic region
> + *
> + * Accesses within the atomic region may appear to race with other accesses but
> + * should be considered atomic.
> + *
> + * @nest true if regions may be nested, or false for flat region
> + */
> +void kcsan_begin_atomic(bool nest);
> +
> +/**
> + * kcsan_end_atomic - end atomic region
> + *
> + * @nest must match argument to kcsan_begin_atomic().
> + */
> +void kcsan_end_atomic(bool nest);
> +

Similarly to the check_{read,write}() naming, could we get rid of the
bool argument and split this into separate nestable and flat functions?

That makes it easier to read in-context, e.g.

	kcsan_nestable_atomic_begin();
	...
	kcsan_nestable_atomic_end();

... has a more obvious meaning than:

	kcsan_begin_atomic(true);
	...
	kcsan_end_atomic(true);

... and putting the begin/end at the end of the name makes it easier to
spot the matching pair.

[...]

> +static inline bool is_enabled(void)
> +{
> +	return READ_ONCE(kcsan_enabled) && get_ctx()->disable == 0;
> +}

Can we please make this kcsan_is_enabled(), to avoid confusion with
IS_ENABLED()?

> +static inline unsigned int get_delay(void)
> +{
> +	unsigned int max_delay = in_task() ? CONFIG_KCSAN_UDELAY_MAX_TASK :
> +					     CONFIG_KCSAN_UDELAY_MAX_INTERRUPT;
> +	return IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
> +		       ((prandom_u32() % max_delay) + 1) :
> +		       max_delay;
> +}
> +
> +/* === Public interface ===================================================== */
> +
> +void __init kcsan_init(void)
> +{
> +	BUG_ON(!in_task());
> +
> +	kcsan_debugfs_init();
> +	kcsan_enable_current();
> +#ifdef CONFIG_KCSAN_EARLY_ENABLE
> +	/*
> +	 * We are in the init task, and no other tasks should be running.
> +	 */
> +	WRITE_ONCE(kcsan_enabled, true);
> +#endif

Where possible, please use IS_ENABLED() rather than ifdeffery for
portions of functions like this, e.g.

	/*
	 * We are in the init task, and no other tasks should be running.
	 */
	if (IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE))
		WRITE_ONCE(kcsan_enabled, true);

That makes code a bit easier to read, and ensures that the code always
gets build coverage, so it's less likely that code changes will
introduce a build failure when the option is enabled.

[...]

> +#ifdef CONFIG_KCSAN_DEBUG
> +	kcsan_disable_current();
> +	pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
> +	       is_write ? "write" : "read", size, ptr,
> +	       watchpoint_slot((unsigned long)ptr),
> +	       encode_watchpoint((unsigned long)ptr, size, is_write));
> +	kcsan_enable_current();
> +#endif

This can use IS_ENABLED(), e.g.

	if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
		kcsan_disable_current();
		pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
		       is_write ? "write" : "read", size, ptr,
		       watchpoint_slot((unsigned long)ptr),
		       encode_watchpoint((unsigned long)ptr, size, is_write));
		kcsan_enable_current();
	}

[...]
> +#ifdef CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> +		kcsan_report(ptr, size, is_write, smp_processor_id(),
> +			     kcsan_report_race_unknown_origin);
> +#endif

This can also use IS_ENABLED().

[...]

> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> new file mode 100644
> index 000000000000..429479b3041d
> --- /dev/null
> +++ b/kernel/kcsan/kcsan.h
> @@ -0,0 +1,140 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef _MM_KCSAN_KCSAN_H
> +#define _MM_KCSAN_KCSAN_H
> +
> +#include <linux/kcsan.h>
> +
> +/*
> + * Total number of watchpoints. An address range maps into a specific slot as
> + * specified in `encoding.h`. Although larger number of watchpoints may not even
> + * be usable due to limited thread count, a larger value will improve
> + * performance due to reducing cache-line contention.
> + */
> +#define KCSAN_NUM_WATCHPOINTS 64

Is there any documentation as to how 64 was chosen? It's fine if it's
arbitrary, but it would be good to know either way.

I wonder if this is something that might need to scale with NR_CPUS (or
nr_cpus).

> +enum kcsan_counter_id {
> +	/*
> +	 * Number of watchpoints currently in use.
> +	 */
> +	kcsan_counter_used_watchpoints,

Nit: typically enum values are capitalized (as coding-style.rst says).
That helps to make it clear each value is a constant rather than a
variable. Likewise for the other enums here.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191022141103.GE11583%40lakrids.cambridge.arm.com.
