Return-Path: <kasan-dev+bncBDV37XP3XYDRBZHITTWQKGQEUDB2H4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F003D9545
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 17:16:53 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 205sf4419128ljf.13
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 08:16:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571239012; cv=pass;
        d=google.com; s=arc-20160816;
        b=EbjYyw/ss4SgnLP5K6UXsKm6LlfrtVGv0v8tlKl5kfl0r152KAjj58qEdgir+wI5yU
         PKbPd11j4YPgpE+xxmwLNBDmvv69fjritkQbSoOKuYpDRELon122ZJYFs3dZJqzRUL2e
         jP4iBzUym1P6ws4AcZjn/ggQuLnzK+pk1ISR4aMYyi4+lvwGbXXBORokoFNxJGTd3+S8
         nBGY8PB+o3795yC4DU/lJCmijTlg39TFbjR22fe7nuzq0pAuaKI1UNPhzQG+84DYvtPM
         g7kxN3waKPefHI8emqTZAdFA80OT1Wn5Yhr1z/dyWBSHy8Cp6tn+f3KFUCy5w0xlhc3w
         jqcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=b8uv6Ys4s8lFABE8Cmhdnt/hcM9pINbB/xlgPm3Pmjc=;
        b=X5p8vbxFv2bIKs/mYYalqcW0zRgvLe7DqRddqp7W9T8XoDb47ZwP7DWYvAiL6MVLT4
         zIrJhmoS55/NK0XMN3jn7mHA3VuoOd13XWKGURv5/KZD8jKkRjbiP2ZC3miAov4CqZWB
         ayWvMbh2FDJyHuhaJ3Ujny2/CulEFa7tfogi60r0fl18zjNQQoURXZhnNHX+fsyQsoD0
         maYoTCRDrOE0pMmWEOwsE6MTMwejOUGFpu4ZnrpN4ryQpbXNGFnprNfoluB5ClXK1YNo
         1VgEnymjDOjHgZILe39WM12EfYGsAmVYR78rahHj2k/xFdmusJwxQBXbiabNjZhL5t/o
         q7WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b8uv6Ys4s8lFABE8Cmhdnt/hcM9pINbB/xlgPm3Pmjc=;
        b=Heb25I5lp0okUEWMgmcYOb90e5Q3Xmkzchn1qODrSIvSqbhHIjhoD4i2YQe8HURmv3
         yuqn7kM2QQGnc+f7ljXML2DCq2T87qKiY2j/0PIfN6RNH+6G6srU0/RQswAbMUK8VIxC
         OnuB2YDb/QIt6Z17RPMFZdmnHzwtdUUfdgwAthpAH/bZI//oS/GlRCpIRCwWyfbxxF7N
         NeQBpxArqDoSdTtJ1gm0hQSQRaeifW7lyt0NpCQtYrJCKD/9RVHIWIjw8g3hNenGxKoy
         IgMr9R0uqMdmFiuWmNvuFwz+/47JPEJnFROIYE1G+yY4XyTMwNN1Hu8DujnkLhyQliST
         Srfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b8uv6Ys4s8lFABE8Cmhdnt/hcM9pINbB/xlgPm3Pmjc=;
        b=WwuESCZSc3XKMt7Gytz7fM2j6XE/h+ZWjTWh4FBahasSZPzm9zgo5QG9m8rlQZJQCZ
         0dskQ5mI5cbU0giQt1SURZEosWb7cBDmUtGvRUWV+8zMFDKd6UuIXNJBhBCWHm9cUdNK
         WAEiYFcj0ABQ8r6NjL3aQGqtjpY2w0CxrEMiWuLxls/TSubdPPA5KL/SRxMaPS1+4JDD
         S3aJpmsrucsjjkZS9EOWrjof7dfK3/neIKuNTkxaHz733uEtDm1QDKW1ecc8u5wuYOye
         ba2uphDZlPvOZpBQrM4XaNuchiWrKsc7jm8Gd4iImbvtsTl/bJLpO3Tk09aPNy8Ovi4c
         051w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWYmSYSNyGE06hZACVDsXFXJWVNEC6cgxTGy+gHREyPPzPKGVY9
	GY6tKDrx1LmI+qz6MCjvHmQ=
X-Google-Smtp-Source: APXvYqyKs474rQQhoIwDBPPMq+pHNigWoxJjrfz7Ye8TJ4QArp0S5wM2btkRAqKbsMHRMtmflw+Eqw==
X-Received: by 2002:ac2:54b3:: with SMTP id w19mr3165649lfk.66.1571239012798;
        Wed, 16 Oct 2019 08:16:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:8c4c:: with SMTP id i12ls2057203lfj.2.gmail; Wed, 16 Oct
 2019 08:16:52 -0700 (PDT)
X-Received: by 2002:a19:c114:: with SMTP id r20mr24627389lff.7.1571239012040;
        Wed, 16 Oct 2019 08:16:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571239012; cv=none;
        d=google.com; s=arc-20160816;
        b=GsxZdHB0lWjYLZccFOuh3C0DleOC5zGSvrsB5+ttmAVEUVpItvrgmOJDC5DP8ybS5F
         XFkybE6seQxZ/izQkn8nvTXx3q+yVaym9WFcXJiwY0+Z9gu0aYk/qqDTZX0uY6s9X67Y
         ZzjdUA5ixfjHPCfecUuxV4HNkjUlY9MCiAmtmI1endNUIL0i7FLVL0F83XwlSYUjim22
         GW94DKeBiXZ3WXiaKPkVlcErimGA9kwuG5cn1rzr2xZEqp5WWqXcvn4w2cvEOLcj2zAG
         rfoijxtMq5D01myDwy5+8oTnXLAPNGq9Q5LLIbv8ilMgJ3DCQvb9z0shpMumEfVCxRe3
         4pZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=4+j9LnCYihVmRtZZZsViPejJ7e06mz+rSEUMV4JYnr8=;
        b=MdPfZVwQ1wB9KjtP3M4F6wumMK2eDjzwYXB5rjqNX5coWYwZ4XLyUYX4DJ6g14f8Ij
         52Y4VPwQoV6kz3qnyM0TSBLxmtfQoL147rpL+DFzvIY/JIllvw+GiN5TLk7/N1gUejXL
         hCltiy+LtNxUDcySCztGNplf1Ou6kcv1xWuOY9WwPHFxmMxPM6qFlatxLcjDeRgnmh4q
         WQlh/Ud1sBQJCczTHWTY8K3hfNYDGf2RpJqPhcOjnK0pbn1Cj0aVP9xUAG+FwOZo7q4p
         5fwQbuZ7dwh4WnIopEe0Ue08o5My5zdxj5cXJ7vqR9c6HwY0YKAzVBM1he/n+JcEgHrs
         Vtxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h6si1028438lfc.3.2019.10.16.08.16.51
        for <kasan-dev@googlegroups.com>;
        Wed, 16 Oct 2019 08:16:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B25BA142F;
	Wed, 16 Oct 2019 08:16:50 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F416A3F68E;
	Wed, 16 Oct 2019 08:16:45 -0700 (PDT)
Date: Wed, 16 Oct 2019 16:16:43 +0100
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
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191016151643.GC46264@lakrids.cambridge.arm.com>
References: <20191016083959.186860-1-elver@google.com>
 <20191016083959.186860-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191016083959.186860-2-elver@google.com>
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

On Wed, Oct 16, 2019 at 10:39:52AM +0200, Marco Elver wrote:
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 2c2e56bd8913..34a1d9310304 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1171,6 +1171,13 @@ struct task_struct {
>  #ifdef CONFIG_KASAN
>  	unsigned int			kasan_depth;
>  #endif
> +#ifdef CONFIG_KCSAN
> +	/* See comments at kernel/kcsan/core.c: struct cpu_state. */
> +	int				kcsan_disable;
> +	int				kcsan_atomic_next;
> +	int				kcsan_atomic_region;
> +	bool				kcsan_atomic_region_flat;
> +#endif

Should these be unsigned?

> +/*
> + * Per-CPU state that should be used instead of 'current' if we are not in a
> + * task.
> + */
> +struct cpu_state {
> +	int disable; /* disable counter */
> +	int atomic_next; /* number of following atomic ops */
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
> +static DEFINE_PER_CPU(struct cpu_state, this_state) = {
> +	.disable = 0,
> +	.atomic_next = 0,
> +	.atomic_region = 0,
> +	.atomic_region_flat = 0,
> +};

These are the same as in task_struct, so I think it probably makes sense
to have a common structure for these, e.g.

| struct kcsan_ctx {
| 	int	disable;
| 	int	atomic_next;
| 	int	atomic_region;
| 	bool	atomic_region_flat;
| };

... which you then place within task_struct, e.g.

| #ifdef CONFIG_KCSAN
| 	struct kcsan_ctx	kcsan_ctx;
| #endif

... and here, e.g.

| static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx);

That would simplify a number of cases below where you have to choose one
or the other, as you can choose the pointer, then handle the rest in a
common way.

e.g. for:

> +static inline bool is_atomic(const volatile void *ptr)
> +{
> +	if (in_task()) {
> +		if (unlikely(current->kcsan_atomic_next > 0)) {
> +			--current->kcsan_atomic_next;
> +			return true;
> +		}
> +		if (unlikely(current->kcsan_atomic_region > 0 ||
> +			     current->kcsan_atomic_region_flat))
> +			return true;
> +	} else { /* interrupt */
> +		if (unlikely(this_cpu_read(this_state.atomic_next) > 0)) {
> +			this_cpu_dec(this_state.atomic_next);
> +			return true;
> +		}
> +		if (unlikely(this_cpu_read(this_state.atomic_region) > 0 ||
> +			     this_cpu_read(this_state.atomic_region_flat)))
> +			return true;
> +	}
> +
> +	return kcsan_is_atomic(ptr);
> +}

... you could have something like:

| struct kcsan_ctx *kcsan_get_ctx(void)
| {
| 	return in_task() ? &current->kcsan_ctx : this_cpu_ptr(kcsan_cpu_ctx);
| }
|
| static inline bool is_atomic(const volatile void *ptr)
| {
| 	struct kcsan_ctx *ctx = kcsan_get_ctx();
|	if (unlikely(ctx->atomic_next > 0) {
|		--ctx->atomic_next;
| 		return true;
| 	}
| 	if (unlikely(ctx->atomic_region > 0 || ctx->atomic_region_flat))
| 		return true;
|
| 	return kcsan_is_atomic(ptr);
| }

... avoiding duplicating the checks for task/irq contexts.

It's not clear to me how either that or the original code works if a
softirq is interrupted by a hardirq. IIUC most of the fields should
remain stable over that window, since the hardirq should balance most
changes it makes before returning, but I don't think that's true for
atomic_next. Can't that be corrupted from the PoV of the softirq
handler?

[...]

> +void kcsan_begin_atomic(bool nest)
> +{
> +	if (nest) {
> +		if (in_task())
> +			++current->kcsan_atomic_region;
> +		else
> +			this_cpu_inc(this_state.atomic_region);
> +	} else {
> +		if (in_task())
> +			current->kcsan_atomic_region_flat = true;
> +		else
> +			this_cpu_write(this_state.atomic_region_flat, true);
> +	}
> +}

Assuming my suggestion above wasn't bogus, this can be:

| void kcsan_begin_atomic(boot nest)
| {
| 	struct kcsan_ctx *ctx = kcsan_get_ctx();
| 	if (nest)
| 		ctx->atomic_region++;
| 	else
| 		ctx->atomic_region_flat = true;
| }

> +void kcsan_end_atomic(bool nest)
> +{
> +	if (nest) {
> +		int prev =
> +			in_task() ?
> +				current->kcsan_atomic_region-- :
> +				(this_cpu_dec_return(this_state.atomic_region) +
> +				 1);
> +		if (prev == 0) {
> +			kcsan_begin_atomic(true); /* restore to 0 */
> +			kcsan_disable_current();
> +			WARN(1, "mismatching %s", __func__);
> +			kcsan_enable_current();
> +		}
> +	} else {
> +		if (in_task())
> +			current->kcsan_atomic_region_flat = false;
> +		else
> +			this_cpu_write(this_state.atomic_region_flat, false);
> +	}
> +}

... similarly:

| void kcsan_end_atomic(bool nest)
| {
| 	struct kcsan_ctx *ctx = kcsan_get_ctx();
| 
| 	if (nest)
| 		if (ctx->kcsan_atomic_region--) {
| 			kcsan_begin_atomic(true); /* restore to 0 */
| 			kcsan_disable_current();
| 			WARN(1, "mismatching %s"\ __func__);
| 			kcsan_enable_current();
| 		}
| 	} else {
| 		ctx->atomic_region_flat = true;
| 	}
| }

> +void kcsan_atomic_next(int n)
> +{
> +	if (in_task())
> +		current->kcsan_atomic_next = n;
> +	else
> +		this_cpu_write(this_state.atomic_next, n);
> +}

... and:

| void kcsan_atomic_nextint n)
| {
| 	kcsan_get_ctx()->atomic_next = n;
| }

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016151643.GC46264%40lakrids.cambridge.arm.com.
