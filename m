Return-Path: <kasan-dev+bncBDV37XP3XYDRBXPNQ2AAMGQEVBXD26Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA132F7FB9
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 16:38:06 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id s17sf6588710pgv.14
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 07:38:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610725085; cv=pass;
        d=google.com; s=arc-20160816;
        b=d1HqE1OZZiZPLnT6oyyZYQy2O1WzSrkcd3HEi/aTJNsMufGPjE9N/vroHPlFFcx6lv
         VRlSuQNFLTcxqxLwwRQwp5J0FqP3wtVXqIuZ98blFHxm7brk/FzeUxDW5YxahO4r15Ev
         1XsL38jOaqfKF646ebp3H98U04Eho8oTdukkI9z7pt81u0Fpt04vmyw/C9ufhdOaBUBf
         /MszpGKOk+abn/jgglhvii+RGe3Zb3w7YRl+mXHkfN8atxgl2FEJX1uLt/b9EsXhbfmL
         qr8nz79WLf4rV3X0z9w/HdTeFe5mzHYOXuDH1VYG90dkKdmanQwEMKU0XdDTQ89v6Q7p
         fZRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qUsHc7BDvq7iO3FVq8lh5PEmUGP9J36sOLByjK3Kork=;
        b=ky6B+ZliDrJAgVvdAB1pf5sivJIB16rBp7hGjG0fvIgFvVmkcHUaUvqdaq7yAzu4Gc
         FBQN03/PTujAIINePrtcLmzy2SYr8m4rIZsoMYBGpFQboegGxIFTYLrMkeDzNWOsXP8Q
         wS4lHzq1IEuDrJpM5CFEKuDbkTXrRpKtkbK9HFkfnMw0CMbf3FmkL0FIIpwB71GTUGfc
         7jd7iz8pbf3jT7CUVuBcJWHdWZFbNSMunAUJ0j/1JndV5lvOFpR/XeiZEPRmmz0rO5u2
         IQk4Vunb31Kf+CeseS81D4mZGlHvNoSjGvgANXE3yIW6CqfHNiIU95BrsBlX71tSOKks
         kjjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qUsHc7BDvq7iO3FVq8lh5PEmUGP9J36sOLByjK3Kork=;
        b=YkrDAH4eLwkzrzWxYiIHrLJbdoD6q9a8LbgdCd/mKo28lr73w/aQ+MYdWSg8NWLa4x
         Cgtb9eV3rzZmch+nFBzVuO0cp1j2hq5jWDXiGDFtwIPk3kADYU5tfzDsi+Ll1OhBo7aA
         0/fObJb6Rwymhl8fKYNm8Un9d7ztnd5y3wd6sXHJNZIZftd56zcdv0AY9H8uMGUleQfn
         cBoaYBoXwebGP4P7NvK6p06waeOWxAZjfaVhq7TH3qF5G97N0RKmE3VnhAN32DuUxkFV
         rOtXkjMV0VjH8srb6jdwvGOaeAKqi4zKDSQjLRO8smvIV/RS4wPXgOxyf6y7+4sNLCdf
         Cypw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qUsHc7BDvq7iO3FVq8lh5PEmUGP9J36sOLByjK3Kork=;
        b=skNmPDafCbH1ztUESmJ6UL/WAPamJPj4UVGuu2e4sNUTodsMMjzGhgz0x9/+K2Ax76
         sfwhgLMuEIKFt99/lC0ZcgwiCTUb4HkSnA1ehRiCi22aIE9EzHlLyZ4HTllYVBUYhDpG
         v1RMwMMiAe3LdxYKyzWGxApGGMI118FVhRcYbWUwv3BmCNFcFbmYsxY1FCU4Gg8X40am
         YLTv9BgK72NmpXq8/iGAMSsyd5Mozfo7Po/sidYYnpAbPWTF+rSSRqAYT6hvJ8o2rE6I
         QxixdYYbA40RgeeKcu5cslutIMmOt1UCDdi0SGS4dIVfypsid8gihvHlelHznf2Ns0NQ
         wO4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RC9ch4PN6gUUWp2AtZZ0YjClWPxpUO/CwU18QGJ+du2lPG00y
	1iBr5A1pn8GMEbD7iQI0O9I=
X-Google-Smtp-Source: ABdhPJwkIldu5F7WiPwfJq4kPhHYU+mIWWsnYgETSIwBrfxikdj1F6hs3rJtBjEsDavAgHB6j2s7Nw==
X-Received: by 2002:a17:90b:358d:: with SMTP id mm13mr692153pjb.146.1610725085209;
        Fri, 15 Jan 2021 07:38:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls4748597pjz.1.canary-gmail;
 Fri, 15 Jan 2021 07:38:04 -0800 (PST)
X-Received: by 2002:a17:90a:8043:: with SMTP id e3mr11521851pjw.20.1610725084469;
        Fri, 15 Jan 2021 07:38:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610725084; cv=none;
        d=google.com; s=arc-20160816;
        b=d8QF5vGxuuZxUQfj8F4JeETIfZ0iuIXClYPkbkGHCm7QnjJa91XSDfVFYJ0zlXItaT
         0YJZl7I1y70EDljSFzFiaLpaS5RleSOGVH0nEwocwGQEQS9WRmJP2vlkEZTBHz8ep+W2
         KfvLu+zuAgxSNBnkTg6D9rRmy0iDYRnW70puKKpie49NH41ZTUOM22CsKJVHGRCr0EYS
         nem71TqVXju5Kkp2VkZSO63fUehHvax0UAAZlRnQ1AbSNkO5bqF18NIeAexmBjtxL+J8
         9kWmvpJmOma367ygp66630HEo0I6rGFwMy4eRmJsrgaVQSlnE5i4Jb4+5MBrZSqtLOLr
         kLAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=8RXNpRC583yd5Gcjg0wddp+8OqFE+U0T/5GkS45Daac=;
        b=DUhnTPgQE9c6F6pvEDmKCd19hFURJaY8n9Ts9LsEVfGPPzg12BelGnpX0mZ2ZXFjPY
         J0XO4Jg8w97C0PuBcMim78lC37mgegPudK3puUH/YQYy7GKX5hRMVoF8M1A+Q8qs5yPG
         numyggblqasS8KTvkRGMe/H5mk3jOClQeb0PW1grG0PLRW3IFC097dd4kTh+pKEDBYTv
         81cxiUsXSUD5Or94rbK1dW8qm1DYm6ICxwujG7EePsyFAJNkz2re8I9JmWp5LD2DyzE7
         6WOMTYD7ujPw5cAqFoXO/F2Snw1wr/gcCi+Y30huclPMtaF20IayEujdXejQNVsj1Aj1
         Rt/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ce15si783850pjb.3.2021.01.15.07.38.04
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 07:38:04 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D0E60D6E;
	Fri, 15 Jan 2021 07:38:03 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.41.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7F28C3F70D;
	Fri, 15 Jan 2021 07:37:59 -0800 (PST)
Date: Fri, 15 Jan 2021 15:37:56 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
Message-ID: <20210115153756.GC44111@C02TD0UTHF1T.local>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-4-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210115120043.50023-4-vincenzo.frascino@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Jan 15, 2021 at 12:00:42PM +0000, Vincenzo Frascino wrote:
> MTE provides a mode that asynchronously updates the TFSR_EL1 register
> when a tag check exception is detected.
> 
> To take advantage of this mode the kernel has to verify the status of
> the register at:
>   1. Context switching
>   2. Return to user/EL0 (Not required in entry from EL0 since the kernel
>   did not run)
>   3. Kernel entry from EL1
>   4. Kernel exit to EL1
> 
> If the register is non-zero a trace is reported.
> 
> Add the required features for EL1 detection and reporting.
> 
> Note: ITFSB bit is set in the SCTLR_EL1 register hence it guaranties that
> the indirect writes to TFSR_EL1 are synchronized at exception entry to
> EL1. On the context switch path the synchronization is guarantied by the
> dsb() in __switch_to().
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h     | 21 +++++++++++++++++++
>  arch/arm64/kernel/entry-common.c | 11 ++++++++++
>  arch/arm64/kernel/mte.c          | 35 ++++++++++++++++++++++++++++++++
>  3 files changed, 67 insertions(+)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index d02aff9f493d..1a715963d909 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -92,5 +92,26 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>  
>  #endif /* CONFIG_ARM64_MTE */
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void mte_check_tfsr_el1_no_sync(void);
> +static inline void mte_check_tfsr_el1(void)
> +{
> +	mte_check_tfsr_el1_no_sync();
> +	/*
> +	 * The asynchronous faults are synch'ed automatically with

Nit: can we please use "sync" rather than "synch", to match what we do
elsewhere, e.g. mte_check_tfsr_el1_no_sync immediately above. The
inconsistency is unfortunate and distracting.

> +	 * TFSR_EL1 on kernel entry but for exit an explicit dsb()
> +	 * is required.
> +	 */
> +	dsb(ish);
> +}

Did you mean to have the barrier /before/ checking the TFSR? I'm
confused as to why it's after the check if the point of it is to ensure
that TFSR has been updated.

I don't understand this difference between the entry/exit paths; are you
relying on a prior DSB in the entry path?

Is the DSB alone sufficient to update the TFSR (i.e. is an indirect
write ordered before a direct read)? ... or do you need a DSB + ISB
here?

It's probably worth a comment as to why the ISH domain is correct here
rather than NSH or SY. I'm not entirely certain if ISH is necessary or
sufficient, but it depends on the completion rules.

[...]

> >  
>  /*
> @@ -47,6 +49,13 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
>  {
>  	lockdep_assert_irqs_disabled();
>  
> +	/*
> +	 * The dsb() in mte_check_tfsr_el1() is required to relate
> +	 * the asynchronous tag check fault to the context in which
> +	 * it happens.
> +	 */
> +	mte_check_tfsr_el1();

I think this comment is misplaced, given that mte_check_tfsr_el1() isn't
even in the same file.

If you need to do different things upon entry/exit, I'd rather we had
separate functions, e.g.

* mte_check_tfsr_entry();
* mte_check_tfsr_exit();

... since then it's immediately obvious in context as to whether we're
using the right function, and then we can have a comment within each of
the functions explaining what we need to do in that specific case.

>  	if (interrupts_enabled(regs)) {
>  		if (regs->exit_rcu) {
>  			trace_hardirqs_on_prepare();
> @@ -243,6 +252,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
>  
>  asmlinkage void noinstr exit_to_user_mode(void)
>  {
> +	mte_check_tfsr_el1();
> +
>  	trace_hardirqs_on_prepare();
>  	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
>  	user_enter_irqoff();
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index df7a1ae26d7c..6cb92e9d6ad1 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -180,6 +180,32 @@ void mte_enable_kernel(enum kasan_hw_tags_mode mode)
>  	isb();
>  }
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void mte_check_tfsr_el1_no_sync(void)
> +{
> +	u64 tfsr_el1;
> +
> +	if (!system_supports_mte())
> +		return;
> +
> +	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
> +
> +	/*
> +	 * The kernel should never hit the condition TF0 == 1
> +	 * at this point because for the futex code we set
> +	 * PSTATE.TCO.
> +	 */

I thing it's worth spelling out what TF0 == 1 means, e.g.

	/*
	 * The kernel should never trigger an asynchronous fault on a
	 * TTBR0 address, so we should never see TF0 set.
	 * For futexes we disable checks via PSTATE.TCO.
	 */

... what about regular uaccess using LDTR/STTR? What happens for those?

> +	WARN_ON(tfsr_el1 & SYS_TFSR_EL1_TF0);

It's probably worth giving this a message so that we can debug it more
easily, e.g.

	WARN(tfsr_el1 & SYS_TFSR_EL1_TF0,
	     "Kernel async tag fault on TTBR0 address");

> +	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {

It might be worth wrapping this with an unlikely(), given we hope this
never happens.

Thanks,
Mark.

> +		write_sysreg_s(0, SYS_TFSR_EL1);
> +		isb();
> +
> +		pr_err("MTE: Asynchronous tag exception detected!");
> +	}
> +}
> +#endif
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>  	/* ISB required for the kernel uaccess routines */
> @@ -245,6 +271,15 @@ void mte_thread_switch(struct task_struct *next)
>  	/* avoid expensive SCTLR_EL1 accesses if no change */
>  	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
>  		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
> +
> +	/*
> +	 * Check if an async tag exception occurred at EL1.
> +	 *
> +	 * Note: On the context switch path we rely on the dsb() present
> +	 * in __switch_to() to guarantee that the indirect writes to TFSR_EL1
> +	 * are synchronized before this point.
> +	 */
> +	mte_check_tfsr_el1_no_sync();
>  }
>  
>  void mte_suspend_exit(void)
> -- 
> 2.30.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115153756.GC44111%40C02TD0UTHF1T.local.
