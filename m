Return-Path: <kasan-dev+bncBDV37XP3XYDRBPV7TKPAMGQEQQ3THUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A6D666DE83
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 14:16:47 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf11726426lfb.22
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 05:16:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673961406; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZNe7QkJa0NAhqFoZ+ATYqETte19bsD61Sc/zwbdZsmzQaV99JZc6ZsKgdSXjQOe4g8
         s6kZKViXTtvIgJZjSZ5zUDOPUnJBs2j8jjPn/d6j08kzhlEyFYdETcSJfuRTh+krha+Q
         gpY7XCRLoghcfOgbEapjMU0yT3U6knqkr4hTBJOEnSmStNrhPCV7RJ1pWaiX0o8RiAzi
         f/vww77xJMf6DsM8K1DQ6D6UFauN5/2ZLiYmfnQk91LOvM1aFsb6bw/1z57HuUSs4U75
         svWmu3qEqG0NWLJp1YmAyKVi8ajKMbiWHQfoPAgscqlG169kt3GbwkqWHaWeWuv5Y9Kv
         EL1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zHP9G6A87NtRs3k1JH7Bg8RkWoAW0ONd00LhA7vCN6A=;
        b=Pr0Fi2ZNuFHQpnFbB9e18fwz9jAQQsOI8WEVw1ZCYPC3ShmjsXwMjnbWuwjTMG6Psa
         r5wkqw0Yn5errrHBd3VwY15EhhH+vPaZaRk7e49dP/wmDrDpQXMrDH8KFclUp7lADu0x
         tAAzD+UdJab5tjlViJE8r9M9/wzfb/qGT3++P1U8Nq71sTDnhlOYSAPX44YMLgHnbWin
         ip+2mRQnMc8ziBoEFdmLyxv547DRIPDvKw0m3K3X4KH/iIjA8GPIh/0Oc3TJUhPbFLWM
         TOuyvap8SvrmSQeYprY4fO5wQNOMd9mKdukvKJBH5h8sY69I2B2ECGjBa3oo8V2cioMg
         0PzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zHP9G6A87NtRs3k1JH7Bg8RkWoAW0ONd00LhA7vCN6A=;
        b=ci4Ktqbc9xKYJU7Deob1MydytB+c9HtuScTrE1ic0LxkglTZXlsdhlpZk6ce5wkvjc
         k+HOyGfKW3aL0tbcSl8Qt5vr2A3aSFi/UVNbjYQqfnKZ3v6wDfebB/lrebeT561Rf5nR
         WB8i28wG/zkU5AD7nakZsaCa1dxOUfwCI3vKsSKOjC9GcLDz1GDwCtXoC2nJHgS9gnPi
         vf3KuoTnSmI0T2pMCzzVU5B/Qxk/VALx2SZVjDXVpsqDXJiuwD9oP18c9Uu4IEPgPMST
         W4KfU9JTYzyQ707qRO+dO/XrDwsgOZq3VOpRNdooEcDJFNwZz43V+TgE7cKSdGObXNZ1
         qW9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zHP9G6A87NtRs3k1JH7Bg8RkWoAW0ONd00LhA7vCN6A=;
        b=pXwwhBsVBaFJKx98c5tLH3ikYghMk72QkdHtDpogrwMO4xKIZn0aGN065uhI7MAvPn
         JV1Gym+L/0XBST8BkCi2KDxfTbsOvS2PmQPdYUrV5fLWDvBT2uSXZD5rdZfEWL5apOYI
         3dS++4L2iaLOcR8iyu/bnCAyDMzUSGbp5mVL3Ka0Mi9PRhuwCaKbzKzBFaFP4iTNbSeX
         nXt5dwKloU72jt8YEFAJgpHbRy0vRvu55R07ITUElR7vHqUScKPjEWH6lA7Pi8KYiVwe
         hUhH2LUhcxvO8uvHfGCtGHzM9dAFbjeLWteGTOw7PKrmQaYAbRtOxTEIXaV8dkBBAbiQ
         8Oxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koYqSX5OjTqAPWl6wYhih+/0HXB+SVxHJbIaWbVCeYujxyR5YYz
	g/mIaYMgUX0XyaABNntTcTA=
X-Google-Smtp-Source: AMrXdXs9DkNuwc7TZkWc0iRm2JxMcuhz3NNTUcYPvUdBFtwFLUWeaRI0QbDtxgdM3jh5Q6fCl9Xs0A==
X-Received: by 2002:a2e:6e0c:0:b0:27a:b66:aa7b with SMTP id j12-20020a2e6e0c000000b0027a0b66aa7bmr253978ljc.246.1673961406634;
        Tue, 17 Jan 2023 05:16:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9205:0:b0:277:4af7:14ea with SMTP id k5-20020a2e9205000000b002774af714eals37976ljg.2.-pod-prod-gmail;
 Tue, 17 Jan 2023 05:16:45 -0800 (PST)
X-Received: by 2002:a2e:9250:0:b0:281:956:67 with SMTP id v16-20020a2e9250000000b0028109560067mr847425ljg.19.1673961404967;
        Tue, 17 Jan 2023 05:16:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673961404; cv=none;
        d=google.com; s=arc-20160816;
        b=iT3pYPI0QWDgW/vC1vPCDXeNDwvow7vp47Jd14iwsQD6FOe9G65zeJgg/yxibDD4Ms
         Yl1x5rqDgGjKgs7nO9m7vMXP1TXXtBrwunLzsArRyuDy1CdtWB0AJJr6eEKZr6dXXeEy
         bHJUBsMhh0WsCiUxz7ir9iLDS0yJ33rkPCZKl1eABBnck3uMdJaMHSkSnktCt8pRm3zX
         LU7OcJEguFnGSxFFsifdvZYG/oXkiqHsHoEQQ1VlUoAsuyZxmhAhK0snUazKzAk+0Yix
         cYomaVoy4QJix542hBN4mA0t26/flGSnA8gl1koh/7KFOOqCt0iUfx3cZ7uUs9bsVJk7
         GmDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=XBR2j2WobSI/ezrkv6zcggGb+f68YhK+NbVBn7so8co=;
        b=N9YadceduqDG2bXzs3HU5T3Fn/gcPTAtt/vTV4+VtZjs10LYwKHJV2wqKWfpjCQZAM
         Fd4iQYN7iSsb5Sj+0QdSS3QJabKsjuQRdgYPBlLATfZcIaLN5K+uoRp4TTKy72WCt6LT
         S+h+nPezse/ABucgAHSckuwFEsLh3fzv27ZJ1c/ZrcW9/oWph2uM+FNN7CgB1eh+ddBy
         LFSaR9XKuaMw0MkFKew4aY0IZYbCtouW/7VACQbfnObKoUPbAo97CNkIQ9iY59ZwN0fR
         YiGrEHsqVigItic0Pqr2gy1hlZdT/iZK4j8TRgxls7tr7yZNWmeTuZXUhi8Md7LMbjv5
         kF9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id k11-20020a2eb74b000000b0028b7cc84addsi326890ljo.2.2023.01.17.05.16.44
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Jan 2023 05:16:44 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F26A02B;
	Tue, 17 Jan 2023 05:17:25 -0800 (PST)
Received: from FVFF77S0Q05N.cambridge.arm.com (FVFF77S0Q05N.cambridge.arm.com [10.1.31.153])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 223C03F67D;
	Tue, 17 Jan 2023 05:16:27 -0800 (PST)
Date: Tue, 17 Jan 2023 13:16:21 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	nsekhar@ti.com, brgl@bgdev.pl, ulli.kroll@googlemail.com,
	linus.walleij@linaro.org, shawnguo@kernel.org,
	Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de,
	festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com,
	khilman@kernel.org, krzysztof.kozlowski@linaro.org,
	alim.akhtar@samsung.com, catalin.marinas@arm.com, will@kernel.org,
	guoren@kernel.org, bcain@quicinc.com, chenhuacai@kernel.org,
	kernel@xen0n.name, geert@linux-m68k.org, sammy@sammy.net,
	monstr@monstr.eu, tsbogend@alpha.franken.de, dinguyen@kernel.org,
	jonas@southpole.se, stefan.kristiansson@saunalahti.fi,
	shorne@gmail.com, James.Bottomley@hansenpartnership.com,
	deller@gmx.de, mpe@ellerman.id.au, npiggin@gmail.com,
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
	palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
	gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, alexander.shishkin@linux.intel.com,
	jolsa@kernel.org, namhyung@kernel.org, jgross@suse.com,
	srivatsa@csail.mit.edu, amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, andersson@kernel.org,
	konrad.dybcio@linaro.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	mhiramat@kernel.org, frederic@kernel.org, paulmck@kernel.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-samsung-soc@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org,
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org,
	linux-mips@vger.kernel.org, openrisc@lists.librecores.org,
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
	linux-um@lists.infradead.org, linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 00/51] cpuidle,rcu: Clean up the mess
Message-ID: <Y8afpbHtDOqAHq9M@FVFF77S0Q05N.cambridge.arm.com>
References: <20230112194314.845371875@infradead.org>
 <Y8WCWAuQSHN651dA@FVFF77S0Q05N.cambridge.arm.com>
 <Y8Z31UbzG3LJgAXE@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y8Z31UbzG3LJgAXE@hirez.programming.kicks-ass.net>
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

On Tue, Jan 17, 2023 at 11:26:29AM +0100, Peter Zijlstra wrote:
> On Mon, Jan 16, 2023 at 04:59:04PM +0000, Mark Rutland wrote:
> 
> > I'm sorry to have to bear some bad news on that front. :(
> 
> Moo, something had to give..
> 
> 
> > IIUC what's happenign here is the PSCI cpuidle driver has entered idle and RCU
> > is no longer watching when arm64's cpu_suspend() manipulates DAIF. Our
> > local_daif_*() helpers poke lockdep and tracing, hence the call to
> > trace_hardirqs_off() and the RCU usage.
> 
> Right, strictly speaking not needed at this point, IRQs should have been
> traced off a long time ago.

True, but there are some other calls around here that *might* end up invoking
RCU stuff (e.g. the MTE code).

That all needs a noinstr cleanup too, which I'll sort out as a follow-up.

> > I think we need RCU to be watching all the way down to cpu_suspend(), and it's
> > cpu_suspend() that should actually enter/exit idle context. That and we need to
> > make cpu_suspend() and the low-level PSCI invocation noinstr.
> > 
> > I'm not sure whether 32-bit will have a similar issue or not.
> 
> I'm not seeing 32bit or Risc-V have similar issues here, but who knows,
> maybe I missed somsething.

I reckon if they do, the core changes here give us the infrastructure to fix
them if/when we get reports.

> In any case, the below ought to cure the ARM64 case and remove that last
> known RCU_NONIDLE() user as a bonus.

The below works for me testing on a Juno R1 board with PSCI, using defconfig +
CONFIG_PROVE_LOCKING=y + CONFIG_DEBUG_LOCKDEP=y + CONFIG_DEBUG_ATOMIC_SLEEP=y.
I'm not sure how to test the LPI / FFH part, but it looks good to me.

FWIW:

Reviewed-by: Mark Rutland <mark.rutland@arm.com>
Tested-by: Mark Rutland <mark.rutland@arm.com>

Sudeep, would you be able to give the LPI/FFH side a spin with the kconfig
options above?

Thanks,
Mark.

> 
> ---
> diff --git a/arch/arm64/kernel/cpuidle.c b/arch/arm64/kernel/cpuidle.c
> index 41974a1a229a..42e19fff40ee 100644
> --- a/arch/arm64/kernel/cpuidle.c
> +++ b/arch/arm64/kernel/cpuidle.c
> @@ -67,10 +67,10 @@ __cpuidle int acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
>  	u32 state = lpi->address;
>  
>  	if (ARM64_LPI_IS_RETENTION_STATE(lpi->arch_flags))
> -		return CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM(psci_cpu_suspend_enter,
> +		return CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM_RCU(psci_cpu_suspend_enter,
>  						lpi->index, state);
>  	else
> -		return CPU_PM_CPU_IDLE_ENTER_PARAM(psci_cpu_suspend_enter,
> +		return CPU_PM_CPU_IDLE_ENTER_PARAM_RCU(psci_cpu_suspend_enter,
>  					     lpi->index, state);
>  }
>  #endif
> diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
> index e7163f31f716..0fbdf5fe64d8 100644
> --- a/arch/arm64/kernel/suspend.c
> +++ b/arch/arm64/kernel/suspend.c
> @@ -4,6 +4,7 @@
>  #include <linux/slab.h>
>  #include <linux/uaccess.h>
>  #include <linux/pgtable.h>
> +#include <linux/cpuidle.h>
>  #include <asm/alternative.h>
>  #include <asm/cacheflush.h>
>  #include <asm/cpufeature.h>
> @@ -104,6 +105,10 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
>  	 * From this point debug exceptions are disabled to prevent
>  	 * updates to mdscr register (saved and restored along with
>  	 * general purpose registers) from kernel debuggers.
> +	 *
> +	 * Strictly speaking the trace_hardirqs_off() here is superfluous,
> +	 * hardirqs should be firmly off by now. This really ought to use
> +	 * something like raw_local_daif_save().
>  	 */
>  	flags = local_daif_save();
>  
> @@ -120,6 +125,8 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
>  	 */
>  	arm_cpuidle_save_irq_context(&context);
>  
> +	ct_cpuidle_enter();
> +
>  	if (__cpu_suspend_enter(&state)) {
>  		/* Call the suspend finisher */
>  		ret = fn(arg);
> @@ -133,8 +140,11 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
>  		 */
>  		if (!ret)
>  			ret = -EOPNOTSUPP;
> +
> +		ct_cpuidle_exit();
>  	} else {
> -		RCU_NONIDLE(__cpu_suspend_exit());
> +		ct_cpuidle_exit();
> +		__cpu_suspend_exit();
>  	}
>  
>  	arm_cpuidle_restore_irq_context(&context);
> diff --git a/drivers/cpuidle/cpuidle-psci.c b/drivers/cpuidle/cpuidle-psci.c
> index 4fc4e0381944..312a34ef28dc 100644
> --- a/drivers/cpuidle/cpuidle-psci.c
> +++ b/drivers/cpuidle/cpuidle-psci.c
> @@ -69,16 +69,12 @@ static __cpuidle int __psci_enter_domain_idle_state(struct cpuidle_device *dev,
>  	else
>  		pm_runtime_put_sync_suspend(pd_dev);
>  
> -	ct_cpuidle_enter();
> -
>  	state = psci_get_domain_state();
>  	if (!state)
>  		state = states[idx];
>  
>  	ret = psci_cpu_suspend_enter(state) ? -1 : idx;
>  
> -	ct_cpuidle_exit();
> -
>  	if (s2idle)
>  		dev_pm_genpd_resume(pd_dev);
>  	else
> @@ -192,7 +188,7 @@ static __cpuidle int psci_enter_idle_state(struct cpuidle_device *dev,
>  {
>  	u32 *state = __this_cpu_read(psci_cpuidle_data.psci_states);
>  
> -	return CPU_PM_CPU_IDLE_ENTER_PARAM(psci_cpu_suspend_enter, idx, state[idx]);
> +	return CPU_PM_CPU_IDLE_ENTER_PARAM_RCU(psci_cpu_suspend_enter, idx, state[idx]);
>  }
>  
>  static const struct of_device_id psci_idle_state_match[] = {
> diff --git a/drivers/firmware/psci/psci.c b/drivers/firmware/psci/psci.c
> index e7bcfca4159f..f3a044fa4652 100644
> --- a/drivers/firmware/psci/psci.c
> +++ b/drivers/firmware/psci/psci.c
> @@ -462,11 +462,22 @@ int psci_cpu_suspend_enter(u32 state)
>  	if (!psci_power_state_loses_context(state)) {
>  		struct arm_cpuidle_irq_context context;
>  
> +		ct_cpuidle_enter();
>  		arm_cpuidle_save_irq_context(&context);
>  		ret = psci_ops.cpu_suspend(state, 0);
>  		arm_cpuidle_restore_irq_context(&context);
> +		ct_cpuidle_exit();
>  	} else {
> +		/*
> +		 * ARM64 cpu_suspend() wants to do ct_cpuidle_*() itself.
> +		 */
> +		if (!IS_ENABLED(CONFIG_ARM64))
> +			ct_cpuidle_enter();
> +
>  		ret = cpu_suspend(state, psci_suspend_finisher);
> +
> +		if (!IS_ENABLED(CONFIG_ARM64))
> +			ct_cpuidle_exit();
>  	}
>  
>  	return ret;
> diff --git a/include/linux/cpuidle.h b/include/linux/cpuidle.h
> index 630c879143c7..3183aeb7f5b4 100644
> --- a/include/linux/cpuidle.h
> +++ b/include/linux/cpuidle.h
> @@ -307,7 +307,7 @@ extern s64 cpuidle_governor_latency_req(unsigned int cpu);
>  #define __CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter,			\
>  				idx,					\
>  				state,					\
> -				is_retention)				\
> +				is_retention, is_rcu)			\
>  ({									\
>  	int __ret = 0;							\
>  									\
> @@ -319,9 +319,11 @@ extern s64 cpuidle_governor_latency_req(unsigned int cpu);
>  	if (!is_retention)						\
>  		__ret =  cpu_pm_enter();				\
>  	if (!__ret) {							\
> -		ct_cpuidle_enter();					\
> +		if (!is_rcu)						\
> +			ct_cpuidle_enter();				\
>  		__ret = low_level_idle_enter(state);			\
> -		ct_cpuidle_exit();					\
> +		if (!is_rcu)						\
> +			ct_cpuidle_exit();				\
>  		if (!is_retention)					\
>  			cpu_pm_exit();					\
>  	}								\
> @@ -330,15 +332,21 @@ extern s64 cpuidle_governor_latency_req(unsigned int cpu);
>  })
>  
>  #define CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx)	\
> -	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 0)
> +	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 0, 0)
>  
>  #define CPU_PM_CPU_IDLE_ENTER_RETENTION(low_level_idle_enter, idx)	\
> -	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 1)
> +	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, idx, 1, 0)
>  
>  #define CPU_PM_CPU_IDLE_ENTER_PARAM(low_level_idle_enter, idx, state)	\
> -	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 0)
> +	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 0, 0)
> +
> +#define CPU_PM_CPU_IDLE_ENTER_PARAM_RCU(low_level_idle_enter, idx, state)	\
> +	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 0, 1)
>  
>  #define CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM(low_level_idle_enter, idx, state)	\
> -	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 1)
> +	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 1, 0)
> +
> +#define CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM_RCU(low_level_idle_enter, idx, state)	\
> +	__CPU_PM_CPU_IDLE_ENTER(low_level_idle_enter, idx, state, 1, 1)
>  
>  #endif /* _LINUX_CPUIDLE_H */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y8afpbHtDOqAHq9M%40FVFF77S0Q05N.cambridge.arm.com.
