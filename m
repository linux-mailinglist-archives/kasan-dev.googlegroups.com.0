Return-Path: <kasan-dev+bncBCS4VDMYRUNBBL53Q2PAMGQEUL6ZU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BE0666A183
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Jan 2023 19:06:40 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id bi18-20020a05600c3d9200b003d991844dbcsf14560427wmb.4
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Jan 2023 10:06:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673633199; cv=pass;
        d=google.com; s=arc-20160816;
        b=QjclK6mmUbbYQkUxfEWV6Ld5uwuLIXdQtwTWAGhiVeJOUo/azdvnsj2Laf38RqGdQB
         i3VhphhLVQWpOXwzSy2q5vonp8toe8wNQESgZV9JkDUmIpndARh1QTyvPoCLS6CMHhQ+
         kICT0UuCwERAgs/EAWUx/dBBgHHntzIZMlqoCIsCAkZJbh4mv90/dlNuLDnCY+szQbWe
         Atowys2Ea9jaCuLfsDtldphLnRl3NyFVC2/ROPpsV4YsqEvAj+LGweLBWDvrs5FBrmli
         W5jlLUR5e0w2JBXhC5tgem3CZKufAHDl/ciKUxWU/JXt/JGRFPUO4l19gDj8ZO2ALsN0
         2gaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=4pEakIg5P6dtdfkvj4oTohEMpXsdufVlZkfyt2S2thA=;
        b=h01sjjpcJuUnLq7ucNc7xlpM5kWLckFI2HrPYUoXPuTBF1kKFPI21S+8UQJbyVpXHC
         H2V2PZeUJs0JDPgQC9/UYy6vdrH3rHQ6GnBMyPUgohWUYH5hbfOtUGXBepvCR+XQalWR
         b/DAtrqZFc1toucb8YoqI5yaN8JlEhjI28XkT9VGraCBmmzfblOZy2heY3l4At7bjB7A
         jT5wCcYex5CU+7QIXEi9OF2eRfm9htR+wtSIYg0oKB5IyqbDX7iUKqws8CTxcRvMGqq6
         ZcdnGmjZ1KzARNWP+Ss7O+OJOqxvhlMyHgy07Eud+9aQeQK0tSCLKcwCPXNYTk1/E+H5
         hzxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="d/TyPrfu";
       spf=pass (google.com: domain of srs0=0rbx=5k=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=0RBX=5K=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4pEakIg5P6dtdfkvj4oTohEMpXsdufVlZkfyt2S2thA=;
        b=HaMUeTuXheJ7BYAXFJL3/6QjHv0dFaS+2c6LtyzYejJzR8+wkQ5s+fEd1sS4fSSDfY
         /o26MR1pI9s91C8SO8Zdw7ZDVZ0a74Cr1Wdw/GQCmemanfBqkhnbw1VV3hwhi5iqit6E
         kpqroyjN4u2pGELlbnQnpGwfNU1Ty0VEuAr1oiRoPcQV0vowp3osIGa6pfvzQvkzjCUF
         ytPAl+gCgbK2yBrHUG/rik8qn2mn3TmAR2Jv/r2mgf2FjqNLALTTDVCRGBt20QvbxQ9Z
         6y4GX5HMO3SaqV2zl34wXZksCFzHloNzgHXqS65UhKH7u6D0I+wfaJxfTM9whTjLrExe
         1gtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4pEakIg5P6dtdfkvj4oTohEMpXsdufVlZkfyt2S2thA=;
        b=14GdoVSWu7PdZN62Nw1PAgFQhMKHa2iwdauviZtrDs0dfFtaK0jpvC4x94+Gkd/xgh
         IqrPnhsFYJu4HcdM16GcrCrbPc7LnD+f4OVzQc1Xn3pX0G7iRPOkDtRkjA7ztDUVuK4p
         Mm9I79oRurEMGf7OyKJ+eFLtiVSI+2ueS/s+gn6VkacxlJboOfZjmgWAsBIoGkxAX8u1
         o4c/d1az6SS/tB+ba09Sk5VHKg/I/ZOiRAHIB7Xq7y3sTZwpgzyIWfb73eEJmXRRYiK8
         q0CGFDxPQVtGOcFwx7sh2UlUGaLabqCYGqrfxQf9f/V0e7hzxN441OCx64E0LaFyOsaA
         N8IA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpBsgSKJWik8p0StWqnWAsGhQtoMLa13neoYTpI36iqU3a+med6
	hIkaJR4IN2Detgr0dTHdqVU=
X-Google-Smtp-Source: AMrXdXtg+pDEmQHLLJK0ml68sslJ60UpmQ6wQ8+5M70XHbnEOkow9fwAPqu90yA5olHCfa88k2Ce1A==
X-Received: by 2002:a5d:5449:0:b0:2bb:4142:1345 with SMTP id w9-20020a5d5449000000b002bb41421345mr998932wrv.112.1673633199689;
        Fri, 13 Jan 2023 10:06:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7305:0:b0:3cd:d7d0:14b6 with SMTP id d5-20020a1c7305000000b003cdd7d014b6ls3178101wmb.1.-pod-control-gmail;
 Fri, 13 Jan 2023 10:06:38 -0800 (PST)
X-Received: by 2002:a05:600c:3d10:b0:3d9:ee3d:2f54 with SMTP id bh16-20020a05600c3d1000b003d9ee3d2f54mr515472wmb.13.1673633198442;
        Fri, 13 Jan 2023 10:06:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673633198; cv=none;
        d=google.com; s=arc-20160816;
        b=bcU07f+ee8ohsDRew0+ZRQyazWLu/PfnJ7O69bEtVhslB8Ra0bila9gF2CR4jGFr9h
         6BH94U7DuvKsr2Dtt6JB3Os/z/dS2+hiqr/DxCvsdo1J9SFRWxi//N4ZAg0Yn4e3oy1v
         3mtikDeFBmfCbWy33FgrQcWQNRiwqf2kgRZhitiBIqCaJFK5beBY8cKZcR1qeuZPDL7M
         qAzPcMllKxITYGYh7wOuCFvQgd1bDpa7Wq4scU01It6m0R8sbd9lMXLfdRq7Vjv9knAa
         ae61zrh2P1+Bqp9Bbzdpx8r8S1DaL7/C6tyU3QCv9qOejbt1hmEooYjxT0saGvHxhhaJ
         zagw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aAy24DltFAyjJC8v9Tqp0XYfHzWDkXmYNlZl8jkJSN0=;
        b=xQ6JN7Iv8aLeGgLs84lk4A61I6ujbD1uVWbmegmcE8UwF/UKUjkCmU7CU70IRzS/CW
         Wf4XQ/R658dgZkp5Cm1/r6kxEEK2BLOyPjkd41h6cUfNpifpiCDHosfZu2imyYQ/Uikt
         TrdfPDImHSAxKLpPQT2KMuQMdW/B51T5AXiOuGbYB1dxHqUpTA3MA/ji40ZkzB1jEa3u
         4RY7SO9Mx/gGkivJfsqkclc7E/S4Xk6028GrXgIxXxC4A18mQOAaxK9Z5/LS6XBglH6D
         YHk2ZeJB7guK7R2y50IHoETmWgfRE21ih6yfCpMMF5pno+zyPXXBIO8OcCnhGrbkroPa
         WkIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="d/TyPrfu";
       spf=pass (google.com: domain of srs0=0rbx=5k=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=0RBX=5K=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id n7-20020a05600c500700b003da2550fb5fsi115158wmr.1.2023.01.13.10.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Jan 2023 10:06:38 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=0rbx=5k=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id D1F60B82198;
	Fri, 13 Jan 2023 18:06:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 53A0BC433F0;
	Fri, 13 Jan 2023 18:06:37 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id D78905C06D0; Fri, 13 Jan 2023 10:06:36 -0800 (PST)
Date: Fri, 13 Jan 2023 10:06:36 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	shorne@gmail.com, James.Bottomley@HansenPartnership.com,
	deller@gmx.de, mpe@ellerman.id.au, npiggin@gmail.com,
	christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
	palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
	gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
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
	mhiramat@kernel.org, frederic@kernel.org, pmladek@suse.com,
	senozhatsky@chromium.org, john.ogness@linutronix.de,
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	bristot@redhat.com, vschneid@redhat.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
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
Message-ID: <20230113180636.GA4028633@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230112194314.845371875@infradead.org>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="d/TyPrfu";       spf=pass
 (google.com: domain of srs0=0rbx=5k=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=0RBX=5K=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Jan 12, 2023 at 08:43:14PM +0100, Peter Zijlstra wrote:
> Hi All!
> 
> The (hopefully) final respin of cpuidle vs rcu cleanup patches. Barring any
> objections I'll be queueing these patches in tip/sched/core in the next few
> days.
> 
> v2: https://lkml.kernel.org/r/20220919095939.761690562@infradead.org
> 
> These here patches clean up the mess that is cpuidle vs rcuidle.
> 
> At the end of the ride there's only on RCU_NONIDLE user left:
> 
>   arch/arm64/kernel/suspend.c:            RCU_NONIDLE(__cpu_suspend_exit());
> 
> And I know Mark has been prodding that with something sharp.
> 
> The last version was tested by a number of people and I'm hoping to not have
> broken anything in the meantime ;-)
> 
> 
> Changes since v2:

150 rcutorture hours on each of the default scenarios passed.  This
is qemu/KVM on x86:

Tested-by: Paul E. McKenney <paulmck@kernel.org>

>  - rebased to v6.2-rc3; as available at:
>      git://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git sched/idle
> 
>  - folded: https://lkml.kernel.org/r/Y3UBwYNY15ETUKy9@hirez.programming.kicks-ass.net
>    which makes the ARM cpuidle index 0 consistently not use
>    CPUIDLE_FLAG_RCU_IDLE, as requested by Ulf.
> 
>  - added a few more __always_inline to empty stub functions as found by the
>    robot.
> 
>  - Used _RET_IP_ instead of _THIS_IP_ in a few placed because of:
>    https://github.com/ClangBuiltLinux/linux/issues/263
> 
>  - Added new patches to address various robot reports:
> 
>      #35:  trace,hardirq: No moar _rcuidle() tracing
>      #47:  cpuidle: Ensure ct_cpuidle_enter() is always called from noinstr/__cpuidle
>      #48:  cpuidle,arch: Mark all ct_cpuidle_enter() callers __cpuidle
>      #49:  cpuidle,arch: Mark all regular cpuidle_state::enter methods __cpuidle
>      #50:  cpuidle: Comments about noinstr/__cpuidle
>      #51:  context_tracking: Fix noinstr vs KASAN
> 
> 
> ---
>  arch/alpha/kernel/process.c               |  1 -
>  arch/alpha/kernel/vmlinux.lds.S           |  1 -
>  arch/arc/kernel/process.c                 |  3 ++
>  arch/arc/kernel/vmlinux.lds.S             |  1 -
>  arch/arm/include/asm/vmlinux.lds.h        |  1 -
>  arch/arm/kernel/cpuidle.c                 |  4 +-
>  arch/arm/kernel/process.c                 |  1 -
>  arch/arm/kernel/smp.c                     |  6 +--
>  arch/arm/mach-davinci/cpuidle.c           |  4 +-
>  arch/arm/mach-gemini/board-dt.c           |  3 +-
>  arch/arm/mach-imx/cpuidle-imx5.c          |  4 +-
>  arch/arm/mach-imx/cpuidle-imx6q.c         |  8 ++--
>  arch/arm/mach-imx/cpuidle-imx6sl.c        |  4 +-
>  arch/arm/mach-imx/cpuidle-imx6sx.c        |  9 ++--
>  arch/arm/mach-imx/cpuidle-imx7ulp.c       |  4 +-
>  arch/arm/mach-omap2/common.h              |  6 ++-
>  arch/arm/mach-omap2/cpuidle34xx.c         | 16 ++++++-
>  arch/arm/mach-omap2/cpuidle44xx.c         | 29 +++++++------
>  arch/arm/mach-omap2/omap-mpuss-lowpower.c | 12 +++++-
>  arch/arm/mach-omap2/pm.h                  |  2 +-
>  arch/arm/mach-omap2/pm24xx.c              | 51 +---------------------
>  arch/arm/mach-omap2/pm34xx.c              | 14 +++++--
>  arch/arm/mach-omap2/pm44xx.c              |  2 +-
>  arch/arm/mach-omap2/powerdomain.c         | 10 ++---
>  arch/arm/mach-s3c/cpuidle-s3c64xx.c       |  5 +--
>  arch/arm64/kernel/cpuidle.c               |  2 +-
>  arch/arm64/kernel/idle.c                  |  1 -
>  arch/arm64/kernel/smp.c                   |  4 +-
>  arch/arm64/kernel/vmlinux.lds.S           |  1 -
>  arch/csky/kernel/process.c                |  1 -
>  arch/csky/kernel/smp.c                    |  2 +-
>  arch/csky/kernel/vmlinux.lds.S            |  1 -
>  arch/hexagon/kernel/process.c             |  1 -
>  arch/hexagon/kernel/vmlinux.lds.S         |  1 -
>  arch/ia64/kernel/process.c                |  1 +
>  arch/ia64/kernel/vmlinux.lds.S            |  1 -
>  arch/loongarch/kernel/idle.c              |  1 +
>  arch/loongarch/kernel/vmlinux.lds.S       |  1 -
>  arch/m68k/kernel/vmlinux-nommu.lds        |  1 -
>  arch/m68k/kernel/vmlinux-std.lds          |  1 -
>  arch/m68k/kernel/vmlinux-sun3.lds         |  1 -
>  arch/microblaze/kernel/process.c          |  1 -
>  arch/microblaze/kernel/vmlinux.lds.S      |  1 -
>  arch/mips/kernel/idle.c                   | 14 +++----
>  arch/mips/kernel/vmlinux.lds.S            |  1 -
>  arch/nios2/kernel/process.c               |  1 -
>  arch/nios2/kernel/vmlinux.lds.S           |  1 -
>  arch/openrisc/kernel/process.c            |  1 +
>  arch/openrisc/kernel/vmlinux.lds.S        |  1 -
>  arch/parisc/kernel/process.c              |  2 -
>  arch/parisc/kernel/vmlinux.lds.S          |  1 -
>  arch/powerpc/kernel/idle.c                |  5 +--
>  arch/powerpc/kernel/vmlinux.lds.S         |  1 -
>  arch/riscv/kernel/process.c               |  1 -
>  arch/riscv/kernel/vmlinux-xip.lds.S       |  1 -
>  arch/riscv/kernel/vmlinux.lds.S           |  1 -
>  arch/s390/kernel/idle.c                   |  1 -
>  arch/s390/kernel/vmlinux.lds.S            |  1 -
>  arch/sh/kernel/idle.c                     |  1 +
>  arch/sh/kernel/vmlinux.lds.S              |  1 -
>  arch/sparc/kernel/leon_pmc.c              |  4 ++
>  arch/sparc/kernel/process_32.c            |  1 -
>  arch/sparc/kernel/process_64.c            |  3 +-
>  arch/sparc/kernel/vmlinux.lds.S           |  1 -
>  arch/um/kernel/dyn.lds.S                  |  1 -
>  arch/um/kernel/process.c                  |  1 -
>  arch/um/kernel/uml.lds.S                  |  1 -
>  arch/x86/boot/compressed/vmlinux.lds.S    |  1 +
>  arch/x86/coco/tdx/tdcall.S                | 15 +------
>  arch/x86/coco/tdx/tdx.c                   | 25 ++++-------
>  arch/x86/events/amd/brs.c                 | 13 +++---
>  arch/x86/include/asm/fpu/xcr.h            |  4 +-
>  arch/x86/include/asm/irqflags.h           | 11 ++---
>  arch/x86/include/asm/mwait.h              | 14 +++----
>  arch/x86/include/asm/nospec-branch.h      |  2 +-
>  arch/x86/include/asm/paravirt.h           |  6 ++-
>  arch/x86/include/asm/perf_event.h         |  2 +-
>  arch/x86/include/asm/shared/io.h          |  4 +-
>  arch/x86/include/asm/shared/tdx.h         |  1 -
>  arch/x86/include/asm/special_insns.h      |  8 ++--
>  arch/x86/include/asm/xen/hypercall.h      |  2 +-
>  arch/x86/kernel/cpu/bugs.c                |  2 +-
>  arch/x86/kernel/fpu/core.c                |  4 +-
>  arch/x86/kernel/paravirt.c                | 14 ++++++-
>  arch/x86/kernel/process.c                 | 65 ++++++++++++++--------------
>  arch/x86/kernel/vmlinux.lds.S             |  1 -
>  arch/x86/lib/memcpy_64.S                  |  5 +--
>  arch/x86/lib/memmove_64.S                 |  4 +-
>  arch/x86/lib/memset_64.S                  |  4 +-
>  arch/x86/xen/enlighten_pv.c               |  2 +-
>  arch/x86/xen/irq.c                        |  2 +-
>  arch/xtensa/kernel/process.c              |  1 +
>  arch/xtensa/kernel/vmlinux.lds.S          |  1 -
>  drivers/acpi/processor_idle.c             | 28 ++++++++-----
>  drivers/base/power/runtime.c              | 24 +++++------
>  drivers/clk/clk.c                         |  8 ++--
>  drivers/cpuidle/cpuidle-arm.c             |  4 +-
>  drivers/cpuidle/cpuidle-big_little.c      | 12 ++++--
>  drivers/cpuidle/cpuidle-mvebu-v7.c        | 13 ++++--
>  drivers/cpuidle/cpuidle-psci.c            | 26 +++++-------
>  drivers/cpuidle/cpuidle-qcom-spm.c        |  4 +-
>  drivers/cpuidle/cpuidle-riscv-sbi.c       | 19 +++++----
>  drivers/cpuidle/cpuidle-tegra.c           | 31 +++++++++-----
>  drivers/cpuidle/cpuidle.c                 | 70 ++++++++++++++++++++++---------
>  drivers/cpuidle/dt_idle_states.c          |  2 +-
>  drivers/cpuidle/poll_state.c              | 10 ++++-
>  drivers/idle/intel_idle.c                 | 19 ++++-----
>  drivers/perf/arm_pmu.c                    | 11 +----
>  drivers/perf/riscv_pmu_sbi.c              |  8 +---
>  include/asm-generic/vmlinux.lds.h         |  9 ++--
>  include/linux/clockchips.h                |  4 +-
>  include/linux/compiler_types.h            | 18 +++++++-
>  include/linux/cpu.h                       |  3 --
>  include/linux/cpuidle.h                   | 32 ++++++++++++++
>  include/linux/cpumask.h                   |  4 +-
>  include/linux/percpu-defs.h               |  2 +-
>  include/linux/sched/idle.h                | 40 +++++++++++++-----
>  include/linux/thread_info.h               | 18 +++++++-
>  include/linux/tracepoint.h                | 15 ++++++-
>  kernel/context_tracking.c                 | 12 +++---
>  kernel/cpu_pm.c                           |  9 ----
>  kernel/printk/printk.c                    |  2 +-
>  kernel/sched/idle.c                       | 47 ++++++---------------
>  kernel/time/tick-broadcast-hrtimer.c      | 29 ++++++-------
>  kernel/time/tick-broadcast.c              |  6 ++-
>  kernel/trace/trace.c                      |  3 ++
>  kernel/trace/trace_preemptirq.c           | 50 ++++++----------------
>  lib/ubsan.c                               |  5 ++-
>  mm/kasan/kasan.h                          |  4 ++
>  mm/kasan/shadow.c                         | 38 +++++++++++++++++
>  tools/objtool/check.c                     | 17 ++++++++
>  131 files changed, 617 insertions(+), 523 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230113180636.GA4028633%40paulmck-ThinkPad-P17-Gen-1.
